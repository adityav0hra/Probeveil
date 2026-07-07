import { after, NextResponse } from "next/server";
import { ScanStatus } from "@prisma/client";
import { requireRole } from "@/lib/auth";
import {
  authHeadersFromPayload,
  authOptionsFromPayload,
  decryptVaultPayload,
} from "@/lib/auth-vault";
import { db } from "@/lib/db";
import { getScanQueue } from "@/lib/queue";
import {
  approvedDomainForUrl,
  assertBusinessWindow,
  safetyPolicyFromApproval,
} from "@/lib/scan-safety";
import { scanPolicyFromProfile } from "@/lib/scan-profiles";
import { PASSIVE_STAGES } from "@/lib/stages";
import { createScanSchema, normalizeUrlInput, urlFingerprint } from "@/lib/url";
import { signWorkerToken } from "@/lib/worker-token";

export const maxDuration = 300;
export const runtime = "nodejs";

export async function GET() {
  await requireRole(["ADMIN", "AUDITOR"]);
  const scans = await db.scan.findMany({
    include: {
      _count: { select: { findings: true } },
      findings: { select: { confidence: true, severity: true } },
    },
    orderBy: { createdAt: "desc" },
    take: 100,
  });
  return NextResponse.json(scans);
}

export async function POST(request: Request) {
  const session = await requireRole(["ADMIN"]);
  const contentType = request.headers.get("content-type") ?? "";
  const isJson = contentType.includes("application/json");
  const body = isJson
    ? await request.json().catch(() => null)
    : Object.fromEntries((await request.formData()).entries());
  const parsed = createScanSchema.safeParse(body);

  if (!parsed.success) {
    return scanErrorResponse(
      request,
      isJson,
      "Enter a valid URL and select a scan mode.",
      body,
    );
  }

  let normalizedUrl: string;
  try {
    normalizedUrl = normalizeUrlInput(parsed.data.url);
  } catch (error) {
    return scanErrorResponse(
      request,
      isJson,
      error instanceof Error ? error.message : "Invalid URL.",
      parsed.data,
    );
  }

  const normalizedHash = urlFingerprint(normalizedUrl);
  const approvedDomain = await approvedDomainForUrl(normalizedUrl);
  if (!approvedDomain) {
    return scanErrorResponse(
      request,
      isJson,
      "This domain needs an approved ownership record before scanning. Add proof in Settings > Safety.",
      parsed.data,
    );
  }
  const profile = parsed.data.profileId
    ? await db.scanProfile.findFirst({
        where: { enabled: true, id: parsed.data.profileId },
      })
    : null;
  const policy = profile ? scanPolicyFromProfile(profile) : null;
  const mode = policy?.mode ?? parsed.data.mode;
  const safety = safetyPolicyFromApproval(
    approvedDomain,
    policy?.limits.maxRoutes ?? defaultMaxRequests(mode),
  );
  try {
    assertBusinessWindow(safety);
  } catch (error) {
    return scanErrorResponse(
      request,
      isJson,
      error instanceof Error ? error.message : "Outside approved scan window.",
      parsed.data,
    );
  }
  let vaultSelections: Awaited<ReturnType<typeof loadVaultSelections>>;
  try {
    vaultSelections = await loadVaultSelections(parsed.data);
  } catch (error) {
    return scanErrorResponse(
      request,
      isJson,
      error instanceof Error ? error.message : "Credential profile failed.",
      parsed.data,
    );
  }
  const authHeaders = {
    ...vaultSelections.primary.authHeaders,
    ...scanAuthHeaders(parsed.data),
  };
  const auth = scanAuthOptions(
    parsed.data,
    policy?.authConfig,
    vaultSelections.primary.auth,
  );
  const comparisonProfiles = scanComparisonProfiles(
    parsed.data,
    vaultSelections.comparison,
  );
  const features =
    policy?.features ??
    ({
      apiDiscovery: parsed.data.apiDiscovery,
      browserRendering: parsed.data.browserRendering,
      screenshots: parsed.data.screenshotCapture,
    } satisfies Record<string, boolean>);
  const duplicate = await db.scan.findFirst({
    orderBy: { createdAt: "desc" },
    where: {
      normalizedHash,
      status: { in: [ScanStatus.QUEUED, ScanStatus.RUNNING] },
    },
  });

  if (duplicate) {
    if (!isJson) {
      return NextResponse.redirect(
        new URL(`/scans/${duplicate.id}`, request.url),
        303,
      );
    }
    return NextResponse.json(
      {
        error: "A scan for this website is already active.",
        scanId: duplicate.id,
      },
      { status: 409 },
    );
  }

  const scan = await db.scan.create({
    data: {
      mode,
      normalizedHash,
      normalizedUrl,
      originalUrl: parsed.data.url.trim(),
      profileId: profile?.id,
      stages: {
        create: PASSIVE_STAGES.map(([key, label], order) => ({
          key,
          label,
          order,
        })),
      },
      targets: {
        create: {
          hostname: new URL(normalizedUrl).hostname,
          inScope: true,
          kind: "PRIMARY",
          metadata: {
            auth: {
              credentialProfileId: vaultSelections.primary.id,
              credentialProfileName: vaultSelections.primary.name,
              contextName: auth.contextName,
              expectedTextConfigured: Boolean(auth.expectedText),
              routeSeeds: auth.routeSeeds,
              verificationPath: auth.verificationPath,
            },
            authHeaderConfigured: Boolean(authHeaders.authorization),
            cookieHeaderConfigured: Boolean(authHeaders.cookie),
            comparisonProfiles: comparisonProfiles.map((profile) => ({
              credentialProfileId: "id" in profile ? profile.id : undefined,
              name: profile.name,
              role: profile.role,
            })),
            features,
            safety: {
              approvalId: safety.approvalId,
              businessHours: safety.businessHours,
              excludedDangerousPayloadClasses:
                safety.excludedDangerousPayloadClasses,
              maxRequestsPerScan: safety.maxRequestsPerScan,
              requestsPerMinute: safety.requestsPerMinute,
            },
            policy: policy
              ? {
                  alertThresholds: policy.alertThresholds,
                  authConfig: {
                    authenticated: policy.authConfig.authenticated,
                    roleComparison: policy.authConfig.roleComparison,
                    routeSeeds: policy.authConfig.routeSeeds,
                    verificationPath: policy.authConfig.verificationPath,
                  },
                  engines: policy.engines,
                  limits: policy.limits,
                  profileId: policy.id,
                  profileName: policy.name,
                  profileSlug: policy.slug,
                  stageConfig: policy.stageConfig,
                }
              : undefined,
          },
          reason: "Submitted scan target",
          url: normalizedUrl,
        },
      },
      userId: session.user.id,
    },
  });
  const token = signWorkerToken(scan.id);
  let queueJobId = `serverless:${scan.id}`;
  let workerType = "SERVERLESS_PASSIVE_HTTP";

  if (shouldUseBullMq()) {
    try {
      const job = await getScanQueue().add(
        "passive",
        {
          mode,
          auth,
          authHeaders,
          comparisonProfiles,
          features,
          safety,
          scanId: scan.id,
          token,
          url: normalizedUrl,
        },
        { jobId: scan.id },
      );
      queueJobId = String(job.id);
      workerType = "PASSIVE_HTTP";
    } catch (error) {
      console.warn(
        JSON.stringify({
          error: error instanceof Error ? error.message : String(error),
          scanId: scan.id,
          worker: "bullmq-enqueue-fallback",
        }),
      );
    }
  }

  await db.$transaction([
    db.workerJob.create({
      data: {
        queueJobId,
        scanId: scan.id,
        status: "QUEUED",
        workerType,
      },
    }),
    db.auditLog.create({
      data: {
        action: "SCAN_CREATED",
        metadata: {
          authHeaderConfigured: Boolean(authHeaders.authorization),
          cookieHeaderConfigured: Boolean(authHeaders.cookie),
          authContextName: auth.contextName,
          authRouteSeedCount: auth.routeSeeds?.length ?? 0,
          authVerificationPath: auth.verificationPath,
          comparisonProfileCount: comparisonProfiles.length,
          comparisonProfileRoles: comparisonProfiles.map(
            (profile) => profile.role,
          ),
          credentialProfileIds: [
            vaultSelections.primary.id,
            ...vaultSelections.comparison.map((profile) => profile.id),
          ].filter((item): item is string => typeof item === "string"),
          features,
          mode,
          normalizedUrl,
          safety: {
            approvalId: safety.approvalId,
            businessHoursEnabled: safety.businessHours?.enabled ?? false,
            excludedDangerousPayloadClasses:
              safety.excludedDangerousPayloadClasses,
            maxRequestsPerScan: safety.maxRequestsPerScan,
            requestsPerMinute: safety.requestsPerMinute,
          },
          profileId: profile?.id,
          profileName: profile?.name,
        },
        resourceId: scan.id,
        resourceType: "Scan",
        userId: session.user.id,
      },
    }),
  ]);

  if (workerType === "SERVERLESS_PASSIVE_HTTP")
    schedulePassiveWorkerKick(request, scan.id, token, {
      auth,
      authHeaders,
      comparisonProfiles,
      features,
      safety,
    });

  if (!isJson) {
    return NextResponse.redirect(
      new URL(`/scans/${scan.id}`, request.url),
      303,
    );
  }

  return NextResponse.json({ id: scan.id }, { status: 201 });
}

function scanAuthHeaders(data: { authHeader?: string; cookieHeader?: string }) {
  return {
    ...(data.authHeader ? { authorization: data.authHeader } : {}),
    ...(data.cookieHeader ? { cookie: data.cookieHeader } : {}),
  };
}

function scanAuthOptions(
  data: {
    authContextName?: string;
    authExpectedText?: string;
    authRouteSeeds?: string;
    authVerificationPath?: string;
  },
  policyAuth?: Record<string, unknown>,
  vaultAuth?: {
    contextName?: string;
    expectedText?: string;
    routeSeeds?: string[];
    verificationPath?: string;
  },
) {
  const policyRouteSeeds = Array.isArray(policyAuth?.routeSeeds)
    ? policyAuth.routeSeeds.filter(
        (item): item is string => typeof item === "string",
      )
    : [];
  const policyVerificationPath =
    typeof policyAuth?.verificationPath === "string"
      ? policyAuth.verificationPath
      : "";
  return {
    ...(vaultAuth?.contextName ? { contextName: vaultAuth.contextName } : {}),
    ...(data.authContextName ? { contextName: data.authContextName } : {}),
    ...(vaultAuth?.expectedText
      ? { expectedText: vaultAuth.expectedText }
      : {}),
    ...(data.authExpectedText ? { expectedText: data.authExpectedText } : {}),
    routeSeeds: [
      ...new Set([
        ...policyRouteSeeds,
        ...(vaultAuth?.routeSeeds ?? []),
        ...routeSeedsFromText(data.authRouteSeeds ?? ""),
      ]),
    ].slice(0, 60),
    ...(data.authVerificationPath ||
    vaultAuth?.verificationPath ||
    policyVerificationPath
      ? {
          verificationPath:
            data.authVerificationPath ||
            vaultAuth?.verificationPath ||
            policyVerificationPath,
        }
      : {}),
  };
}

function scanComparisonProfiles(
  data: Record<string, string | boolean | undefined>,
  vaultProfiles: Array<{
    authHeaders: Record<string, string>;
    id?: string;
    name: string;
    role: "NORMAL_USER" | "ADMIN" | "USER_A" | "USER_B";
  }> = [],
) {
  const profileSpecs = [
    ["normalUser", "Normal user", "NORMAL_USER"],
    ["adminUser", "Admin", "ADMIN"],
    ["userA", "User A", "USER_A"],
    ["userB", "User B", "USER_B"],
  ] as const;
  const manualProfiles = profileSpecs.flatMap(([prefix, name, role]) => {
    const authHeader = data[`${prefix}AuthHeader`];
    const cookieHeader = data[`${prefix}CookieHeader`];
    const authHeaders = {
      ...(typeof authHeader === "string" && authHeader
        ? { authorization: authHeader }
        : {}),
      ...(typeof cookieHeader === "string" && cookieHeader
        ? { cookie: cookieHeader }
        : {}),
    };
    return Object.keys(authHeaders).length ? [{ authHeaders, name, role }] : [];
  });
  const manualRoles = new Set(manualProfiles.map((profile) => profile.role));
  return [
    ...vaultProfiles.filter((profile) => !manualRoles.has(profile.role)),
    ...manualProfiles,
  ];
}

async function loadVaultSelections(data: {
  authCredentialProfileId?: string;
  normalUserCredentialProfileId?: string;
  adminUserCredentialProfileId?: string;
  userACredentialProfileId?: string;
  userBCredentialProfileId?: string;
}) {
  const primary = data.authCredentialProfileId
    ? await loadVaultProfile(data.authCredentialProfileId)
    : emptyVaultSelection();
  const comparisonSpecs = [
    [data.normalUserCredentialProfileId, "NORMAL_USER"],
    [data.adminUserCredentialProfileId, "ADMIN"],
    [data.userACredentialProfileId, "USER_A"],
    [data.userBCredentialProfileId, "USER_B"],
  ] as const;
  const comparison = (
    await Promise.all(
      comparisonSpecs.map(async ([id, role]) => {
        if (!id) return undefined;
        const selection = await loadVaultProfile(id);
        return {
          authHeaders: selection.authHeaders,
          id: selection.id,
          name: selection.name || roleLabel(role),
          role,
        };
      }),
    )
  ).filter((item): item is NonNullable<typeof item> => Boolean(item));
  return { comparison, primary };
}

async function loadVaultProfile(id: string) {
  const profile = await db.authCredentialProfile.findFirst({
    where: { enabled: true, id },
  });
  if (!profile) throw new Error("Credential profile not found.");
  if (profile.expiresAt && profile.expiresAt.getTime() < Date.now())
    throw new Error(`Credential profile "${profile.name}" is expired.`);
  const payload = decryptVaultPayload(profile.encryptedPayload);
  return {
    auth: authOptionsFromPayload(payload),
    authHeaders: authHeadersFromPayload(payload),
    id: profile.id,
    name: profile.name,
  };
}

function emptyVaultSelection() {
  return {
    auth: {},
    authHeaders: {},
    id: undefined,
    name: undefined,
  };
}

function roleLabel(role: string) {
  return role
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function routeSeedsFromText(value: string) {
  return [
    ...new Set(
      value
        .split(/\r?\n|,/)
        .map((item) => item.trim())
        .filter(Boolean)
        .slice(0, 40),
    ),
  ];
}

function shouldUseBullMq() {
  if (process.env.SCAN_QUEUE_DRIVER === "serverless") return false;
  if (process.env.SCAN_QUEUE_DRIVER === "bullmq") return true;
  if (process.env.VERCEL === "1") return false;
  const redisUrl = process.env.REDIS_URL;
  return Boolean(
    redisUrl &&
      !/^redis:\/\/(?:localhost|127\.0\.0\.1)(?::|\/|$)/i.test(redisUrl),
  );
}

function schedulePassiveWorkerKick(
  request: Request,
  scanId: string,
  token: string,
  options: Pick<
    import("@/worker/types").ScanJob,
    "auth" | "authHeaders" | "comparisonProfiles" | "features" | "safety"
  >,
) {
  const url = new URL(`/api/internal/workers/passive/${scanId}`, request.url);
  after(async () => {
    try {
      await fetch(url, {
        body: JSON.stringify(options),
        cache: "no-store",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        method: "POST",
        signal: AbortSignal.timeout(300_000),
      });
    } catch (error) {
      console.warn(
        JSON.stringify({
          error: error instanceof Error ? error.message : String(error),
          scanId,
          worker: "serverless-passive-kick",
        }),
      );
    }
  });
}

function defaultMaxRequests(mode: "QUICK" | "FULL" | "MAXIMUM") {
  if (mode === "QUICK") return 75;
  if (mode === "FULL") return 250;
  return 500;
}

function scanErrorResponse(
  request: Request,
  isJson: boolean,
  error: string,
  body: unknown,
) {
  if (isJson) {
    return NextResponse.json({ error }, { status: 400 });
  }

  const url = new URL("/scans/new", request.url);
  url.searchParams.set("error", error);
  if (
    body &&
    typeof body === "object" &&
    "url" in body &&
    typeof body.url === "string"
  ) {
    url.searchParams.set("url", body.url);
  }
  if (
    body &&
    typeof body === "object" &&
    "mode" in body &&
    typeof body.mode === "string"
  ) {
    url.searchParams.set("mode", body.mode);
  }
  return NextResponse.redirect(url, 303);
}
