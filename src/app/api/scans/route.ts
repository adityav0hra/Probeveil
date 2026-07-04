import { after, NextResponse } from "next/server";
import { ScanStatus } from "@prisma/client";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";
import { getScanQueue } from "@/lib/queue";
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
      mode: parsed.data.mode,
      normalizedHash,
      normalizedUrl,
      originalUrl: parsed.data.url.trim(),
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
          reason: "Submitted scan target",
          url: normalizedUrl,
        },
      },
      userId: session.user.id,
    },
  });
  const token = signWorkerToken(scan.id);
  const job = await getScanQueue().add(
    "passive",
    {
      mode: parsed.data.mode,
      scanId: scan.id,
      token,
      url: normalizedUrl,
    },
    { jobId: scan.id },
  );

  await db.$transaction([
    db.workerJob.create({
      data: {
        queueJobId: String(job.id),
        scanId: scan.id,
        status: "QUEUED",
        workerType: "PASSIVE_HTTP",
      },
    }),
    db.auditLog.create({
      data: {
        action: "SCAN_CREATED",
        metadata: { mode: parsed.data.mode, normalizedUrl },
        resourceId: scan.id,
        resourceType: "Scan",
        userId: session.user.id,
      },
    }),
  ]);

  schedulePassiveWorkerKick(request, scan.id, token);

  if (!isJson) {
    return NextResponse.redirect(
      new URL(`/scans/${scan.id}`, request.url),
      303,
    );
  }

  return NextResponse.json({ id: scan.id }, { status: 201 });
}

function schedulePassiveWorkerKick(request: Request, scanId: string, token: string) {
  const url = new URL(`/api/internal/workers/passive/${scanId}`, request.url);
  after(async () => {
    try {
      await fetch(url, {
        cache: "no-store",
        headers: { authorization: `Bearer ${token}` },
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
