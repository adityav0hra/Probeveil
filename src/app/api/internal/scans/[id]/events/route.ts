import { createHash } from "node:crypto";
import type { Prisma } from "@prisma/client";
import { NextResponse } from "next/server";
import { z } from "zod";
import { db } from "@/lib/db";
import { processScanNotifications } from "@/lib/notifications/scan-notifications";
import { calculateCoverageScore, calculateSecurityScore } from "@/lib/scoring";
import { verifyWorkerToken } from "@/lib/worker-token";

const stageEvent = z.object({
  type: z.literal("stage"),
  key: z.string(),
  status: z.enum(["RUNNING", "COMPLETED", "FAILED", "SKIPPED"]),
  progress: z.number().min(0).max(100).optional(),
  message: z.string().max(1000).optional(),
});
const endpointEvent = z.object({
  type: z.literal("endpoints"),
  endpoints: z
    .array(
      z.object({
        url: z.string().url(),
        method: z.string().default("GET"),
        statusCode: z.number().optional(),
        contentType: z.string().optional(),
        title: z.string().optional(),
        depth: z.number(),
        tested: z.boolean(),
        external: z.boolean().default(false),
        discoveredBy: z.string(),
      }),
    )
    .max(500),
});
const parameterEvent = z.object({
  type: z.literal("parameters"),
  parameters: z
    .array(
      z.object({
        endpointUrl: z.string().url(),
        method: z.string().default("GET"),
        name: z.string().min(1).max(200),
        location: z.string().min(1).max(80),
        dataType: z.string().max(80).optional(),
        tested: z.boolean().default(false),
      }),
    )
    .max(1000),
});
const serviceEvent = z.object({
  type: z.literal("services"),
  services: z
    .array(
      z.object({
        host: z.string(),
        ip: z.string().optional(),
        port: z.number().optional(),
        protocol: z.string(),
        tls: z.any().optional(),
      }),
    )
    .max(100),
});
const technologyEvent = z.object({
  type: z.literal("technologies"),
  technologies: z
    .array(
      z.object({
        name: z.string(),
        version: z.string().optional(),
        category: z.string().optional(),
        evidence: z.string().optional(),
      }),
    )
    .max(100),
});
const findingShape = z.object({
  title: z.string(),
  description: z.string(),
  category: z.string(),
  cwe: z.string().optional(),
  owaspCategory: z.string().optional(),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
  confidence: z.enum([
    "CONFIRMED",
    "HIGH",
    "PROBABLE",
    "POTENTIAL",
    "INFORMATIONAL",
    "MANUAL_REVIEW",
  ]),
  affectedUrl: z.string().optional(),
  httpMethod: z.string().optional(),
  parameter: z.string().optional(),
  payload: z.string().optional(),
  scannerName: z.string().optional(),
  scannerRuleId: z.string(),
  scannerVersion: z.string().optional(),
  fingerprint: z.string(),
  impact: z.string(),
  remediation: z.string(),
  reproductionSteps: z.array(z.string()),
  references: z.array(z.string()),
  evidence: z
    .array(
      z.object({ type: z.string(), title: z.string(), content: z.string() }),
    )
    .default([]),
});
const findingsEvent = z.object({
  type: z.literal("findings"),
  findings: z.array(findingShape).max(100),
});
const artifactEvent = z.object({
  type: z.literal("artifacts"),
  artifacts: z
    .array(
      z.object({
        name: z.string().min(1).max(240),
        type: z.string().min(1).max(80),
        storageKey: z.string().min(1).max(500),
        sha256: z.string().length(64),
        size: z.number().int().min(0),
        contentType: z.string().min(1).max(120),
        metadata: z.record(z.string(), z.unknown()).optional(),
      }),
    )
    .max(100),
});
const finalEvent = z.object({
  type: z.enum(["complete", "failed"]),
  finalUrl: z.string().optional(),
  error: z.string().optional(),
});
const eventSchema = z.discriminatedUnion("type", [
  stageEvent,
  endpointEvent,
  parameterEvent,
  serviceEvent,
  technologyEvent,
  findingsEvent,
  artifactEvent,
  finalEvent,
]);

const transactionOptions = { maxWait: 10_000, timeout: 30_000 };

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  if (
    !verifyWorkerToken(
      request.headers.get("authorization")?.replace(/^Bearer /, "") ?? "",
      id,
    )
  )
    return new NextResponse("Unauthorized", { status: 401 });
  const parsed = eventSchema.safeParse(await request.json().catch(() => null));
  if (!parsed.success)
    return NextResponse.json(
      { error: parsed.error.flatten() },
      { status: 400 },
    );
  const event = parsed.data;
  const scanState = await db.scan.findUnique({
    where: { id },
    select: { status: true },
  });
  if (!scanState) return new NextResponse("Not found", { status: 404 });
  if (scanState.status === "CANCELLED")
    return NextResponse.json({ ok: true, skipped: "cancelled" });

  if (event.type === "stage") {
    await db.$transaction([
      db.scan.update({
        where: { id },
        data: { status: "RUNNING", startedAt: { set: new Date() } },
      }),
      db.scanStage.update({
        where: { scanId_key: { scanId: id, key: event.key } },
        data: {
          status: event.status,
          progress: event.progress ?? (event.status === "COMPLETED" ? 100 : 0),
          message: event.message,
          ...(event.status === "RUNNING"
            ? { startedAt: new Date() }
            : { completedAt: new Date() }),
        },
      }),
    ]);
  } else if (event.type === "endpoints") {
    await db.$transaction(async (tx) => {
      for (const endpoint of event.endpoints) {
        await tx.endpoint.upsert({
          where: {
            scanId_url_method: {
              scanId: id,
              url: endpoint.url,
              method: endpoint.method,
            },
          },
          update: endpoint,
          create: { scanId: id, ...endpoint },
        });
      }
    }, transactionOptions);
  } else if (event.type === "parameters") {
    await db.$transaction(async (tx) => {
      for (const parameter of event.parameters) {
        const endpoint = await tx.endpoint.upsert({
          where: {
            scanId_url_method: {
              scanId: id,
              url: parameter.endpointUrl,
              method: parameter.method,
            },
          },
          update: {},
          create: {
            scanId: id,
            url: parameter.endpointUrl,
            method: parameter.method,
            depth: 0,
            tested: false,
            external: false,
            discoveredBy: "parameter-inventory",
          },
        });
        await tx.parameter.upsert({
          where: {
            endpointId_name_location: {
              endpointId: endpoint.id,
              name: parameter.name,
              location: parameter.location,
            },
          },
          update: {
            dataType: parameter.dataType,
            tested: parameter.tested,
          },
          create: {
            endpointId: endpoint.id,
            name: parameter.name,
            location: parameter.location,
            dataType: parameter.dataType,
            tested: parameter.tested,
          },
        });
      }
    }, transactionOptions);
  } else if (event.type === "services") {
    await db.service.createMany({
      data: event.services.map((service) => ({ scanId: id, ...service })),
      skipDuplicates: true,
    });
  } else if (event.type === "technologies") {
    await db.$transaction(async (tx) => {
      for (const technology of event.technologies) {
        const version = technology.version ?? "detected";
        await tx.technology.upsert({
          where: {
            scanId_name_version: { scanId: id, name: technology.name, version },
          },
          update: { ...technology, version },
          create: { scanId: id, ...technology, version },
        });
      }
    }, transactionOptions);
  } else if (event.type === "findings") {
    for (const finding of event.findings) {
      const { evidence, reproductionSteps, references, ...data } = finding;
      await db.finding.upsert({
        where: {
          scanId_fingerprint: { scanId: id, fingerprint: finding.fingerprint },
        },
        update: { ...data },
        create: {
          scanId: id,
          ...data,
          scannerName: data.scannerName ?? "Probeveil Passive",
          scannerVersion: data.scannerVersion ?? "1.0.0",
          reproductionSteps,
          references,
          evidence: {
            create: evidence.map((item) => ({
              ...item,
              sha256: createHash("sha256").update(item.content).digest("hex"),
            })),
          },
        },
      });
    }
  } else if (event.type === "artifacts") {
    await db.$transaction(async (tx) => {
      await tx.evidenceArtifact.deleteMany({
        where: {
          scanId: id,
          type: { in: [...new Set(event.artifacts.map((item) => item.type))] },
        },
      });
      if (event.artifacts.length)
        await tx.evidenceArtifact.createMany({
          data: event.artifacts.map((artifact) => {
            const { metadata, ...data } = artifact;
            return {
              scanId: id,
              ...data,
              metadata: metadata as Prisma.InputJsonValue | undefined,
            };
          }),
        });
    }, transactionOptions);
  } else if (event.type === "failed") {
    await db.scan.update({
      where: { id },
      data: {
        status: "FAILED",
        error: event.error ?? "Worker failed",
        completedAt: new Date(),
        stages: {
          updateMany: {
            where: { status: { in: ["PENDING", "RUNNING"] } },
            data: { status: "FAILED", completedAt: new Date() },
          },
        },
      },
    });
    await markTargetedRetestScanFailed(id, event.error ?? "Worker failed");
    await safelyProcessScanNotifications(id);
  } else {
    const [findings, stages, endpointCount, tested] = await Promise.all([
      db.finding.findMany({
        where: { scanId: id },
        select: { severity: true, confidence: true },
      }),
      db.scanStage.groupBy({
        by: ["status"],
        where: { scanId: id },
        _count: true,
      }),
      db.endpoint.count({ where: { scanId: id } }),
      db.endpoint.count({ where: { scanId: id, tested: true } }),
    ]);
    const completed = stages.find((x) => x.status === "COMPLETED")?._count ?? 0;
    const total = stages.reduce((sum, x) => sum + x._count, 0);
    await db.scan.update({
      where: { id },
      data: {
        status: "COMPLETED",
        finalUrl: event.finalUrl,
        securityScore: calculateSecurityScore(findings),
        coverageScore: calculateCoverageScore({
          completedStages: completed,
          totalStages: total,
          endpointsTested: tested,
          endpointsDiscovered: endpointCount,
        }),
        completedAt: new Date(),
        reports: {
          createMany: {
            data: [
              { type: "JSON" },
              { type: "EXECUTIVE_HTML" },
              { type: "TECHNICAL_HTML" },
            ],
          },
        },
      },
    });
    await evaluateTargetedRetest(id);
    await safelyProcessScanNotifications(id);
  }
  return NextResponse.json({ ok: true });
}

async function safelyProcessScanNotifications(scanId: string) {
  try {
    await processScanNotifications(scanId);
  } catch (error) {
    console.error("Scan notification processing failed", {
      error: error instanceof Error ? error.message : String(error),
      scanId,
    });
  }
}

async function markTargetedRetestScanFailed(scanId: string, error: string) {
  const retestTarget = await db.scanTarget.findFirst({
    where: { scanId, kind: "RETEST" },
  });
  const metadata = retestMetadata(retestTarget?.metadata);
  if (!metadata) return;
  await db.retest.updateMany({
    where: { id: metadata.retestId },
    data: {
      completedAt: new Date(),
      newEvidence: {
        comparedAt: new Date().toISOString(),
        error,
        newScanId: scanId,
        outcome: "ERROR",
        summary:
          "The targeted retest scan failed before Probeveil could determine whether the finding disappeared.",
      },
      status: "FAILED",
    },
  });
}

async function evaluateTargetedRetest(scanId: string) {
  const retestTarget = await db.scanTarget.findFirst({
    where: { scanId, kind: "RETEST" },
  });
  const metadata = retestMetadata(retestTarget?.metadata);
  if (!metadata) return;

  const [retest, originalFinding, retestScan] = await Promise.all([
    db.retest.findUnique({ where: { id: metadata.retestId } }),
    db.finding.findUnique({
      where: { id: metadata.originalFindingId },
      include: { evidence: true },
    }),
    db.scan.findUnique({
      where: { id: scanId },
      include: {
        findings: {
          include: { evidence: true },
          orderBy: [{ severity: "asc" }, { detectedAt: "desc" }],
        },
      },
    }),
  ]);
  if (!retest || !originalFinding || !retestScan) return;

  const matched = retestScan.findings.filter((finding) =>
    retestFindingMatches(originalFinding, finding),
  );
  const passed = matched.length === 0;
  const newEvidence = {
    comparedAt: new Date().toISOString(),
    newScanId: scanId,
    targetUrl: retestTarget?.url,
    outcome: passed ? "PASSED" : "FAILED",
    rule: originalFinding.scannerRuleId,
    originalFinding: {
      id: originalFinding.id,
      title: originalFinding.title,
      affectedUrl: originalFinding.affectedUrl,
      fingerprint: originalFinding.fingerprint,
      scannerRuleId: originalFinding.scannerRuleId,
      evidence: originalFinding.evidence.map((item) => ({
        title: item.title,
        type: item.type,
        sha256: item.sha256,
        content: item.content?.slice(0, 4000),
      })),
    },
    matchedFindings: matched.map((finding) => ({
      id: finding.id,
      title: finding.title,
      severity: finding.severity,
      confidence: finding.confidence,
      affectedUrl: finding.affectedUrl,
      fingerprint: finding.fingerprint,
      scannerRuleId: finding.scannerRuleId,
      evidence: finding.evidence.map((item) => ({
        title: item.title,
        type: item.type,
        sha256: item.sha256,
        content: item.content?.slice(0, 4000),
      })),
    })),
    summary: passed
      ? "No matching finding was reproduced in the targeted retest scan."
      : `${matched.length} matching finding${matched.length === 1 ? "" : "s"} reproduced in the targeted retest scan.`,
  };
  const previousStatus = originalFinding.status;
  const nextStatus = passed ? "RETEST_PASSED" : "RETEST_FAILED";

  await db.$transaction([
    db.retest.update({
      where: { id: retest.id },
      data: {
        completedAt: new Date(),
        newEvidence: newEvidence as Prisma.InputJsonValue,
        status: passed ? "PASSED" : "FAILED",
      },
    }),
    db.finding.update({
      where: { id: originalFinding.id },
      data: {
        status: nextStatus,
      },
    }),
    db.findingReview.create({
      data: {
        action: nextStatus,
        explanation: newEvidence.summary,
        findingId: originalFinding.id,
        newValue: {
          newEvidence,
          retestId: retest.id,
          status: nextStatus,
        } as Prisma.InputJsonValue,
        previousValue: {
          status: previousStatus,
        },
        userId: retestScan.userId,
      },
    }),
    db.auditLog.create({
      data: {
        action: "FINDING_RETEST_EVALUATED",
        metadata: {
          matchedFindings: matched.length,
          newScanId: scanId,
          outcome: passed ? "PASSED" : "FAILED",
          retestId: retest.id,
        },
        resourceId: originalFinding.id,
        resourceType: "Finding",
        userId: retestScan.userId,
      },
    }),
  ]);
}

function retestMetadata(value: unknown) {
  if (!value || typeof value !== "object") return undefined;
  const data = value as {
    originalFindingId?: unknown;
    retestId?: unknown;
    scannerRuleId?: unknown;
  };
  if (
    typeof data.originalFindingId !== "string" ||
    typeof data.retestId !== "string"
  )
    return undefined;
  return {
    originalFindingId: data.originalFindingId,
    retestId: data.retestId,
    scannerRuleId:
      typeof data.scannerRuleId === "string" ? data.scannerRuleId : undefined,
  };
}

function retestFindingMatches(
  original: {
    affectedUrl: string | null;
    fingerprint: string;
    scannerRuleId: string;
    title: string;
  },
  candidate: {
    affectedUrl: string | null;
    fingerprint: string;
    scannerRuleId: string;
    title: string;
  },
) {
  if (candidate.fingerprint === original.fingerprint) return true;
  if (candidate.scannerRuleId !== original.scannerRuleId) return false;
  const originalPath = comparablePath(original.affectedUrl);
  const candidatePath = comparablePath(candidate.affectedUrl);
  if (originalPath && candidatePath && originalPath === candidatePath)
    return true;
  return candidate.title === original.title && !originalPath && !candidatePath;
}

function comparablePath(value: string | null) {
  if (!value) return "";
  try {
    const url = new URL(value);
    url.hash = "";
    return `${url.hostname}${url.pathname}${url.search}`;
  } catch {
    return value;
  }
}
