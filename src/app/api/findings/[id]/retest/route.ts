import { after, NextResponse } from "next/server";
import { ScanStatus } from "@prisma/client";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";
import { getScanQueue } from "@/lib/queue";
import { PASSIVE_STAGES } from "@/lib/stages";
import { normalizeUrlInput, urlFingerprint } from "@/lib/url";
import { signWorkerToken } from "@/lib/worker-token";

export const maxDuration = 300;
export const runtime = "nodejs";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const session = await requireRole(["ADMIN"]);
  const { id } = await params;
  const finding = await db.finding.findUnique({
    include: { evidence: true, scan: true },
    where: { id },
  });
  if (!finding) return new NextResponse("Not found", { status: 404 });

  const targetUrl = normalizeUrlInput(
    finding.affectedUrl || finding.scan.normalizedUrl,
  );
  const normalizedHash = urlFingerprint(targetUrl);
  const duplicate = await db.scan.findFirst({
    orderBy: { createdAt: "desc" },
    where: {
      normalizedHash,
      status: { in: [ScanStatus.QUEUED, ScanStatus.RUNNING] },
    },
  });
  if (duplicate)
    return NextResponse.redirect(
      new URL(`/scans/${duplicate.id}`, request.url),
      303,
    );

  const retest = await db.retest.create({
    data: {
      findingId: finding.id,
      previousEvidence: finding.evidence.map((item) => ({
        sha256: item.sha256,
        title: item.title,
        type: item.type,
      })),
      scanId: finding.scanId,
      status: "QUEUED",
    },
  });
  const scan = await db.scan.create({
    data: {
      mode: "FULL",
      normalizedHash,
      normalizedUrl: targetUrl,
      originalUrl: targetUrl,
      stages: {
        create: PASSIVE_STAGES.map(([key, label], order) => ({
          key,
          label,
          order,
        })),
      },
      targets: {
        create: {
          hostname: new URL(targetUrl).hostname,
          inScope: true,
          kind: "RETEST",
          metadata: {
            originalFindingId: finding.id,
            originalScanId: finding.scanId,
            retestId: retest.id,
            scannerRuleId: finding.scannerRuleId,
          },
          reason: `Targeted retest for ${finding.scannerRuleId}`,
          url: targetUrl,
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
        { mode: scan.mode, scanId: scan.id, token, url: targetUrl },
        { jobId: scan.id },
      );
      queueJobId = String(job.id);
      workerType = "PASSIVE_HTTP";
    } catch (error) {
      console.warn(
        JSON.stringify({
          error: error instanceof Error ? error.message : String(error),
          scanId: scan.id,
          worker: "retest-enqueue-fallback",
        }),
      );
    }
  }

  await db.$transaction([
    db.workerJob.create({
      data: { queueJobId, scanId: scan.id, status: "QUEUED", workerType },
    }),
    db.auditLog.create({
      data: {
        action: "FINDING_RETEST_CREATED",
        metadata: {
          findingId: finding.id,
          retestId: retest.id,
          targetUrl,
        },
        resourceId: finding.id,
        resourceType: "Finding",
        userId: session.user.id,
      },
    }),
  ]);

  if (workerType === "SERVERLESS_PASSIVE_HTTP")
    schedulePassiveWorkerKick(request, scan.id, token);

  return NextResponse.redirect(new URL(`/scans/${scan.id}`, request.url), 303);
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
          worker: "serverless-retest-kick",
        }),
      );
    }
  });
}
