import "server-only";
import { ScanStatus, type ScanMode, type ScanSchedule } from "@prisma/client";
import { db } from "@/lib/db";
import { getScanQueue } from "@/lib/queue";
import { nextScheduledRun } from "@/lib/scheduling";
import { PASSIVE_STAGES } from "@/lib/stages";
import { signWorkerToken } from "@/lib/worker-token";
import type { ScanJob } from "@/worker/types";

export type ScheduledScanLaunch = {
  nextRunAt: Date;
  scanId?: string;
  skipped?: string;
  token?: string;
  workerOptions?: Pick<
    ScanJob,
    "auth" | "authHeaders" | "comparisonProfiles" | "features"
  >;
};

export async function launchScheduledScan(
  schedule: Pick<
    ScanSchedule,
    | "cadence"
    | "features"
    | "id"
    | "mode"
    | "normalizedHash"
    | "normalizedUrl"
    | "originalUrl"
    | "userId"
  >,
) {
  const now = new Date();
  const nextRunAt = nextScheduledRun(schedule.cadence, now);
  const active = await db.scan.findFirst({
    orderBy: { createdAt: "desc" },
    where: {
      normalizedHash: schedule.normalizedHash,
      status: { in: [ScanStatus.QUEUED, ScanStatus.RUNNING] },
    },
  });

  if (active) {
    await db.scanSchedule.update({
      where: { id: schedule.id },
      data: { lastRunAt: now, lastScanId: active.id, nextRunAt },
    });
    return {
      nextRunAt,
      scanId: active.id,
      skipped: "A scan for this website is already active.",
    } satisfies ScheduledScanLaunch;
  }

  const features = scanFeatures(schedule.features);
  const scan = await db.scan.create({
    data: {
      mode: schedule.mode,
      normalizedHash: schedule.normalizedHash,
      normalizedUrl: schedule.normalizedUrl,
      originalUrl: schedule.originalUrl,
      scheduleId: schedule.id,
      stages: {
        create: PASSIVE_STAGES.map(([key, label], order) => ({
          key,
          label,
          order,
        })),
      },
      targets: {
        create: {
          hostname: new URL(schedule.normalizedUrl).hostname,
          inScope: true,
          kind: "PRIMARY",
          metadata: {
            features,
            scheduleId: schedule.id,
            scheduled: true,
          },
          reason: "Scheduled scan target",
          url: schedule.normalizedUrl,
        },
      },
      userId: schedule.userId,
    },
  });
  const token = signWorkerToken(scan.id);
  const workerOptions = { features };
  let queueJobId = `serverless:${scan.id}`;
  let workerType = "SERVERLESS_PASSIVE_HTTP";

  if (shouldUseBullMq()) {
    try {
      const job = await getScanQueue().add(
        "passive",
        {
          features,
          mode: schedule.mode as ScanMode,
          scanId: scan.id,
          token,
          url: schedule.normalizedUrl,
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
          worker: "scheduled-bullmq-enqueue-fallback",
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
    db.scanSchedule.update({
      where: { id: schedule.id },
      data: { lastRunAt: now, lastScanId: scan.id, nextRunAt },
    }),
    db.auditLog.create({
      data: {
        action: "SCHEDULED_SCAN_CREATED",
        metadata: {
          features,
          mode: schedule.mode,
          nextRunAt: nextRunAt.toISOString(),
          normalizedUrl: schedule.normalizedUrl,
          scheduleId: schedule.id,
        },
        resourceId: scan.id,
        resourceType: "Scan",
        userId: schedule.userId,
      },
    }),
  ]);

  return {
    nextRunAt,
    scanId: scan.id,
    token,
    workerOptions,
  } satisfies ScheduledScanLaunch;
}

export async function kickScheduledScanWorker(
  origin: string,
  scanId: string,
  token: string,
  options: ScheduledScanLaunch["workerOptions"],
) {
  const url = new URL(`/api/internal/workers/passive/${scanId}`, origin);
  await fetch(url, {
    body: JSON.stringify(options ?? {}),
    cache: "no-store",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    method: "POST",
    signal: AbortSignal.timeout(300_000),
  });
}

function scanFeatures(value: unknown) {
  if (!value || typeof value !== "object") {
    return {
      apiDiscovery: true,
      browserRendering: true,
      screenshots: true,
    };
  }
  const data = value as Record<string, unknown>;
  return {
    apiDiscovery: data.apiDiscovery !== false,
    browserRendering: data.browserRendering !== false,
    screenshots: data.screenshots !== false,
  };
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
