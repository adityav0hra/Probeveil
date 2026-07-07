import { Worker } from "bullmq";
import IORedis from "ioredis";
import { db } from "@/lib/db";
import { runPassive } from "./passive";
import type { ScanJob } from "./types";

const connection = new IORedis(process.env.REDIS_URL ?? "redis://localhost:6379", { maxRetriesPerRequest: null });
const api = process.env.INTERNAL_API_URL ?? "http://localhost:3000";

new Worker<ScanJob>("scan.passive", async (queueJob) => {
  const job = queueJob.data;
  const claimed = await db.scan.updateMany({
    where: { id: job.scanId, status: "QUEUED" },
    data: { startedAt: new Date(), status: "RUNNING" },
  });
  if (claimed.count === 0) return;
  await db.workerJob.upsert({
    where: { queueJobId: String(queueJob.id) },
    update: {
      attempts: { increment: 1 },
      startedAt: new Date(),
      status: "RUNNING",
    },
    create: {
      attempts: 1,
      queueJobId: String(queueJob.id),
      scanId: job.scanId,
      startedAt: new Date(),
      status: "RUNNING",
      workerType: "PASSIVE_HTTP",
    },
  });
  const emit = async (event: unknown) => {
    const response = await fetch(`${api}/api/internal/scans/${job.scanId}/events`, { method: "POST", headers: { authorization: `Bearer ${job.token}`, "content-type": "application/json" }, body: JSON.stringify(event), signal: AbortSignal.timeout(15_000) });
    if (!response.ok) {
      const detail = await response.text().catch(() => "");
      throw new Error(`Control-plane event rejected (${response.status})${detail ? `: ${detail.slice(0, 500)}` : ""}`);
    }
  };
  const cancelled = async () => {
    const response = await fetch(`${api}/api/internal/scans/${job.scanId}/status`, { headers: { authorization: `Bearer ${job.token}` }, signal: AbortSignal.timeout(5000) });
    return response.ok && (await response.json()).status === "CANCELLED";
  };
  try {
    await runPassive(job, emit, cancelled);
    await db.workerJob.updateMany({
      where: { scanId: job.scanId, status: "RUNNING" },
      data: { completedAt: new Date(), status: "COMPLETED" },
    });
  } catch (error) {
    if (!(await cancelled()))
      await emit({
        type: "failed",
        error: error instanceof Error ? error.message : String(error),
      });
    await db.workerJob.updateMany({
      where: { scanId: job.scanId, status: "RUNNING" },
      data: {
        completedAt: new Date(),
        lastError: error instanceof Error ? error.message : String(error),
        status: "FAILED",
      },
    });
    throw error;
  }
}, { connection: connection as never, concurrency: Number(process.env.WORKER_CONCURRENCY ?? 2), lockDuration: 60_000 });

console.log(JSON.stringify({ level: "info", message: "passive worker ready", queue: "scan.passive" }));
