import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { verifyWorkerToken } from "@/lib/worker-token";
import { runPassive } from "@/worker/passive";
import type { ScanJob } from "@/worker/types";

export const dynamic = "force-dynamic";
export const maxDuration = 300;
export const runtime = "nodejs";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const token =
    request.headers.get("authorization")?.replace(/^Bearer /, "") ?? "";
  if (!verifyWorkerToken(token, id))
    return new NextResponse("Unauthorized", { status: 401 });

  const scan = await db.scan.findUnique({
    where: { id },
    select: {
      id: true,
      mode: true,
      normalizedUrl: true,
      status: true,
      targets: {
        select: { metadata: true },
        take: 1,
        where: { kind: "PRIMARY" },
      },
    },
  });
  if (!scan) return new NextResponse("Not found", { status: 404 });
  if (scan.status !== "QUEUED")
    return NextResponse.json({ ok: true, skipped: scan.status });

  const claimed = await db.scan.updateMany({
    where: { id, status: "QUEUED" },
    data: { startedAt: new Date(), status: "RUNNING" },
  });
  if (claimed.count === 0)
    return NextResponse.json({ ok: true, skipped: "already-claimed" });

  await db.workerJob.upsert({
    where: { queueJobId: `serverless:${id}` },
    update: {
      attempts: { increment: 1 },
      completedAt: null,
      lastError: null,
      startedAt: new Date(),
      status: "RUNNING",
    },
    create: {
      attempts: 1,
      queueJobId: `serverless:${id}`,
      scanId: id,
      startedAt: new Date(),
      status: "RUNNING",
      workerType: "SERVERLESS_PASSIVE_HTTP",
    },
  });

  const origin = new URL(request.url).origin;
  const options = scanOptions(scan.targets[0]?.metadata);
  const job: ScanJob = {
    authHeaders: options.authHeaders,
    features: options.features,
    mode: scan.mode,
    scanId: scan.id,
    token,
    url: scan.normalizedUrl,
  };
  const emit = async (event: unknown) => {
    const response = await fetch(
      `${origin}/api/internal/scans/${job.scanId}/events`,
      {
        body: JSON.stringify(event),
        cache: "no-store",
        headers: {
          authorization: `Bearer ${job.token}`,
          "content-type": "application/json",
        },
        method: "POST",
        signal: AbortSignal.timeout(15_000),
      },
    );
    if (!response.ok)
      throw new Error(`Control-plane event rejected (${response.status})`);
  };
  const cancelled = async () => {
    const latest = await db.scan.findUnique({
      where: { id: job.scanId },
      select: { status: true },
    });
    return latest?.status === "CANCELLED";
  };

  try {
    await runPassive(job, emit, cancelled);
    if (await cancelled()) {
      await db.workerJob.updateMany({
        where: { scanId: id, status: "RUNNING" },
        data: {
          completedAt: new Date(),
          lastError: "Cancelled by admin",
          status: "CANCELLED",
        },
      });
      return NextResponse.json({ ok: true, cancelled: true });
    }
    await db.workerJob.updateMany({
      where: { scanId: id, status: "RUNNING" },
      data: { completedAt: new Date(), lastError: null, status: "COMPLETED" },
    });
    return NextResponse.json({ ok: true });
  } catch (error) {
    if (!(await cancelled())) {
      await emit({
        error: error instanceof Error ? error.message : String(error),
        type: "failed",
      });
    }
    await db.workerJob.updateMany({
      where: { scanId: id, status: "RUNNING" },
      data: {
        completedAt: new Date(),
        lastError: error instanceof Error ? error.message : String(error),
        status: "FAILED",
      },
    });
    throw error;
  }
}

function scanOptions(value: unknown): Pick<ScanJob, "authHeaders" | "features"> {
  if (!value || typeof value !== "object") return {};
  const data = value as {
    authHeaders?: Record<string, unknown>;
    features?: Record<string, unknown>;
  };
  return {
    authHeaders: Object.fromEntries(
      Object.entries(data.authHeaders ?? {}).filter(
        (entry): entry is [string, string] => typeof entry[1] === "string",
      ),
    ),
    features: {
      apiDiscovery: Boolean(data.features?.apiDiscovery),
      browserRendering: Boolean(data.features?.browserRendering),
      screenshots: Boolean(data.features?.screenshots),
    },
  };
}
