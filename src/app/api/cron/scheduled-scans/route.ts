import { after, NextResponse } from "next/server";
import { db } from "@/lib/db";
import {
  kickScheduledScanWorker,
  launchScheduledScan,
} from "@/lib/scheduled-scans";

export const dynamic = "force-dynamic";
export const maxDuration = 300;
export const runtime = "nodejs";

export async function GET(request: Request) {
  if (!authorized(request))
    return new NextResponse("Unauthorized", { status: 401 });

  const now = new Date();
  const schedules = await db.scanSchedule.findMany({
    orderBy: { nextRunAt: "asc" },
    take: 10,
    where: {
      enabled: true,
      nextRunAt: { lte: now },
    },
  });
  const origin = new URL(request.url).origin;
  const launched = [];

  for (const schedule of schedules) {
    const result = await launchScheduledScan(schedule);
    launched.push({
      nextRunAt: result.nextRunAt.toISOString(),
      scanId: result.scanId,
      scheduleId: schedule.id,
      skipped: result.skipped,
    });

    if (result.scanId && result.token && !result.skipped) {
      after(async () => {
        try {
          await kickScheduledScanWorker(
            origin,
            result.scanId!,
            result.token!,
            result.workerOptions,
          );
        } catch (error) {
          console.warn(
            JSON.stringify({
              error: error instanceof Error ? error.message : String(error),
              scanId: result.scanId,
              scheduleId: schedule.id,
              worker: "scheduled-serverless-passive-kick",
            }),
          );
        }
      });
    }
  }

  return NextResponse.json({
    checkedAt: now.toISOString(),
    count: launched.length,
    launched,
  });
}

function authorized(request: Request) {
  const secret = process.env.CRON_SECRET;
  if (!secret) return process.env.NODE_ENV !== "production";
  return request.headers.get("authorization") === `Bearer ${secret}`;
}
