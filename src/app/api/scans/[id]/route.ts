import { after, NextResponse } from "next/server";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";
import { signWorkerToken } from "@/lib/worker-token";

export const maxDuration = 300;
export const runtime = "nodejs";

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  await requireRole(["ADMIN", "AUDITOR"]);
  const { id } = await params;
  const scan = await db.scan.findUnique({
    where: { id },
    include: {
      stages: { orderBy: { order: "asc" } },
      findings: { orderBy: [{ severity: "asc" }, { detectedAt: "desc" }] },
      endpoints: {
        orderBy: { url: "asc" },
        take: 500,
        include: { parameters: true },
      },
      services: true,
      technologies: true,
      attackPaths: true,
      reports: true,
      _count: { select: { findings: true, endpoints: true } },
    },
  });
  if (!scan)
    return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  if (scan.status === "QUEUED")
    schedulePassiveWorkerKick(request, scan.id, signWorkerToken(scan.id));
  return NextResponse.json(scan);
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
