import { NextResponse } from "next/server";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const session = await requireRole(["ADMIN"]);
  const { id } = await params;
  const now = new Date();
  const scan = await db.scan.update({
    where: { id },
    data: {
      status: "CANCELLED",
      cancelledAt: now,
      completedAt: now,
      stages: {
        updateMany: {
          where: { status: { in: ["PENDING", "RUNNING"] } },
          data: { status: "CANCELLED", completedAt: now },
        },
      },
      jobs: {
        updateMany: {
          where: { status: { in: ["QUEUED", "RUNNING"] } },
          data: {
            completedAt: now,
            lastError: "Cancelled by admin",
            status: "CANCELLED",
          },
        },
      },
    },
  });
  await db.auditLog.create({
    data: {
      userId: session.user.id,
      action: "SCAN_CANCELLED",
      resourceType: "Scan",
      resourceId: id,
    },
  });

  const accept = request.headers.get("accept") ?? "";
  if (accept.includes("text/html")) {
    return NextResponse.redirect(new URL(`/scans/${id}`, request.url), 303);
  }

  return NextResponse.json({ status: scan.status });
}
