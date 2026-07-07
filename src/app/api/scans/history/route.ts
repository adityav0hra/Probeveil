import { NextResponse } from "next/server";
import { ScanStatus } from "@prisma/client";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";

export const runtime = "nodejs";

export async function DELETE() {
  const session = await requireRole(["ADMIN"]);
  const activeCount = await db.scan.count({
    where: { status: { in: [ScanStatus.QUEUED, ScanStatus.RUNNING] } },
  });
  if (activeCount > 0) {
    return NextResponse.json(
      {
        error: "Cancel or wait for running scans before deleting scan history.",
      },
      { status: 409 },
    );
  }

  const scanCount = await db.scan.count();
  await db.$transaction([
    db.scan.deleteMany({}),
    db.auditLog.create({
      data: {
        userId: session.user.id,
        action: "SCAN_HISTORY_DELETED",
        resourceType: "Scan",
        metadata: { deletedScans: scanCount },
      },
    }),
  ]);

  return NextResponse.json({ deletedScans: scanCount, ok: true });
}
