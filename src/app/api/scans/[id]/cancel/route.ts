import { NextResponse } from "next/server";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";

export async function POST(_: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await requireRole(["ADMIN"]);
  const { id } = await params;
  const scan = await db.scan.update({ where: { id }, data: { status: "CANCELLED", cancelledAt: new Date(), stages: { updateMany: { where: { status: { in: ["PENDING", "RUNNING"] } }, data: { status: "CANCELLED", completedAt: new Date() } } } } });
  await db.auditLog.create({ data: { userId: session.user.id, action: "SCAN_CANCELLED", resourceType: "Scan", resourceId: id } });
  return NextResponse.json({ status: scan.status });
}
