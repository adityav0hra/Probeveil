import { NextResponse } from "next/server";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";

export async function GET(
  _: Request,
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
  return NextResponse.json(scan);
}
