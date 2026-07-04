import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { verifyWorkerToken } from "@/lib/worker-token";

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!verifyWorkerToken(request.headers.get("authorization")?.replace(/^Bearer /, "") ?? "", id)) return new NextResponse("Unauthorized", { status: 401 });
  const scan = await db.scan.findUnique({ where: { id }, select: { status: true } });
  return scan ? NextResponse.json(scan) : new NextResponse("Not found", { status: 404 });
}
