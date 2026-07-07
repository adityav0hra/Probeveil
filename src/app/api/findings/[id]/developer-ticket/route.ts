import { NextResponse } from "next/server";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";
import { buildRemediationAssistant } from "@/lib/remediation-assistant";

export const runtime = "nodejs";

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const session = await requireRole(["ADMIN", "AUDITOR"]);
  const { id } = await params;
  const finding = await db.finding.findUnique({
    include: { scan: true },
    where: { id },
  });
  if (!finding)
    return NextResponse.json({ error: "Finding not found." }, { status: 404 });

  const assistant = buildRemediationAssistant(finding, finding.scan);
  await db.auditLog.create({
    data: {
      userId: session.user.id,
      action: "DEVELOPER_TICKET_GENERATED",
      resourceType: "Finding",
      resourceId: id,
      metadata: {
        scannerRuleId: finding.scannerRuleId,
        severity: finding.severity,
        url: finding.affectedUrl ?? finding.scan.normalizedUrl,
      },
    },
  });

  const filename = `${slug(finding.title)}-${finding.id.slice(0, 8)}.md`;
  return new NextResponse(assistant.developerTicket, {
    headers: {
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Content-Type": "text/markdown; charset=utf-8",
    },
  });
}

function slug(value: string) {
  return (
    value
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/(^-|-$)/g, "")
      .slice(0, 72) || "probeveil-finding"
  );
}
