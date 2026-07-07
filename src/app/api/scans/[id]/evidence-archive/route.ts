import { createHash } from "node:crypto";
import { NextResponse } from "next/server";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";
import { canonicalScanUrl, type ReportScanData } from "@/lib/reports/report-data";
import { reportMetrics } from "@/lib/reports/report-metrics";

export async function GET(
  _: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  await requireRole(["ADMIN", "AUDITOR"]);
  const { id } = await params;
  const scan = await db.scan.findUnique({
    include: {
      attackPaths: true,
      endpoints: { include: { parameters: true }, orderBy: { url: "asc" } },
      findings: {
        include: {
          evidence: true,
          reviews: { include: { user: { select: { email: true, name: true } } } },
        },
        orderBy: [{ severity: "asc" }, { detectedAt: "desc" }],
      },
      reports: true,
      services: true,
      stages: { orderBy: { order: "asc" } },
      technologies: true,
    },
    where: { id },
  });
  if (!scan) return new NextResponse("Not found", { status: 404 });

  const archive = {
    exportedAt: new Date().toISOString(),
    format: "probeveil-evidence-archive-v1",
    integrity: archiveIntegrity(scan),
    limitation:
      "This archive contains persisted scan evidence and metadata. It does not include secrets submitted as scan authentication context.",
    metrics: reportMetrics(scan as unknown as ReportScanData),
    scan,
  };
  const hostname = safeHostname(canonicalScanUrl(scan));
  return NextResponse.json(archive, {
    headers: {
      "content-disposition": `attachment; filename=Probeveil-${hostname}-${id}-evidence-archive.json`,
    },
  });
}

function archiveIntegrity(value: unknown) {
  return {
    algorithm: "sha256",
    digest: createHash("sha256").update(JSON.stringify(value)).digest("hex"),
  };
}

function safeHostname(value: string) {
  try {
    return new URL(value).hostname.replace(/[^a-z0-9.-]+/gi, "-");
  } catch {
    return "scan";
  }
}
