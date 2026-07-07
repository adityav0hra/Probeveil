import { createHash } from "node:crypto";
import { NextResponse } from "next/server";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";
import {
  buildReportFilename,
  contentDisposition,
} from "@/lib/reports/filename";
import {
  canonicalScanUrl,
  type ReportScanData,
} from "@/lib/reports/report-data";
import { reportMetrics } from "@/lib/reports/report-metrics";
import { renderSecurityReportPdf } from "@/lib/reports/pdf-renderer";
import { parseReportKind, reportKindConfig } from "@/lib/reports/report-types";
import {
  REPORT_GENERATOR_VERSION,
  REPORT_TEMPLATE_VERSION,
  getReportProductName,
} from "@/lib/reports/report-version";

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const session = await requireRole(["ADMIN", "AUDITOR"]);
  const { id } = await params;
  const scan = await db.scan.findUnique({
    include: {
      attackPaths: true,
      assets: { orderBy: [{ kind: "asc" }, { lastSeenAt: "desc" }] },
      endpoints: { include: { parameters: true }, orderBy: { url: "asc" } },
      findings: { include: { evidence: true, issue: true } },
      services: true,
      stages: { orderBy: { order: "asc" } },
      technologies: true,
    },
    where: { id },
  });
  if (!scan) return new NextResponse("Not found", { status: 404 });

  const reportScan = scan as unknown as ReportScanData;
  const url = new URL(request.url);
  const format = url.searchParams.get("format") ?? "json";
  const kind = parseReportKind(url.searchParams.get("type"));

  if (format === "json") {
    return new NextResponse(
      JSON.stringify(
        {
          generatedAt: new Date().toISOString(),
          limitation:
            "This scan performs automated security testing across the discovered attack surface. Automated scanning cannot mathematically guarantee that every vulnerability has been identified.",
          metrics: reportMetrics(reportScan),
          scan,
        },
        null,
        2,
      ),
      {
        headers: {
          "content-disposition": `attachment; filename=probeveil-${id}.json`,
          "content-type": "application/json",
        },
      },
    );
  }

  if (format === "csv") {
    return new NextResponse(csvExport(reportScan), {
      headers: {
        "content-disposition": `attachment; filename=probeveil-${id}-findings.csv`,
        "content-type": "text/csv; charset=utf-8",
      },
    });
  }

  if (format === "sarif") {
    return new NextResponse(JSON.stringify(sarifExport(reportScan), null, 2), {
      headers: {
        "content-disposition": `attachment; filename=probeveil-${id}.sarif`,
        "content-type": "application/sarif+json",
      },
    });
  }

  if (format === "pdf") {
    const startedAt = new Date();
    const pdf = renderSecurityReportPdf(reportScan, kind);
    const hash = createHash("sha256").update(pdf).digest("hex");
    const filename = buildReportFilename({
      completedAt: scan.completedAt ?? scan.createdAt,
      kind,
      url: canonicalScanUrl(reportScan),
    });

    await db.report.upsert({
      create: {
        path: filename,
        scanId: scan.id,
        sha256: hash,
        size: pdf.byteLength,
        status: "READY",
        type: reportKindConfig[kind].prismaType,
      },
      update: {
        path: filename,
        sha256: hash,
        size: pdf.byteLength,
        status: "READY",
      },
      where: {
        scanId_type: {
          scanId: scan.id,
          type: reportKindConfig[kind].prismaType,
        },
      },
    });

    await db.auditLog.create({
      data: {
        action: "REPORT_GENERATED",
        metadata: {
          filename,
          generatorVersion: REPORT_GENERATOR_VERSION,
          productName: getReportProductName(),
          reportType: reportKindConfig[kind].label,
          scanDataVersion: scan.updatedAt.toISOString(),
          sha256: hash,
          size: pdf.byteLength,
          startedAt: startedAt.toISOString(),
          templateVersion: REPORT_TEMPLATE_VERSION,
        },
        resourceId: scan.id,
        resourceType: "Report",
        userId: session.user.id,
      },
    });

    return new NextResponse(new Uint8Array(pdf), {
      headers: {
        "content-disposition": contentDisposition(filename),
        "content-type": "application/pdf",
        "x-probeveil-report-filename": filename,
        "x-probeveil-report-template-version": REPORT_TEMPLATE_VERSION,
      },
    });
  }

  return new NextResponse(htmlReport(reportScan), {
    headers: {
      "content-disposition": `attachment; filename=probeveil-${id}.html`,
      "content-type": "text/html; charset=utf-8",
    },
  });
}

function htmlReport(scan: ReportScanData) {
  const metrics = reportMetrics(scan);
  const rows = scan.findings
    .map(
      (finding) =>
        `<tr><td>${escapeHtml(finding.severity)}</td><td>${escapeHtml(finding.title)}</td><td>${escapeHtml(finding.confidence)}</td><td>${escapeHtml(finding.affectedUrl ?? "Not captured")}</td></tr>`,
    )
    .join("");
  const evasionRows = scan.findings
    .filter(
      (finding) =>
        finding.category === "Evasion signal" ||
        finding.scannerRuleId?.startsWith("evasion/"),
    )
    .map(
      (finding) =>
        `<tr><td>${escapeHtml(finding.title)}</td><td>${escapeHtml(finding.severity)}</td><td>${escapeHtml(finding.confidence)}</td><td>${escapeHtml(finding.affectedUrl ?? "Not captured")}</td></tr>`,
    )
    .join("");
  const productName = escapeHtml(getReportProductName());
  return `<!doctype html><html><head><meta charset="utf-8"><title>${productName} report</title><style>
    body{font:14px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;margin:40px;color:#101820;background:#fbfcfd}
    h1{font-size:30px;margin-bottom:4px} h2{margin-top:30px;border-bottom:1px solid #d9e1e8;padding-bottom:8px}
    .grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px;margin:24px 0}.card{background:white;border:1px solid #d9e1e8;border-radius:8px;padding:16px}
    .card b{display:block;font-size:24px;margin-top:8px}table{width:100%;border-collapse:collapse;background:white;border:1px solid #d9e1e8}td,th{padding:10px;border-bottom:1px solid #e8edf2;text-align:left}
  </style></head><body>
    <h1>${productName} security report</h1>
    <p>${escapeHtml(canonicalScanUrl(scan))}</p>
    <div class="grid"><div class="card">Security score<b>${metrics.securityScore}/100</b></div><div class="card">Coverage<b>${metrics.coverageScore}%</b></div><div class="card">Confidence<b>${metrics.confidenceScore}%</b></div><div class="card">Findings<b>${metrics.totalFindings}</b></div><div class="card">Evasion signals<b>${metrics.evasionSignals}</b></div></div>
    <h2>Evasion and coverage controls</h2><table><thead><tr><th>Signal</th><th>Severity</th><th>Confidence</th><th>Affected location</th></tr></thead><tbody>${evasionRows || "<tr><td colspan='4'>No evasion signals recorded.</td></tr>"}</tbody></table>
    <h2>Findings</h2><table><thead><tr><th>Severity</th><th>Finding</th><th>Confidence</th><th>Affected location</th></tr></thead><tbody>${rows || "<tr><td colspan='4'>No findings recorded.</td></tr>"}</tbody></table>
  </body></html>`;
}

function csvExport(scan: ReportScanData) {
  const rows = [
    [
      "ID",
      "Issue ID",
      "Issue status",
      "Severity",
      "Confidence",
      "Status",
      "Title",
      "Affected location",
    ],
    ...scan.findings.map((finding) => [
      finding.id,
      finding.issueId ?? "",
      finding.issue?.status ?? "",
      finding.severity,
      finding.confidence,
      finding.status,
      finding.title,
      finding.affectedUrl ?? "",
    ]),
  ];
  return rows
    .map((row) =>
      row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(","),
    )
    .join("\n");
}

function sarifExport(scan: ReportScanData) {
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        results: scan.findings.map((finding) => ({
          level: sarifLevel(finding.severity),
          message: { text: finding.description },
          properties: {
            issueId: finding.issueId,
            issueStatus: finding.issue?.status,
            occurrenceCount: finding.issue?.occurrenceCount,
          },
          ruleId: finding.scannerRuleId ?? finding.category,
          locations: finding.affectedUrl
            ? [
                {
                  physicalLocation: {
                    artifactLocation: { uri: finding.affectedUrl },
                  },
                },
              ]
            : [],
        })),
        tool: {
          driver: {
            informationUri: "https://example.com/probeveil",
            name: getReportProductName(),
            rules: scan.findings.map((finding) => ({
              id: finding.scannerRuleId ?? finding.category,
              name: finding.title,
              shortDescription: { text: finding.title },
            })),
          },
        },
      },
    ],
    version: "2.1.0",
  };
}

function sarifLevel(severity: string) {
  if (["CRITICAL", "HIGH"].includes(severity)) return "error";
  if (severity === "MEDIUM") return "warning";
  return "note";
}

function escapeHtml(value: string) {
  return value.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
}
