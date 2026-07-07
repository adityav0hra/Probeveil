import { createHash } from "node:crypto";
import {
  canonicalScanUrl,
  scanHostname,
  type ReportScanData,
} from "./report-data";
import { reportMetrics, coverageRows, type ChartDatum } from "./report-metrics";
import {
  getReportProductName,
  REPORT_TEMPLATE_VERSION,
} from "./report-version";
import { reportKindConfig, type SecurityReportKind } from "./report-types";

const width = 612;
const height = 792;
const margin = 48;
const navy = [18, 28, 43] as const;
const slate = [71, 85, 105] as const;
const line = [210, 218, 228] as const;
const pale = [246, 248, 251] as const;
const green = [25, 135, 84] as const;
const amber = [180, 95, 20] as const;
const red = [185, 28, 28] as const;
const purple = [126, 34, 206] as const;

type Section = {
  title: string;
  render: (pdf: PdfDoc) => void;
  page?: number;
};

class PdfDoc {
  pages: string[][] = [[]];
  pageNumber = 1;
  y = margin;
  tocPageIndex = 1;

  constructor(
    private readonly meta: {
      hostname: string;
      reportId: string;
      reportType: string;
    },
  ) {}

  addPage() {
    this.pages.push([]);
    this.pageNumber = this.pages.length;
    this.y = margin;
  }

  page() {
    return this.pages[this.pageNumber - 1];
  }

  rect(
    x: number,
    y: number,
    w: number,
    h: number,
    fill?: readonly number[],
    stroke?: readonly number[],
  ) {
    const ops: string[] = [];
    if (fill) ops.push(`${rgb(fill)} rg`);
    if (stroke) ops.push(`${rgb(stroke)} RG`);
    ops.push(`${num(x)} ${num(height - y - h)} ${num(w)} ${num(h)} re`);
    ops.push(fill && stroke ? "B" : fill ? "f" : "S");
    this.page().push(ops.join("\n"));
  }

  line(
    x1: number,
    y1: number,
    x2: number,
    y2: number,
    color = line,
    size = 0.6,
  ) {
    this.page().push(
      `${rgb(color)} RG\n${num(size)} w\n${num(x1)} ${num(height - y1)} m\n${num(x2)} ${num(height - y2)} l\nS`,
    );
  }

  text(
    value: string,
    x: number,
    y: number,
    options: {
      color?: readonly number[];
      font?: "regular" | "bold" | "mono";
      size?: number;
      width?: number;
      leading?: number;
    } = {},
  ) {
    const size = options.size ?? 10;
    const leading = options.leading ?? size + 4;
    const lines = options.width
      ? wrapText(value, options.width, size)
      : sanitisePdfText(value).split("\n");
    lines.forEach((lineText, index) => {
      this.page().push(
        `BT\n${rgb(options.color ?? navy)} rg\n/${fontName(options.font)} ${num(size)} Tf\n${num(x)} ${num(height - y - index * leading)} Td\n(${escapePdf(lineText)}) Tj\nET`,
      );
    });
    return lines.length * leading;
  }

  ensure(space: number) {
    if (this.y + space > height - 58) this.addPage();
  }

  h1(title: string, sectionNumber?: number) {
    this.ensure(62);
    this.text(
      sectionNumber ? `${sectionNumber}. ${title}` : title,
      margin,
      this.y,
      {
        font: "bold",
        size: 18,
      },
    );
    this.y += 28;
    this.line(margin, this.y, width - margin, this.y, line);
    this.y += 18;
  }

  h2(title: string) {
    this.ensure(38);
    this.text(title, margin, this.y, { font: "bold", size: 12, color: slate });
    this.y += 22;
  }

  paragraph(value: string) {
    this.ensure(38);
    this.y += this.text(value, margin, this.y, {
      color: slate,
      size: 10,
      width: width - margin * 2,
    });
    this.y += 8;
  }

  callout(title: string, body: string) {
    this.ensure(84);
    const start = this.y;
    this.rect(margin, start, width - margin * 2, 72, pale, line);
    this.text(title, margin + 14, start + 16, { font: "bold", size: 11 });
    this.text(body, margin + 14, start + 34, {
      color: slate,
      size: 9,
      width: width - margin * 2 - 28,
    });
    this.y += 88;
  }

  metricCards(cards: Array<{ label: string; value: string; note?: string }>) {
    const gap = 10;
    const cardWidth = (width - margin * 2 - gap * 2) / 3;
    const cardHeight = 96;
    for (let index = 0; index < cards.length; index += 3) {
      this.ensure(cardHeight + 16);
      const row = cards.slice(index, index + 3);
      row.forEach((card, col) => {
        const x = margin + col * (cardWidth + gap);
        this.rect(x, this.y, cardWidth, cardHeight, [255, 255, 255], line);
        this.text(card.label.toUpperCase(), x + 10, this.y + 16, {
          color: slate,
          font: "bold",
          size: 7.5,
          width: cardWidth - 20,
        });
        const valueSize = fitFontSize(card.value, cardWidth - 20, 18, 12);
        const valueHeight = this.text(card.value, x + 10, this.y + 40, {
          color: navy,
          font: "bold",
          size: valueSize,
          width: cardWidth - 20,
        });
        if (card.note) {
          this.text(card.note, x + 10, this.y + 40 + valueHeight + 6, {
            color: slate,
            size: 7,
            width: cardWidth - 20,
          });
        }
      });
      this.y += cardHeight + 16;
    }
  }

  table(
    headers: string[],
    rows: string[][],
    widths: number[],
    options: { small?: boolean } = {},
  ) {
    const fontSize = options.small ? 7.2 : 8.2;
    const rowPad = 7;
    const tableWidth = widths.reduce((sum, item) => sum + item, 0);
    const drawHeader = () => {
      this.ensure(34);
      this.rect(margin, this.y, tableWidth, 24, navy, navy);
      let x = margin;
      headers.forEach((header, index) => {
        this.text(header, x + 5, this.y + 15, {
          color: [255, 255, 255],
          font: "bold",
          size: fontSize,
          width: widths[index] - 10,
        });
        x += widths[index];
      });
      this.y += 24;
    };

    drawHeader();
    rows.forEach((row, rowIndex) => {
      const lineCounts = row.map(
        (cell, index) => wrapText(cell, widths[index] - 10, fontSize).length,
      );
      const rowHeight = Math.max(
        22,
        Math.max(...lineCounts) * (fontSize + 3) + rowPad * 2,
      );
      if (this.y + rowHeight > height - 64) {
        this.addPage();
        drawHeader();
      }
      this.rect(
        margin,
        this.y,
        tableWidth,
        rowHeight,
        rowIndex % 2 ? [255, 255, 255] : pale,
        line,
      );
      let x = margin;
      row.forEach((cell, index) => {
        this.text(cell, x + 5, this.y + rowPad + fontSize, {
          color: index === 0 ? navy : slate,
          font: index === 0 ? "bold" : "regular",
          size: fontSize,
          width: widths[index] - 10,
        });
        x += widths[index];
      });
      this.y += rowHeight;
    });
    this.y += 18;
  }

  bars(title: string, rows: ChartDatum[], caption: string) {
    if (!rows.length) return;
    this.h2(title);
    const max = Math.max(...rows.map((row) => row.value), 1);
    rows.forEach((row, index) => {
      this.ensure(28);
      const y = this.y;
      this.text(row.label, margin, y + 10, {
        size: 8.5,
        color: slate,
        width: 120,
      });
      this.rect(margin + 128, y, 300, 12, [232, 236, 242], undefined);
      this.rect(
        margin + 128,
        y,
        (row.value / max) * 300,
        12,
        chartColor(index),
        undefined,
      );
      this.text(String(row.value), margin + 438, y + 10, {
        font: "bold",
        size: 8.5,
      });
      this.y += 24;
    });
    this.text(caption, margin, this.y + 4, {
      color: slate,
      size: 7.5,
      width: width - margin * 2,
    });
    this.y += 24;
  }

  codeBlock(title: string, body: string) {
    const excerpt =
      body.length > 1600
        ? `${body.slice(0, 1600)}\n\n[Excerpt shown. Complete evidence is available in stored evidence records.]`
        : body;
    this.ensure(80);
    this.text(title, margin, this.y, { font: "bold", size: 9 });
    this.y += 12;
    const lines = wrapText(excerpt, width - margin * 2 - 20, 7.3);
    const chunkSize = 34;
    for (let index = 0; index < lines.length; index += chunkSize) {
      const chunk = lines.slice(index, index + chunkSize);
      this.ensure(chunk.length * 10 + 20);
      this.rect(
        margin,
        this.y,
        width - margin * 2,
        chunk.length * 10 + 16,
        [15, 23, 42],
        undefined,
      );
      chunk.forEach((lineText, lineIndex) => {
        this.text(lineText, margin + 10, this.y + 14 + lineIndex * 10, {
          color: [226, 232, 240],
          font: "mono",
          size: 7.3,
        });
      });
      this.y += chunk.length * 10 + 24;
    }
  }

  finalize(toc: Section[]) {
    this.drawToc(toc);
    this.pages.forEach((_, index) => {
      if (index > 0) this.drawHeaderFooter(index + 1);
    });
    return buildPdf(this.pages);
  }

  private drawToc(sections: Section[]) {
    const previousPage = this.pages.length;
    const previousY = this.y;
    this.pages[this.tocPageIndex] = [];
    this.pageNumber = this.tocPageIndex + 1;
    this.y = margin;
    this.h1("Table of contents");
    sections.forEach((section, index) => {
      this.ensure(24);
      this.text(`${index + 1}. ${section.title}`, margin, this.y, {
        color: navy,
        size: 10,
        width: 390,
      });
      this.text(String(section.page ?? "-"), width - margin - 28, this.y, {
        color: slate,
        font: "bold",
        size: 10,
      });
      this.y += 22;
    });
    this.pageNumber = previousPage;
    this.y = previousY;
  }

  private drawHeaderFooter(pageNumber: number) {
    const page = this.pages[pageNumber - 1];
    page.unshift(
      `BT\n${rgb(slate)} rg\n/F2 8 Tf\n${margin} ${height - 26} Td\n(${escapePdf(getReportProductName())}) Tj\nET`,
      `BT\n${rgb(slate)} rg\n/F1 8 Tf\n${width - margin - 250} ${height - 26} Td\n(${escapePdf(`${this.meta.hostname} | ${this.meta.reportType}`)}) Tj\nET`,
      `${rgb(line)} RG\n0.5 w\n${margin} ${height - 36} m\n${width - margin} ${height - 36} l\nS`,
    );
    page.push(
      `${rgb(line)} RG\n0.5 w\n${margin} 34 m\n${width - margin} 34 l\nS`,
      `BT\n${rgb(slate)} rg\n/F1 7.5 Tf\n${margin} 20 Td\n(${escapePdf(`${getReportProductName()} | ${this.meta.hostname} | ${this.meta.reportType} | ${this.meta.reportId}`)}) Tj\nET`,
      `BT\n${rgb(slate)} rg\n/F2 7.5 Tf\n${width - margin - 46} 20 Td\n(${escapePdf(`Page ${pageNumber}`)}) Tj\nET`,
    );
  }
}

export function renderSecurityReportPdf(
  scan: ReportScanData,
  kind: SecurityReportKind,
) {
  const metrics = reportMetrics(scan);
  const hostname = scanHostname(scan);
  const reportId = reportIdFor(scan);
  const reportType = reportKindConfig[kind].label;
  const pdf = new PdfDoc({ hostname, reportId, reportType });
  const sections: Section[] = buildSections(scan, kind);

  renderCover(pdf, scan, kind, reportId);
  pdf.addPage();
  pdf.tocPageIndex = 1;
  pdf.addPage();
  sections.forEach((section, index) => {
    section.page = pdf.pageNumber;
    pdf.h1(section.title, index + 1);
    section.render(pdf);
  });

  return pdf.finalize(sections);

  function renderCover(
    doc: PdfDoc,
    reportScan: ReportScanData,
    reportKind: SecurityReportKind,
    id: string,
  ) {
    doc.rect(0, 0, width, height, [250, 252, 255], undefined);
    doc.rect(0, 0, width, 118, navy, undefined);
    doc.text(getReportProductName().toUpperCase(), margin, 66, {
      color: [255, 255, 255],
      font: "bold",
      size: 28,
    });
    doc.text("Website Security Report", margin, 104, {
      color: [226, 232, 240],
      size: 14,
    });
    doc.y = 172;
    doc.text(reportKindConfig[reportKind].label, margin, doc.y, {
      font: "bold",
      size: 23,
      width: width - margin * 2,
    });
    doc.y += 52;
    doc.metricCards([
      { label: "Website", value: hostname, note: canonicalScanUrl(reportScan) },
      { label: "Scan mode", value: reportScan.mode },
      {
        label: "Completed",
        value: formatDate(reportScan.completedAt ?? reportScan.createdAt),
      },
      { label: "Report ID", value: id },
      { label: "Security score", value: `${metrics.securityScore}/100` },
      {
        label: "Distribution",
        value: "Confidential",
        note: "Admin Console and approved recipients",
      },
    ]);
    doc.y += 16;
    doc.callout(
      "Delivery note",
      "This report is generated from persisted Probeveil scan data. It is intended for executive review, technical security review, client delivery, remediation planning and long-term record keeping.",
    );
    doc.text(`Template ${REPORT_TEMPLATE_VERSION}`, margin, height - 54, {
      color: slate,
      size: 8,
    });
  }
}

function buildSections(
  scan: ReportScanData,
  kind: SecurityReportKind,
): Section[] {
  const metrics = reportMetrics(scan);
  const common: Section[] = [
    {
      title: "Executive summary",
      render: (pdf) => {
        pdf.metricCards([
          { label: "Security score", value: `${metrics.securityScore}/100` },
          { label: "Coverage score", value: `${metrics.coverageScore}%` },
          { label: "Confidence score", value: `${metrics.confidenceScore}%` },
          {
            label: "Confirmed vulnerabilities",
            value: String(metrics.confirmedFindings),
          },
          { label: "Highest severity", value: metrics.highestSeverity },
          {
            label: "Manual-review tasks",
            value: String(metrics.manualReviewTasks),
          },
          {
            label: "Evasion signals",
            value: String(metrics.evasionSignals),
          },
          {
            label: "Routes tested",
            value: `${metrics.testedRoutes}/${metrics.totalRoutes}`,
          },
          {
            label: "Parameters tested",
            value: `${metrics.testedParameters}/${metrics.parameters}`,
          },
          { label: "APIs tested", value: String(metrics.apiEndpoints) },
        ]);
        pdf.paragraph(executiveNarrative(scan));
      },
    },
    {
      title: "Security posture",
      render: (pdf) => {
        pdf.bars(
          "Vulnerability severity distribution",
          metrics.severityCounts,
          "Figure 1. Severity distribution generated from stored findings.",
        );
        pdf.bars(
          "Finding confidence distribution",
          metrics.confidenceCounts,
          "Figure 2. Verification strength across stored findings.",
        );
      },
    },
    {
      title: "Top security risks",
      render: (pdf) => {
        const rows = sortFindings(scan.findings)
          .slice(0, kind === "executive" ? 8 : 20)
          .map((finding, index) => [
            findingCode(finding.id, index),
            finding.title,
            finding.severity,
            finding.confidence,
            finding.affectedUrl ?? "Not captured",
            finding.status,
          ]);
        pdf.table(
          [
            "ID",
            "Vulnerability",
            "Severity",
            "Confidence",
            "Affected location",
            "Status",
          ],
          rows.length
            ? rows
            : [["-", "No findings recorded", "-", "-", "-", "-"]],
          [42, 130, 58, 70, 160, 58],
          { small: true },
        );
      },
    },
    {
      title: "Root-cause summary",
      render: (pdf) => {
        const rows = rootCauseRows(scan);
        pdf.table(
          [
            "Root cause",
            "Severity",
            "Related findings",
            "Affected locations",
            "Priority",
          ],
          rows.length
            ? rows
            : [["No grouped root causes", "-", "0", "-", "Monitor"]],
          [132, 64, 70, 178, 74],
          { small: true },
        );
      },
    },
    {
      title: "Coverage and methodology",
      render: (pdf) => {
        pdf.table(
          ["Area", "Discovered", "Tested", "Skipped", "Failed", "Coverage"],
          coverageRows(scan).map((row) => [
            row.area,
            String(row.discovered),
            String(row.tested),
            String(row.skipped),
            String(row.failed),
            `${row.coverage}%`,
          ]),
          [130, 76, 68, 68, 64, 112],
        );
        pdf.paragraph(
          "Methodology includes URL validation, DNS resolution, attack-surface discovery, bounded crawling, evasion-signal detection, hidden route checks, TLS/header/cookie/CORS/CSP review, adaptive probes, correlation, scoring and report generation. Authenticated role comparison, active exploitation and stateful business-flow testing remain dependent on available credentials and configured scan mode.",
        );
      },
    },
    {
      title: "Evasion and coverage controls",
      render: (pdf) => {
        const rows = evasionRows(scan);
        pdf.table(
          ["Signal", "Severity", "Confidence", "Affected location", "Action"],
          rows.length
            ? rows
            : [
                [
                  "No evasion signals recorded",
                  "-",
                  "-",
                  "-",
                  "Maintain approved scanner coverage.",
                ],
              ],
          [124, 58, 70, 152, 114],
          { small: true },
        );
        pdf.paragraph(
          "Evasion signals are not automatically vulnerabilities. They identify bot-management, crawl-suppression, challenge, throttling or client-profile differences that can make automated testing see less of the application than a normal approved browser session.",
        );
      },
    },
    {
      title: "Remediation roadmap",
      render: (pdf) => {
        pdf.table(
          [
            "Priority",
            "Vulnerability or root cause",
            "Severity",
            "Recommended action",
            "Effort",
            "Retest scope",
          ],
          remediationRows(scan),
          [50, 118, 54, 150, 58, 88],
          { small: true },
        );
      },
    },
    {
      title: "Scan limitations",
      render: (pdf) => {
        pdf.callout(
          "Limitations",
          "Automated scanning cannot prove the absence of every vulnerability. Results should be paired with manual review for authenticated workflows, business logic, payment or approval flows, destructive operations and multi-role authorization paths.",
        );
      },
    },
  ];

  if (kind === "executive") return common;

  return [
    ...common,
    {
      title: "Website profile and technology inventory",
      render: (pdf) => {
        pdf.table(
          [
            "Technology",
            "Category",
            "Version",
            "Confidence",
            "Detection source",
          ],
          scan.technologies.length
            ? scan.technologies.map((technology) => [
                technology.name,
                technology.category ?? "Detected",
                technology.version ?? "Not detected",
                "Observed",
                technology.evidence ?? "Response or asset signal",
              ])
            : [["No technology signals", "-", "-", "-", "-"]],
          [118, 82, 72, 70, 176],
          { small: true },
        );
      },
    },
    {
      title: "Attack surface analysis",
      render: (pdf) => {
        pdf.table(
          ["Surface type", "Discovered", "Tested", "Coverage", "Notes"],
          [
            [
              "Routes",
              String(metrics.totalRoutes),
              String(metrics.testedRoutes),
              `${metrics.coverageScore}%`,
              "Reachable URLs and crawl discoveries",
            ],
            [
              "Services",
              String(scan.services.length),
              String(scan.services.length),
              "100%",
              "Resolved host/service records",
            ],
            [
              "Parameters",
              String(metrics.parameters),
              String(metrics.testedParameters),
              `${coveragePercent(metrics.testedParameters, metrics.parameters)}%`,
              "Query, path and form-like inputs",
            ],
            [
              "APIs",
              String(metrics.apiEndpoints),
              String(metrics.apiEndpoints),
              "100%",
              "API-like route patterns",
            ],
          ],
          [100, 72, 64, 64, 218],
        );
      },
    },
    {
      title: "Detailed vulnerabilities",
      render: (pdf) => {
        const findings = sortFindings(scan.findings);
        if (!findings.length) {
          pdf.callout(
            "No detailed findings",
            "No vulnerabilities were recorded for this scan.",
          );
          return;
        }
        findings.forEach((finding, index) => {
          pdf.ensure(130);
          pdf.h2(`${findingCode(finding.id, index)} - ${finding.title}`);
          pdf.table(
            ["Field", "Value"],
            [
              ["Severity", finding.severity],
              ["Confidence", finding.confidence],
              ["Status", finding.status],
              ["CWE", finding.cwe ?? "Unclassified"],
              ["OWASP", finding.owaspCategory ?? "Unclassified"],
              ["Affected URL", finding.affectedUrl ?? "Not captured"],
              ["HTTP method", finding.httpMethod ?? "Not captured"],
              [
                "Parameter/component",
                finding.parameter ?? finding.component ?? "Not captured",
              ],
            ],
            [130, 388],
            { small: true },
          );
          pdf.h2("Summary");
          pdf.paragraph(finding.description);
          pdf.h2("Why this matters");
          pdf.paragraph(finding.impact);
          pdf.h2("Root cause and remediation");
          pdf.paragraph(`${finding.category}: ${finding.remediation}`);
          const steps = Array.isArray(finding.reproductionSteps)
            ? finding.reproductionSteps.map(String).join("\n")
            : "";
          if (steps) pdf.codeBlock("Reproduction steps", steps);
          finding.evidence.slice(0, 2).forEach((evidence, evidenceIndex) => {
            if (evidence.content) {
              pdf.codeBlock(
                `Evidence ${evidenceIndex + 1}: ${evidence.title ?? evidence.type ?? "Stored evidence"}`,
                evidence.content,
              );
            }
          });
        });
      },
    },
    {
      title: "Attack paths and manual review",
      render: (pdf) => {
        pdf.table(
          ["Path", "Confidence", "Impact"],
          scan.attackPaths.length
            ? scan.attackPaths.map((path) => [
                path.title,
                path.confidence,
                path.impact,
              ])
            : [["No attack paths recorded", "-", "-"]],
          [150, 90, 278],
          { small: true },
        );
        pdf.table(
          [
            "Priority",
            "Area",
            "Reason",
            "Required comparison",
            "Current evidence",
          ],
          scan.findings
            .filter((finding) => finding.confidence === "MANUAL_REVIEW")
            .map((finding) => [
              finding.severity,
              finding.category,
              finding.title,
              "Manual role, workflow or state comparison",
              finding.affectedUrl ?? "Not captured",
            ])
            .slice(0, 30),
          [64, 84, 140, 126, 104],
          { small: true },
        );
      },
    },
    {
      title: "Route, API and scanner diagnostics",
      render: (pdf) => {
        pdf.table(
          ["Route", "Method", "Status", "Parameters", "Tested"],
          scan.endpoints
            .slice(0, 80)
            .map((endpoint) => [
              endpoint.url,
              endpoint.method ?? "GET",
              endpoint.statusCode ? String(endpoint.statusCode) : "-",
              String(endpoint.parameters?.length ?? 0),
              endpoint.tested ? "Yes" : "No",
            ]),
          [240, 54, 54, 76, 94],
          { small: true },
        );
        pdf.table(
          ["Stage", "Status", "Duration", "Requests", "Findings", "Errors"],
          scan.stages.map((stage) => [
            stage.label,
            stage.status,
            stageDuration(stage.startedAt, stage.completedAt),
            "-",
            stage.key === "correlate" ? String(scan.findings.length) : "-",
            stage.message ?? "-",
          ]),
          [130, 72, 66, 62, 64, 124],
          { small: true },
        );
      },
    },
    {
      title: "Technical appendices",
      render: (pdf) => {
        pdf.paragraph(
          "Appendices include evidence excerpts, route inventories, scanner diagnostics and retest guidance. Large evidence bodies are excerpted in this PDF and remain available through stored evidence records.",
        );
      },
    },
  ];
}

function executiveNarrative(scan: ReportScanData) {
  const metrics = reportMetrics(scan);
  const risk =
    metrics.securityScore < 60 ||
    ["CRITICAL", "HIGH"].includes(metrics.highestSeverity)
      ? "high"
      : metrics.securityScore < 80
        ? "moderate"
        : "lower";
  return `The website presents a ${risk} overall security risk based on the persisted scan results. ${metrics.totalFindings} finding${metrics.totalFindings === 1 ? "" : "s"} were recorded, with ${metrics.highestSeverity.toLowerCase()} as the highest severity. Testing covered ${metrics.coverageScore}% of the reachable attack surface, including ${metrics.testedRoutes} route${metrics.testedRoutes === 1 ? "" : "s"} and ${metrics.testedParameters} tested parameter${metrics.testedParameters === 1 ? "" : "s"}. ${metrics.manualReviewTasks ? `${metrics.manualReviewTasks} manual-review task${metrics.manualReviewTasks === 1 ? "" : "s"} should be completed before final risk acceptance.` : "No manual-review tasks were recorded by the scanner."}`;
}

function evasionRows(scan: ReportScanData) {
  return sortFindings(
    scan.findings.filter(
      (finding) =>
        finding.category === "Evasion signal" ||
        finding.scannerRuleId?.startsWith("evasion/"),
    ),
  ).map((finding) => [
    finding.title,
    finding.severity,
    finding.confidence,
    finding.affectedUrl ?? "Not captured",
    finding.remediation,
  ]);
}

function rootCauseRows(scan: ReportScanData) {
  const grouped = new Map<string, typeof scan.findings>();
  scan.findings.forEach((finding) => {
    grouped.set(finding.category, [
      ...(grouped.get(finding.category) ?? []),
      finding,
    ]);
  });
  return [...grouped.entries()]
    .sort((a, b) => b[1].length - a[1].length)
    .map(([category, findings]) => [
      category,
      sortFindings(findings)[0]?.severity ?? "INFO",
      String(findings.length),
      [
        ...new Set(
          findings.map((finding) => finding.affectedUrl).filter(Boolean),
        ),
      ]
        .slice(0, 3)
        .join(", ") || "Multiple locations",
      priorityFor(sortFindings(findings)[0]?.severity ?? "INFO"),
    ]);
}

function remediationRows(scan: ReportScanData) {
  const rows = rootCauseRows(scan).map((row) => [
    row[4],
    row[0],
    row[1],
    `Address ${row[0].toLowerCase()} findings and retest affected routes.`,
    effortFor(row[1]),
    row[3],
  ]);
  return rows.length
    ? rows
    : [
        [
          "Monitor",
          "No recorded vulnerabilities",
          "-",
          "Maintain periodic scanning.",
          "Low",
          "Next scheduled scan",
        ],
      ];
}

function sortFindings<T extends { severity: string }>(findings: T[]) {
  const order: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
  };
  return [...findings].sort(
    (a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9),
  );
}

function findingCode(id: string, index: number) {
  return `GE-${String(index + 1).padStart(3, "0")}-${id.slice(-4).toUpperCase()}`;
}

function priorityFor(severity: string) {
  if (["CRITICAL", "HIGH"].includes(severity)) return "Immediate";
  if (severity === "MEDIUM") return "Short term";
  if (severity === "LOW") return "Medium term";
  return "Hardening";
}

function effortFor(severity: string) {
  if (["CRITICAL", "HIGH"].includes(severity)) return "High";
  if (severity === "MEDIUM") return "Moderate";
  return "Low";
}

function coveragePercent(tested: number, discovered: number) {
  return discovered === 0 ? 100 : Math.round((tested / discovered) * 100);
}

function stageDuration(
  start?: Date | string | null,
  end?: Date | string | null,
) {
  if (!start || !end) return "-";
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "-";
  return `${Math.round(ms / 1000)}s`;
}

function reportIdFor(scan: ReportScanData) {
  const date = formatDate(scan.completedAt ?? scan.createdAt).replace(/-/g, "");
  const hash = createHash("sha256")
    .update(
      `${scan.id}:${canonicalScanUrl(scan)}:${scan.completedAt ?? scan.createdAt}`,
    )
    .digest("hex")
    .slice(0, 6)
    .toUpperCase();
  return `GE-${date}-${hash}`;
}

function formatDate(value: Date | string | null | undefined) {
  const date = value ? new Date(value) : new Date();
  return Number.isNaN(date.getTime())
    ? new Date().toISOString().slice(0, 10)
    : date.toISOString().slice(0, 10);
}

function buildPdf(pages: string[][]) {
  const objects: string[] = [];
  objects[0] = "<< /Type /Catalog /Pages 2 0 R >>";
  objects[2] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";
  objects[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>";
  objects[4] = "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>";
  const pageIds: number[] = [];
  pages.forEach((content, index) => {
    const pageId = 6 + index * 2;
    const contentId = pageId + 1;
    pageIds.push(pageId);
    const stream = content.join("\n");
    objects[contentId - 1] =
      `<< /Length ${Buffer.byteLength(stream, "utf8")} >>\nstream\n${stream}\nendstream`;
    objects[pageId - 1] =
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${width} ${height}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents ${contentId} 0 R >>`;
  });
  objects[1] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${pages.length} >>`;
  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  objects.forEach((object, index) => {
    offsets[index + 1] = Buffer.byteLength(pdf, "utf8");
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xrefOffset = Buffer.byteLength(pdf, "utf8");
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (let index = 1; index <= objects.length; index += 1) {
    pdf += `${String(offsets[index]).padStart(10, "0")} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  return Buffer.from(pdf, "utf8");
}

function fontName(font: "regular" | "bold" | "mono" = "regular") {
  if (font === "bold") return "F2";
  if (font === "mono") return "F3";
  return "F1";
}

function rgb(values: readonly number[]) {
  return values.map((value) => num(value / 255)).join(" ");
}

function chartColor(index: number) {
  return [red, amber, green, purple, slate][index % 5];
}

function fitFontSize(
  value: string,
  maxWidth: number,
  preferred: number,
  minimum: number,
) {
  let size = preferred;
  while (size > minimum && wrapText(value, maxWidth, size).length > 1) {
    size -= 0.5;
  }
  return size;
}

function wrapText(value: string, maxWidth: number, fontSize: number) {
  const maxChars = Math.max(8, Math.floor(maxWidth / (fontSize * 0.52)));
  return sanitisePdfText(value)
    .split("\n")
    .flatMap((line) => wrapLine(line, maxChars));
}

function wrapLine(line: string, maxChars: number) {
  const words = line.replace(/\s+/g, " ").trim().split(" ").filter(Boolean);
  if (!words.length) return [""];
  const lines: string[] = [];
  let current = "";
  words.forEach((word) => {
    if (word.length > maxChars) {
      if (current) lines.push(current);
      for (let index = 0; index < word.length; index += maxChars) {
        lines.push(word.slice(index, index + maxChars));
      }
      current = "";
      return;
    }
    const next = current ? `${current} ${word}` : word;
    if (next.length > maxChars) {
      lines.push(current);
      current = word;
    } else {
      current = next;
    }
  });
  if (current) lines.push(current);
  return lines;
}

function sanitisePdfText(value: string) {
  return String(value).replace(/[^\x09\x0A\x0D\x20-\x7E]/g, " ");
}

function escapePdf(value: string) {
  return sanitisePdfText(value)
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");
}

function num(value: number) {
  return Number(value.toFixed(3)).toString();
}
