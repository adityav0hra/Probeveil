import { describe, expect, it } from "vitest";
import { renderSecurityReportPdf } from "../src/lib/reports/pdf-renderer";
import type { ReportScanData } from "../src/lib/reports/report-data";

const scan: ReportScanData = {
  attackPaths: [
    {
      confidence: "HIGH",
      edges: [],
      id: "path_1",
      impact: "A chained exposure could lead to account data access.",
      nodes: [],
      title: "Public endpoint to sensitive object path",
    },
  ],
  completedAt: "2026-07-04T01:00:00.000Z",
  coverageScore: 88,
  createdAt: "2026-07-04T00:00:00.000Z",
  endpoints: [
    {
      method: "GET",
      parameters: [{ location: "query", name: "id", tested: true }],
      statusCode: 200,
      tested: true,
      url: "https://example.com/api/users?id=1",
    },
  ],
  finalUrl: "https://example.com/",
  findings: [
    {
      affectedUrl: "https://example.com/api/users?id=1",
      category: "Access control",
      confidence: "CONFIRMED",
      cwe: "CWE-639",
      cvssScore: 8.1,
      description: "The endpoint returns records without enforcing ownership.",
      evidence: [
        {
          content: "HTTP 200 response returned another account record.",
          title: "Response evidence",
          type: "HTTP",
        },
      ],
      httpMethod: "GET",
      id: "finding_1",
      impact: "A user may access another user's private data.",
      owaspCategory: "A01:2021 Broken Access Control",
      parameter: "id",
      remediation: "Enforce object-level authorization on every request.",
      reproductionSteps: [
        "Log in as a low privilege user.",
        "Request /api/users?id=<another-user-id>.",
      ],
      retestInstructions:
        "Confirm cross-account identifiers return 403 or 404.",
      severity: "HIGH",
      status: "OPEN",
      title: "Insecure direct object reference",
    },
  ],
  id: "scan_pdf_test",
  mode: "MAXIMUM",
  normalizedUrl: "https://example.com/",
  originalUrl: "https://example.com/",
  securityScore: 64,
  services: [{ host: "example.com", port: 443, protocol: "https" }],
  stages: [
    {
      completedAt: "2026-07-04T00:05:00.000Z",
      key: "crawl",
      label: "Crawl",
      progress: 100,
      startedAt: "2026-07-04T00:00:00.000Z",
      status: "COMPLETED",
    },
  ],
  status: "COMPLETED",
  technologies: [{ category: "Framework", name: "Next.js", version: "15" }],
};

describe("security report PDF renderer", () => {
  it("renders distinct executive and technical PDFs with expected report copy", () => {
    const executive = renderSecurityReportPdf(scan, "executive");
    const technical = renderSecurityReportPdf(scan, "technical");

    expect(executive.subarray(0, 8).toString()).toBe("%PDF-1.4");
    expect(technical.subarray(0, 8).toString()).toBe("%PDF-1.4");
    expect(technical.byteLength).toBeGreaterThan(executive.byteLength);

    const executiveText = executive.toString("latin1");
    const technicalText = technical.toString("latin1");

    expect(executiveText).toContain("Executive Security Report");
    expect(executiveText).toContain("Executive summary");
    expect(executiveText).toContain("Security posture");
    expect(technicalText).toContain("Full Technical Security Report");
    expect(technicalText).toContain("Detailed vulnerabilities");
    expect(technicalText).toContain("Attack paths and manual review");
    expect(`${executiveText}\n${technicalText}`).not.toMatch(
      new RegExp(["assess", "ment"].join(""), "i"),
    );
  });

  it("renders compliance-style report modes with mapped evidence", () => {
    const owasp = renderSecurityReportPdf(scan, "owasp-top-10");
    const remediation = renderSecurityReportPdf(scan, "remediation-tracking");

    expect(owasp.subarray(0, 8).toString()).toBe("%PDF-1.4");
    expect(remediation.subarray(0, 8).toString()).toBe("%PDF-1.4");

    const owaspText = owasp.toString("latin1");
    const remediationText = remediation.toString("latin1");

    expect(owaspText).toContain("OWASP Top 10 Report");
    expect(owaspText).toContain("Broken Access Control");
    expect(owaspText).toContain("Control mapping");
    expect(remediationText).toContain("Remediation Tracking Report");
    expect(remediationText).toContain("Finding lifecycle tracker");
    expect(remediationText).toContain("Retest scope");
  });
});
