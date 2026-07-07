import { describe, expect, it } from "vitest";
import type { ReportScanData } from "../src/lib/reports/report-data";
import { coverageRows, reportMetrics } from "../src/lib/reports/report-metrics";

const baseScan: ReportScanData = {
  attackPaths: [],
  completedAt: "2026-07-04T00:00:00.000Z",
  coverageScore: 50,
  createdAt: "2026-07-04T00:00:00.000Z",
  endpoints: [],
  finalUrl: "https://example.com/",
  findings: [],
  id: "scan_1",
  mode: "FULL",
  normalizedUrl: "https://example.com/",
  originalUrl: "https://example.com/",
  securityScore: 100,
  services: [],
  stages: [],
  status: "COMPLETED",
  technologies: [],
};

describe("report metrics", () => {
  it("handles an empty findings report", () => {
    const metrics = reportMetrics(baseScan);
    expect(metrics.totalFindings).toBe(0);
    expect(metrics.highestSeverity).toBe("NONE");
    expect(metrics.confidenceScore).toBe(100);
    expect(metrics.severityCounts).toEqual([]);
  });

  it("calculates severity, confidence and coverage values", () => {
    const metrics = reportMetrics({
      ...baseScan,
      endpoints: [
        {
          method: "GET",
          parameters: [{ location: "query", name: "id", tested: true }],
          tested: true,
          url: "https://example.com/api/items?id=1",
        },
        {
          method: "GET",
          parameters: [{ location: "query", name: "page", tested: false }],
          tested: false,
          url: "https://example.com/page",
        },
      ],
      findings: [
        {
          category: "Access control",
          confidence: "CONFIRMED",
          description: "Role bypass",
          evidence: [],
          id: "finding_1",
          impact: "Sensitive data exposure",
          remediation: "Enforce authorization",
          reproductionSteps: [],
          severity: "HIGH",
          status: "OPEN",
          title: "Broken access control",
        },
        {
          category: "Configuration",
          confidence: "POTENTIAL",
          description: "Header missing",
          evidence: [],
          id: "finding_2",
          impact: "Browser hardening gap",
          remediation: "Add header",
          reproductionSteps: [],
          severity: "LOW",
          status: "OPEN",
          title: "Missing header",
        },
      ],
      securityScore: 72,
    });
    expect(metrics.highestSeverity).toBe("HIGH");
    expect(metrics.confirmedFindings).toBe(1);
    expect(metrics.apiEndpoints).toBe(1);
    expect(metrics.testedRoutes).toBe(1);
    expect(metrics.testedParameters).toBe(1);
    expect(metrics.confidenceScore).toBe(50);
    expect(metrics.severityCounts).toEqual([
      { label: "HIGH", value: 1 },
      { label: "LOW", value: 1 },
    ]);
  });

  it("builds coverage table rows without division errors", () => {
    expect(
      coverageRows(baseScan).find((row) => row.area === "Routes"),
    ).toMatchObject({
      coverage: 100,
      discovered: 0,
    });
  });

  it("counts evasion signals separately from ordinary findings", () => {
    const metrics = reportMetrics({
      ...baseScan,
      findings: [
        {
          category: "Evasion signal",
          confidence: "HIGH",
          description: "Challenge page",
          evidence: [],
          id: "finding_1",
          impact: "Coverage reduced",
          remediation: "Approve scanner coverage",
          reproductionSteps: [],
          scannerRuleId: "evasion/challenge-page",
          severity: "LOW",
          status: "OPEN",
          title: "Scanner-facing challenge detected",
        },
        {
          category: "Security headers",
          confidence: "HIGH",
          description: "Missing header",
          evidence: [],
          id: "finding_2",
          impact: "Browser hardening gap",
          remediation: "Add header",
          reproductionSteps: [],
          severity: "LOW",
          status: "OPEN",
          title: "Header missing",
        },
      ],
    });

    expect(metrics.totalFindings).toBe(2);
    expect(metrics.evasionSignals).toBe(1);
  });
});
