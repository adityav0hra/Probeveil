import { describe, expect, it } from "vitest";
import {
  complianceRowsForKind,
  remediationTrackingRows,
} from "../src/lib/reports/compliance";
import type { ReportScanData } from "../src/lib/reports/report-data";

const scan: ReportScanData = {
  attackPaths: [],
  completedAt: "2026-07-04T01:00:00.000Z",
  coverageScore: 88,
  createdAt: "2026-07-04T00:00:00.000Z",
  endpoints: [],
  finalUrl: "https://example.com/",
  findings: [
    {
      affectedUrl: "https://example.com/api/users?id=1",
      category: "Access control",
      confidence: "CONFIRMED",
      cwe: "CWE-639",
      description: "The endpoint returns records without enforcing ownership.",
      evidence: [],
      id: "finding_1",
      impact: "A user may access another user's private data.",
      issue: {
        firstSeenAt: "2026-07-04T00:00:00.000Z",
        id: "issue_1",
        lastSeenAt: "2026-07-04T00:00:00.000Z",
        occurrenceCount: 2,
        status: "CONFIRMED",
      },
      issueId: "issue_1",
      owaspCategory: "A01:2021 Broken Access Control",
      remediation: "Enforce object-level authorization on every request.",
      reproductionSteps: [],
      retestInstructions: "Confirm cross-account identifiers return 403.",
      severity: "HIGH",
      status: "OPEN",
      title: "Insecure direct object reference",
    },
  ],
  id: "scan_compliance_test",
  mode: "FULL",
  normalizedUrl: "https://example.com/",
  originalUrl: "https://example.com/",
  securityScore: 50,
  services: [],
  stages: [],
  status: "COMPLETED",
  technologies: [],
};

describe("compliance report mappings", () => {
  it("maps findings to OWASP and CWE report rows", () => {
    const owaspRows = complianceRowsForKind(scan, "owasp-top-10");
    const cweRows = complianceRowsForKind(scan, "cwe");

    expect(owaspRows).toHaveLength(10);
    expect(owaspRows.find((row) => row.control === "A01")).toMatchObject({
      findingCount: 1,
      highestSeverity: "HIGH",
      status: "Needs remediation",
    });
    expect(cweRows[0]).toMatchObject({
      control: "CWE-639",
      findingCount: 1,
      highestSeverity: "HIGH",
    });
  });

  it("builds remediation lifecycle rows with issue status and retest scope", () => {
    expect(remediationTrackingRows(scan)[0]).toMatchObject({
      issueId: "issue_1",
      priority: "Immediate",
      retestScope: "Confirm cross-account identifiers return 403.",
      status: "CONFIRMED",
    });
  });
});
