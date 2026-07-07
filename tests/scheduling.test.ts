import { describe, expect, it } from "vitest";
import { diffFindings, nextScheduledRun } from "@/lib/scheduling";

describe("scheduling", () => {
  it("calculates weekly and monthly next runs", () => {
    expect(
      nextScheduledRun(
        "WEEKLY",
        new Date("2026-07-07T08:00:00Z"),
      ).toISOString(),
    ).toBe("2026-07-14T08:00:00.000Z");
    expect(
      nextScheduledRun(
        "MONTHLY",
        new Date("2026-01-31T08:00:00Z"),
      ).toISOString(),
    ).toBe("2026-02-28T08:00:00.000Z");
  });

  it("diffs new and fixed findings using stable scanner identity", () => {
    const previous = [
      {
        affectedUrl: "https://example.com/admin#ignored",
        scannerRuleId: "missing-csp",
        severity: "HIGH",
        title: "Missing CSP",
      },
      {
        affectedUrl: "https://example.com/debug",
        scannerRuleId: "debug-page",
        severity: "MEDIUM",
        title: "Debug page exposed",
      },
    ];
    const current = [
      {
        affectedUrl: "https://example.com/admin",
        scannerRuleId: "missing-csp",
        severity: "HIGH",
        title: "Missing CSP",
      },
      {
        affectedUrl: "https://example.com/export",
        scannerRuleId: "csv-export",
        severity: "CRITICAL",
        title: "Sensitive export exposed",
      },
    ];

    const diff = diffFindings(current, previous);

    expect(diff.newFindings).toHaveLength(1);
    expect(diff.newFindings[0].scannerRuleId).toBe("csv-export");
    expect(diff.fixedFindings).toHaveLength(1);
    expect(diff.fixedFindings[0].scannerRuleId).toBe("debug-page");
  });
});
