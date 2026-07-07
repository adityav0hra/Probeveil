import { describe, expect, it } from "vitest";
import { buildRemediationAssistant } from "@/lib/remediation-assistant";

const baseFinding = {
  affectedUrl: "https://example.com/admin/users/123",
  category: "Role comparison",
  component: null,
  confidence: "HIGH",
  cwe: "CWE-862",
  description: "A normal user can request another account's admin data.",
  httpMethod: "GET",
  impact: "Cross-account data exposure is possible.",
  owaspCategory: "A01 Broken Access Control",
  parameter: "userId",
  remediation:
    "Validate ownership and role privileges before returning account data.",
  reproductionSteps: ["Log in as user A.", "Request user B's record."],
  retestInstructions:
    "Repeat the request after deploying the authorization fix.",
  scannerName: "Probeveil",
  scannerRuleId: "role-comparison/cross-account-leakage",
  severity: "HIGH",
  sourceFile: null,
  lineNumber: null,
  title: "Cross-account user data exposure",
};

describe("remediation assistant", () => {
  it("generates access-control fix guidance from finding context", () => {
    const assistant = buildRemediationAssistant(baseFinding, {
      finalUrl: null,
      mode: "FULL",
      normalizedUrl: "https://example.com",
    });

    expect(assistant.affectedCodePattern).toContain("GET https://example.com");
    expect(assistant.affectedCodePattern).toContain("userId");
    expect(assistant.fixGuidance.join(" ")).toContain(
      "server-side authorization",
    );
  });

  it("builds a developer ticket with verification steps", () => {
    const assistant = buildRemediationAssistant(baseFinding, {
      finalUrl: null,
      mode: "FULL",
      normalizedUrl: "https://example.com",
    });

    expect(assistant.developerTicket).toContain(
      "# Cross-account user data exposure",
    );
    expect(assistant.developerTicket).toContain("## Verification Steps");
    expect(assistant.verificationSteps).toContain("Log in as user A.");
    expect(assistant.verificationSteps.at(-1)).toContain("same route");
  });
});
