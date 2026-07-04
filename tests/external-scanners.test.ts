import { describe, expect, it } from "vitest";
import { parseNucleiJsonLines } from "../src/worker/external-scanners";

describe("external scanner adapters", () => {
  it("converts nuclei JSONL findings into Probeveil findings", () => {
    const findings = parseNucleiJsonLines(
      JSON.stringify({
        "matched-at": "https://example.com/.git/config",
        "template-id": "exposed-git-config",
        "template-url":
          "https://github.com/projectdiscovery/nuclei-templates/http/exposures/configs/git-config.yaml",
        info: {
          classification: { "cwe-id": "CWE-200" },
          description: "Git config file exposed.",
          name: "Exposed Git Config",
          reference: ["https://cwe.mitre.org/data/definitions/200.html"],
          remediation: "Remove the exposed repository metadata.",
          severity: "high",
        },
      }),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      affectedUrl: "https://example.com/.git/config",
      category: "External scanner",
      confidence: "PROBABLE",
      cwe: "CWE-200",
      scannerName: "Nuclei",
      scannerRuleId: "exposed-git-config",
      severity: "HIGH",
      title: "Exposed Git Config",
    });
  });
});
