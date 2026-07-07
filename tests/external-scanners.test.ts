import { describe, expect, it } from "vitest";
import {
  parseNucleiJsonLines,
  parseSemgrepJson,
  selectJavaScriptTargets,
  selectNucleiTargets,
} from "../src/worker/external-scanners";

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

  it("feeds broad endpoint coverage into full and maximum nuclei scans", () => {
    const endpoints = Array.from({ length: 120 }, (_, index) => ({
      statusCode: 200,
      tested: true,
      url: `https://example.com/route-${index}`,
    }));

    expect(
      selectNucleiTargets(
        {
          mode: "FULL",
          scanId: "scan-1",
          token: "token",
          url: "https://example.com",
        },
        endpoints,
      ),
    ).toHaveLength(80);

    expect(
      selectNucleiTargets(
        {
          mode: "MAXIMUM",
          scanId: "scan-1",
          token: "token",
          url: "https://example.com",
        },
        endpoints,
      ),
    ).toHaveLength(121);
  });

  it("maps Semgrep JSON results back to JavaScript asset URLs", () => {
    const findings = parseSemgrepJson(
      JSON.stringify({
        results: [
          {
            check_id: "probeveil.javascript.eval-use",
            extra: {
              message: "Dynamic JavaScript execution sink requires review.",
              severity: "WARNING",
            },
            path: "/tmp/source-0.js",
            start: { line: 12 },
          },
        ],
      }),
      new Map([["/tmp/source-0.js", "https://example.com/app.js"]]),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      affectedUrl: "https://example.com/app.js",
      scannerName: "Semgrep",
      scannerRuleId: "probeveil.javascript.eval-use",
      severity: "LOW",
    });
  });

  it("selects same-scope JavaScript assets for Semgrep source hints", () => {
    const targets = selectJavaScriptTargets(
      {
        mode: "FULL",
        scanId: "scan-1",
        token: "token",
        url: "https://example.com",
      },
      [
        {
          contentType: "application/javascript",
          tested: true,
          url: "https://example.com/app.js",
        },
        {
          discoveredBy: "browser-rendered:script",
          tested: true,
          url: "https://cdn.example.com/chunk",
        },
        {
          tested: true,
          url: "https://other.test/app.js",
        },
      ],
    );

    expect(targets).toEqual([
      "https://example.com/app.js",
      "https://cdn.example.com/chunk",
    ]);
  });
});
