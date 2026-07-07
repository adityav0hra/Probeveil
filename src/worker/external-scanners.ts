import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { isSameOriginOrSubdomain } from "@/lib/url";
import type { FindingInput, ScanJob } from "./types";

const run = promisify(execFile);
const NUCLEI_TIMEOUT_MS = Number(process.env.NUCLEI_TIMEOUT_MS ?? 0);

type EndpointLike = {
  contentType?: string;
  discoveredBy?: string;
  url: string;
  tested: boolean;
  statusCode?: number;
};

type NucleiJson = {
  "template-id"?: string;
  "template-url"?: string;
  "matched-at"?: string;
  host?: string;
  info?: {
    name?: string;
    severity?: string;
    description?: string;
    remediation?: string;
    reference?: string | string[];
    classification?: {
      "cwe-id"?: string | string[];
    };
  };
};

type SemgrepJson = {
  results?: Array<{
    check_id?: string;
    path?: string;
    start?: { line?: number };
    extra?: {
      message?: string;
      severity?: string;
      metadata?: Record<string, unknown>;
    };
  }>;
};

export async function runExternalScanners({
  cancelled,
  endpoints,
  job,
}: {
  cancelled: () => Promise<boolean>;
  endpoints: EndpointLike[];
  job: ScanJob;
}) {
  if (job.mode === "QUICK") return [];
  const enabled = process.env.PROBEVEIL_EXTERNAL_SCANNERS ?? "auto";
  if (enabled === "off" || enabled === "false" || enabled === "0") return [];

  const findings: FindingInput[] = [];
  const availability: Array<{ engine: string; installed: boolean }> = [];
  if (await commandExists("nuclei")) {
    availability.push({ engine: "Nuclei", installed: true });
    findings.push(
      ...(await runNuclei(selectNucleiTargets(job, endpoints), cancelled, job)),
    );
  } else availability.push({ engine: "Nuclei", installed: false });

  if (await commandExists("nikto")) {
    availability.push({ engine: "Nikto", installed: true });
    findings.push(...(await runNikto(job.url, cancelled, job)));
  } else {
    availability.push({ engine: "Nikto", installed: false });
    findings.push(...builtinNiktoStyleChecks(job, endpoints));
  }

  const testSslCommand = await firstExistingCommand(["testssl.sh", "testssl"]);
  if (testSslCommand) {
    availability.push({ engine: "testssl.sh", installed: true });
    findings.push(
      ...(await runTestSsl(testSslCommand, job.url, cancelled, job)),
    );
  } else availability.push({ engine: "testssl.sh", installed: false });

  if (await commandExists("sslyze")) {
    availability.push({ engine: "SSLyze", installed: true });
    findings.push(...(await runSslYze(job.url, cancelled, job)));
  } else availability.push({ engine: "SSLyze", installed: false });

  if (await commandExists("zap-baseline.py")) {
    availability.push({ engine: "OWASP ZAP Baseline", installed: true });
    findings.push(...(await runZapBaseline(job.url, cancelled, job)));
  } else availability.push({ engine: "OWASP ZAP Baseline", installed: false });

  if (await commandExists("semgrep")) {
    availability.push({ engine: "Semgrep", installed: true });
    findings.push(...(await runSemgrepJsHints(job, endpoints, cancelled)));
  } else availability.push({ engine: "Semgrep", installed: false });

  findings.push(...technologySpecificChecks(job, endpoints));
  findings.push(scannerAvailabilityFinding(job.url, availability));
  return dedupeFindings(findings).slice(0, 700);
}

export function parseNucleiJsonLines(value: string): FindingInput[] {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .flatMap((line) => {
      try {
        return [nucleiFinding(JSON.parse(line) as NucleiJson)];
      } catch {
        return [];
      }
    });
}

async function runNuclei(
  targets: string[],
  cancelled: () => Promise<boolean>,
  job: ScanJob,
): Promise<FindingInput[]> {
  const findings: FindingInput[] = [];
  const tags = (process.env.NUCLEI_TAGS ?? "")
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean);
  const args = [
    "-jsonl",
    "-silent",
    "-no-color",
    "-duc",
    "-severity",
    "info,low,medium,high,critical",
    "-exclude-tags",
    "dos,fuzz,brute-force,creds-stuffing",
    "-timeout",
    job.mode === "MAXIMUM" ? "12" : "8",
    "-retries",
    job.mode === "MAXIMUM" ? "2" : "1",
    "-rl",
    process.env.NUCLEI_RATE_LIMIT ?? (job.mode === "MAXIMUM" ? "8" : "5"),
  ];
  if (tags.length) args.push("-tags", tags.join(","));
  for (const target of targets) {
    if (await cancelled()) throw new Error("Scan cancelled");
    try {
      const { stdout } = await run("nuclei", ["-u", target, ...args], {
        maxBuffer: 16 * 1024 * 1024,
        timeout:
          NUCLEI_TIMEOUT_MS || (job.mode === "MAXIMUM" ? 300_000 : 120_000),
      });
      findings.push(...parseNucleiJsonLines(stdout));
    } catch (error) {
      console.warn(
        JSON.stringify({
          error: error instanceof Error ? error.message : String(error),
          scanner: "nuclei",
          target,
        }),
      );
    }
  }
  return dedupeFindings(findings).slice(0, 500);
}

async function commandExists(command: string) {
  try {
    await run("sh", ["-lc", `command -v ${command}`], { timeout: 3000 });
    return true;
  } catch {
    return false;
  }
}

async function firstExistingCommand(commands: string[]) {
  for (const command of commands)
    if (await commandExists(command)) return command;
  return undefined;
}

async function runNikto(
  target: string,
  cancelled: () => Promise<boolean>,
  job: ScanJob,
) {
  if (job.mode === "QUICK") return [];
  if (await cancelled()) throw new Error("Scan cancelled");
  return runTextScanner({
    args: ["-h", target, "-nointeractive", "-Tuning", "x"],
    command: "nikto",
    rule: "external/nikto-diagnostics",
    scannerName: "Nikto",
    target,
    timeout: job.mode === "MAXIMUM" ? 180_000 : 90_000,
  });
}

async function runTestSsl(
  command: string,
  target: string,
  cancelled: () => Promise<boolean>,
  job: ScanJob,
) {
  if (await cancelled()) throw new Error("Scan cancelled");
  return runTextScanner({
    args: ["--warnings", "batch", "--fast", target],
    command,
    rule: "external/testssl-diagnostics",
    scannerName: "testssl.sh",
    target,
    timeout: job.mode === "MAXIMUM" ? 180_000 : 90_000,
  });
}

async function runSslYze(
  target: string,
  cancelled: () => Promise<boolean>,
  job: ScanJob,
) {
  if (await cancelled()) throw new Error("Scan cancelled");
  const endpoint = tlsTarget(target);
  if (!endpoint) return [];
  return runTextScanner({
    args: ["--regular", endpoint],
    command: "sslyze",
    rule: "external/sslyze-diagnostics",
    scannerName: "SSLyze",
    target,
    timeout: job.mode === "MAXIMUM" ? 180_000 : 90_000,
  });
}

async function runZapBaseline(
  target: string,
  cancelled: () => Promise<boolean>,
  job: ScanJob,
) {
  if (job.mode !== "MAXIMUM") return [];
  if (await cancelled()) throw new Error("Scan cancelled");
  return runTextScanner({
    args: ["-t", target, "-J", "-", "-I"],
    command: "zap-baseline.py",
    rule: "external/zap-baseline-diagnostics",
    scannerName: "OWASP ZAP Baseline",
    target,
    timeout: 240_000,
  });
}

async function runSemgrepJsHints(
  job: ScanJob,
  endpoints: EndpointLike[],
  cancelled: () => Promise<boolean>,
) {
  const targets = selectJavaScriptTargets(job, endpoints);
  if (!targets.length) return [];
  const dir = await mkdtemp(join(tmpdir(), "probeveil-semgrep-"));
  const mapping = new Map<string, string>();
  try {
    const configPath = join(dir, "probeveil-js-rules.yml");
    await writeFile(configPath, semgrepJavaScriptConfig());
    for (const [index, target] of targets.entries()) {
      if (await cancelled()) throw new Error("Scan cancelled");
      try {
        const response = await fetch(target, {
          headers: { "user-agent": "Probeveil/1.0 semgrep-js-hints" },
          signal: AbortSignal.timeout(12_000),
        });
        if (!response.ok) continue;
        const body = await response.text();
        if (!body || body.length > 1_500_000) continue;
        const path = join(dir, `source-${index}.js`);
        await writeFile(path, body);
        mapping.set(path, target);
      } catch {}
    }
    if (!mapping.size) return [];
    const { stdout } = await run(
      "semgrep",
      ["--config", configPath, "--json", "--quiet", dir],
      { maxBuffer: 16 * 1024 * 1024, timeout: 120_000 },
    );
    return parseSemgrepJson(stdout, mapping);
  } catch (error) {
    console.warn(
      JSON.stringify({
        error: error instanceof Error ? error.message : String(error),
        scanner: "semgrep-js-hints",
      }),
    );
    return [];
  } finally {
    await rm(dir, { force: true, recursive: true }).catch(() => undefined);
  }
}

export function parseSemgrepJson(
  value: string,
  pathToUrl = new Map<string, string>(),
): FindingInput[] {
  let parsed: SemgrepJson;
  try {
    parsed = JSON.parse(value) as SemgrepJson;
  } catch {
    return [];
  }
  return (parsed.results ?? []).map((result) => {
    const rule = result.check_id ?? "semgrep-js-hint";
    const affectedUrl =
      pathToUrl.get(result.path ?? "") ?? result.path ?? "unknown";
    const severity = semgrepSeverity(result.extra?.severity);
    const title = result.extra?.message ?? rule;
    return {
      affectedUrl,
      category: "External scanner",
      confidence: "MANUAL_REVIEW",
      cwe: "CWE-79",
      description:
        "Semgrep found a client-side JavaScript pattern that should be reviewed in context.",
      evidence: [
        {
          content: JSON.stringify(result, null, 2),
          title: "Semgrep JavaScript/source hint",
          type: "SEMGREP_JS_HINT",
        },
      ],
      fingerprint: createHash("sha256")
        .update(`semgrep|${rule}|${affectedUrl}|${result.start?.line ?? 0}`)
        .digest("hex"),
      httpMethod: "GET",
      impact:
        "Client-side source hints can reveal DOM injection sinks, unsafe dynamic code execution, hard-coded endpoints, secret-like identifiers or logic that deserves server-side validation review.",
      remediation:
        "Review the source location, replace unsafe sinks with safe DOM APIs, avoid dynamic code execution and move sensitive decisions or secrets server-side.",
      references: ["https://semgrep.dev/docs/"],
      reproductionSteps: [
        `Download the JavaScript asset ${affectedUrl}.`,
        "Run Semgrep with Probeveil's JavaScript hint rules.",
        "Review the flagged line and confirm whether the risky pattern is reachable with attacker-controlled data.",
      ],
      scannerName: "Semgrep",
      scannerRuleId: rule,
      scannerVersion: "external-cli",
      severity,
      title,
    };
  });
}

export function selectJavaScriptTargets(
  job: ScanJob,
  endpoints: EndpointLike[],
) {
  const root = new URL(job.url);
  const limit = job.mode === "MAXIMUM" ? 20 : 8;
  return [
    ...new Set(
      endpoints
        .filter((endpoint) => {
          try {
            const url = new URL(endpoint.url);
            return (
              isSameOriginOrSubdomain(url, root) &&
              (/\.(?:m?js)(?:$|\?)/i.test(url.pathname) ||
                /javascript|ecmascript/i.test(endpoint.contentType ?? "") ||
                endpoint.discoveredBy?.includes("script"))
            );
          } catch {
            return false;
          }
        })
        .map((endpoint) => endpoint.url),
    ),
  ].slice(0, limit);
}

function builtinNiktoStyleChecks(
  job: ScanJob,
  endpoints: EndpointLike[],
): FindingInput[] {
  if (job.mode === "QUICK") return [];
  const interesting = endpoints
    .filter(
      (endpoint) =>
        endpoint.tested && endpoint.statusCode && endpoint.statusCode < 400,
    )
    .filter((endpoint) =>
      /\/(?:server-status|phpinfo\.php|info\.php|cgi-bin\/|admin|backup|\.git|\.svn|wp-admin|xmlrpc\.php|manager\/html)(?:\/|$|\?)/i.test(
        endpoint.url,
      ),
    )
    .slice(0, 25);
  if (!interesting.length) return [];
  return [
    externalReviewFinding({
      affectedUrl: job.url,
      content: interesting
        .map((endpoint) => `${endpoint.statusCode} ${endpoint.url}`)
        .join("\n"),
      rule: "external/builtin-nikto-style-web-checks",
      scannerName: "Probeveil Nikto-style Checks",
      severity: "LOW",
      title: "Nikto-style web server surfaces need review",
      detail:
        "Probeveil observed reachable administrative, diagnostic, legacy or sensitive-path surfaces commonly checked by Nikto-style scanners.",
    }),
  ];
}

function technologySpecificChecks(
  job: ScanJob,
  endpoints: EndpointLike[],
): FindingInput[] {
  const findings: FindingInput[] = [];
  const urls = endpoints.map((endpoint) => endpoint.url);
  const groups: Array<{
    matcher: RegExp;
    name: string;
    rule: string;
    detail: string;
  }> = [
    {
      matcher: /\/_next\/|\/api\/auth\/(?:session|csrf|providers)/i,
      name: "Next.js",
      rule: "external/technology-nextjs-surface",
      detail:
        "Next.js routes or assets were discovered. Review middleware/proxy authorization, server actions, API route auth, cache boundaries and exposed build/data routes.",
    },
    {
      matcher: /\/wp-json\/|\/wp-admin\/|\/xmlrpc\.php|wp-content/i,
      name: "WordPress",
      rule: "external/technology-wordpress-surface",
      detail:
        "WordPress routes were discovered. Review plugin/theme exposure, XML-RPC, REST permissions, user enumeration and admin hardening.",
    },
    {
      matcher: /\/actuator\/|\/swagger|\/v3\/api-docs/i,
      name: "Spring/OpenAPI",
      rule: "external/technology-spring-openapi-surface",
      detail:
        "Spring/OpenAPI-style routes were discovered. Review actuator exposure, management endpoint auth and public schema contents.",
    },
    {
      matcher: /\/graphql(?:\/|$|\?)/i,
      name: "GraphQL",
      rule: "external/technology-graphql-surface",
      detail:
        "GraphQL endpoints were discovered. Review introspection, batching, resolver authorization, query complexity and object ownership.",
    },
  ];
  for (const group of groups) {
    const matches = urls.filter((url) => group.matcher.test(url)).slice(0, 20);
    if (!matches.length) continue;
    findings.push(
      externalReviewFinding({
        affectedUrl: job.url,
        content: matches.join("\n"),
        rule: group.rule,
        scannerName: "Probeveil Technology Checks",
        severity: "INFO",
        title: `${group.name} technology-specific checks were prioritized`,
        detail: group.detail,
      }),
    );
  }
  return findings;
}

function externalReviewFinding({
  affectedUrl,
  content,
  detail,
  rule,
  scannerName,
  severity,
  title,
}: {
  affectedUrl: string;
  content: string;
  detail: string;
  rule: string;
  scannerName: string;
  severity: FindingInput["severity"];
  title: string;
}): FindingInput {
  return {
    affectedUrl,
    category: "External scanner",
    confidence: "MANUAL_REVIEW",
    cwe: "CWE-693",
    description: detail,
    evidence: [{ content, title, type: "EXTERNAL_REVIEW" }],
    fingerprint: createHash("sha256")
      .update(`${rule}|${affectedUrl}|${content}`)
      .digest("hex"),
    httpMethod: "GET",
    impact:
      "Technology-specific and baseline scanner signals help prioritize configuration, framework and route-hardening review beyond generic crawling.",
    remediation:
      "Validate the listed routes against the deployed stack, apply framework-specific hardening and rerun Probeveil.",
    references: ["https://owasp.org/www-project-web-security-testing-guide/"],
    reproductionSteps: [
      "Review the listed routes and technologies in the scan output.",
      "Run the named external scanner or equivalent manual checks from an approved testing environment.",
      "Confirm whether each signal is expected, authenticated, hardened and logged.",
    ],
    scannerName,
    scannerRuleId: rule,
    scannerVersion: "1.0.0",
    severity,
    title,
  };
}

function scannerAvailabilityFinding(
  affectedUrl: string,
  availability: Array<{ engine: string; installed: boolean }>,
): FindingInput {
  const installed = availability
    .filter((item) => item.installed)
    .map((item) => item.engine);
  const missing = availability
    .filter((item) => !item.installed)
    .map((item) => item.engine);
  return {
    affectedUrl,
    category: "External scanner coverage",
    confidence: "INFORMATIONAL",
    cwe: "CWE-693",
    description:
      "Probeveil checked optional external scanner engine availability for this scan.",
    evidence: [
      {
        content: [
          `installed=${installed.join(", ") || "none"}`,
          `missing=${missing.join(", ") || "none"}`,
          "Missing engines are optional. Install them on the worker host to expand coverage.",
        ].join("\n"),
        title: "External scanner availability",
        type: "SCANNER_AVAILABILITY",
      },
    ],
    fingerprint: createHash("sha256")
      .update(
        `external-scanner-availability|${affectedUrl}|${installed.join(",")}|${missing.join(",")}`,
      )
      .digest("hex"),
    httpMethod: "GET",
    impact:
      "Scanner availability controls whether optional DAST, TLS, template, source-hint and technology-specific engines can contribute findings.",
    remediation:
      "Install desired engines such as nuclei, zap-baseline.py, sslyze, testssl.sh, nikto and semgrep on the worker, or keep built-in Probeveil checks enabled as lightweight fallbacks.",
    references: [
      "https://owasp.org/www-project-zap/",
      "https://github.com/projectdiscovery/nuclei",
      "https://semgrep.dev/",
    ],
    reproductionSteps: [
      "Open scanner configuration.",
      "Check which optional scanner engines are installed on the worker host.",
      "Install missing engines and rerun the scan if additional coverage is required.",
    ],
    scannerName: "Probeveil Scanner Orchestrator",
    scannerRuleId: "external/scanner-engine-availability",
    scannerVersion: "1.0.0",
    severity: "INFO",
    title: "External scanner engine availability recorded",
  };
}

function tlsTarget(target: string) {
  try {
    const url = new URL(target);
    if (url.protocol !== "https:") return undefined;
    return `${url.hostname}:${url.port || 443}`;
  } catch {
    return undefined;
  }
}

function semgrepSeverity(value: string | undefined): FindingInput["severity"] {
  switch (value?.toUpperCase()) {
    case "ERROR":
      return "MEDIUM";
    case "WARNING":
      return "LOW";
    default:
      return "INFO";
  }
}

function semgrepJavaScriptConfig() {
  return [
    "rules:",
    "  - id: probeveil.javascript.eval-use",
    "    message: Dynamic JavaScript execution sink requires review.",
    "    severity: WARNING",
    "    languages: [javascript, typescript]",
    "    pattern-either:",
    "      - pattern: eval($X)",
    "      - pattern: new Function(...)",
    "      - pattern: setTimeout($X, ...)",
    "      - pattern: setInterval($X, ...)",
    "  - id: probeveil.javascript.dom-write-sink",
    "    message: DOM write sink requires review for attacker-controlled data.",
    "    severity: WARNING",
    "    languages: [javascript, typescript]",
    "    pattern-either:",
    "      - pattern: document.write($X)",
    "      - pattern: $EL.innerHTML = $X",
    "      - pattern: $EL.insertAdjacentHTML($POS, $X)",
    "  - id: probeveil.javascript.client-secret-shape",
    "    message: Secret-like client-side identifier requires review.",
    "    severity: INFO",
    "    languages: [javascript, typescript]",
    "    patterns:",
    '      - pattern-regex: "(?i)(api[_-]?key|secret|token|client[_-]?secret)"',
  ].join("\n");
}

async function runTextScanner({
  args,
  command,
  rule,
  scannerName,
  target,
  timeout,
}: {
  args: string[];
  command: string;
  rule: string;
  scannerName: string;
  target: string;
  timeout: number;
}): Promise<FindingInput[]> {
  try {
    const { stdout, stderr } = await run(command, args, {
      maxBuffer: 16 * 1024 * 1024,
      timeout,
    });
    const output = [stdout, stderr].filter(Boolean).join("\n").trim();
    if (!output) return [];
    const severity = /critical/i.test(output)
      ? "CRITICAL"
      : /\bhigh\b/i.test(output)
        ? "HIGH"
        : /\bmedium\b|warning/i.test(output)
          ? "MEDIUM"
          : "INFO";
    return [
      {
        affectedUrl: target,
        category: "External scanner",
        confidence: severity === "INFO" ? "INFORMATIONAL" : "PROBABLE",
        cwe: "CWE-693",
        description: `${scannerName} produced diagnostic output for ${target}.`,
        evidence: [
          {
            content: output.slice(0, 50000),
            title: `${scannerName} output`,
            type: scannerName.toUpperCase().replaceAll(" ", "_"),
          },
        ],
        fingerprint: createHash("sha256")
          .update(`${rule}|${target}|${output.slice(0, 2000)}`)
          .digest("hex"),
        httpMethod: "GET",
        impact:
          "External scanner diagnostics can reveal additional misconfiguration, TLS, header or passive web-server issues.",
        remediation:
          "Review the attached scanner output, validate each signal against the target environment, fix confirmed issues and rerun Probeveil.",
        references: [
          "https://owasp.org/www-project-web-security-testing-guide/",
        ],
        reproductionSteps: [
          `Run ${scannerName} against ${target}.`,
          "Review the normalized output in the evidence section.",
          "Confirm affected routes/components and rerun Probeveil after remediation.",
        ],
        scannerName,
        scannerRuleId: rule,
        scannerVersion: "external-cli",
        severity,
        title: `${scannerName} diagnostics were recorded`,
      },
    ];
  } catch (error) {
    console.warn(
      JSON.stringify({
        error: error instanceof Error ? error.message : String(error),
        scanner: scannerName,
        target,
      }),
    );
    return [];
  }
}

export function selectNucleiTargets(job: ScanJob, endpoints: EndpointLike[]) {
  const configured = Number(process.env.NUCLEI_TARGET_LIMIT ?? 0);
  const limit = configured > 0 ? configured : job.mode === "MAXIMUM" ? 250 : 80;
  const candidates = [
    job.url,
    ...endpoints
      .filter(
        (endpoint) =>
          endpoint.tested &&
          (!endpoint.statusCode || endpoint.statusCode < 500),
      )
      .map((endpoint) => endpoint.url),
  ];
  return [...new Set(candidates)].slice(0, limit);
}

function nucleiFinding(row: NucleiJson): FindingInput {
  const info = row.info ?? {};
  const title = info.name ?? row["template-id"] ?? "Nuclei finding";
  const affectedUrl = row["matched-at"] ?? row.host ?? "unknown";
  const scannerRuleId = row["template-id"] ?? title.toLowerCase();
  const references = referencesFor(row);
  const cwe = cweFor(row);
  const severity = severityFor(info.severity);
  return {
    affectedUrl,
    category: "External scanner",
    confidence: severity === "INFO" ? "INFORMATIONAL" : "PROBABLE",
    cwe,
    description:
      info.description ??
      `${title} was detected by the Nuclei template ${scannerRuleId}.`,
    evidence: [
      {
        content: JSON.stringify(row, null, 2),
        title: "Nuclei JSONL result",
        type: "NUCLEI",
      },
    ],
    fingerprint: createHash("sha256")
      .update(`nuclei|${scannerRuleId}|${affectedUrl}`)
      .digest("hex"),
    httpMethod: "GET",
    impact:
      info.description ??
      "The template matched a known exposure, misconfiguration or vulnerability pattern.",
    remediation:
      info.remediation ??
      "Review the matched template evidence, upgrade or reconfigure the affected component, then rerun the scan.",
    references,
    reproductionSteps: [
      `Run nuclei against ${affectedUrl}.`,
      `Review template ${scannerRuleId} and confirm whether the matched component is reachable in the deployed environment.`,
      "Apply remediation and rerun Probeveil to confirm the finding is no longer detected.",
    ],
    scannerName: "Nuclei",
    scannerRuleId,
    scannerVersion: "external-cli",
    severity,
    title,
  };
}

function severityFor(value: string | undefined): FindingInput["severity"] {
  switch (value?.toLowerCase()) {
    case "critical":
      return "CRITICAL";
    case "high":
      return "HIGH";
    case "medium":
      return "MEDIUM";
    case "low":
      return "LOW";
    default:
      return "INFO";
  }
}

function cweFor(row: NucleiJson) {
  const raw = row.info?.classification?.["cwe-id"];
  const first = Array.isArray(raw) ? raw[0] : raw;
  return first?.toUpperCase().startsWith("CWE-")
    ? first.toUpperCase()
    : undefined;
}

function referencesFor(row: NucleiJson) {
  const references = row.info?.reference;
  const list = Array.isArray(references)
    ? references
    : references
      ? [references]
      : [];
  if (row["template-url"]) list.push(row["template-url"]);
  return [...new Set(list)];
}

function dedupeFindings(findings: FindingInput[]) {
  return [
    ...new Map(
      findings.map((finding) => [finding.fingerprint, finding]),
    ).values(),
  ];
}
