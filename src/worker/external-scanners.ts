import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { FindingInput, ScanJob } from "./types";

const run = promisify(execFile);
const NUCLEI_TIMEOUT_MS = Number(process.env.NUCLEI_TIMEOUT_MS ?? 0);

type EndpointLike = {
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
  if (await commandExists("nuclei")) {
    findings.push(
      ...(await runNuclei(selectNucleiTargets(job, endpoints), cancelled, job)),
    );
  }
  if (await commandExists("nikto"))
    findings.push(...(await runNikto(job.url, cancelled, job)));
  if (await commandExists("testssl.sh"))
    findings.push(...(await runTestSsl(job.url, cancelled, job)));
  if (await commandExists("zap-baseline.py"))
    findings.push(...(await runZapBaseline(job.url, cancelled, job)));
  return findings;
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
      const { stdout } = await run(
        "nuclei",
        ["-u", target, ...args],
        {
          maxBuffer: 16 * 1024 * 1024,
          timeout:
            NUCLEI_TIMEOUT_MS ||
            (job.mode === "MAXIMUM" ? 300_000 : 120_000),
        },
      );
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
  target: string,
  cancelled: () => Promise<boolean>,
  job: ScanJob,
) {
  if (await cancelled()) throw new Error("Scan cancelled");
  return runTextScanner({
    args: ["--warnings", "batch", "--fast", target],
    command: "testssl.sh",
    rule: "external/testssl-diagnostics",
    scannerName: "testssl.sh",
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
        references: ["https://owasp.org/www-project-web-security-testing-guide/"],
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
  const limit =
    configured > 0 ? configured : job.mode === "MAXIMUM" ? 250 : 80;
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
