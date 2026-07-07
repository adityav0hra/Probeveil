import type { ReportScanData } from "./report-data";
import type { SecurityReportKind } from "./report-types";

type Finding = ReportScanData["findings"][number];

export type ComplianceReportKind = Exclude<
  SecurityReportKind,
  "executive" | "technical"
>;

export type ComplianceRow = {
  framework: string;
  control: string;
  title: string;
  status: string;
  findingCount: number;
  highestSeverity: string;
  evidence: string;
  remediation: string;
};

export type RemediationTrackingRow = {
  priority: string;
  issueId: string;
  status: string;
  severity: string;
  title: string;
  affectedLocation: string;
  ownerAction: string;
  retestScope: string;
};

const severityRank: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

const owaspControls = [
  {
    key: "A01",
    title: "Broken Access Control",
    match:
      /A01|access control|idor|authorization|privilege|admin|tenant|ownership/i,
    remediation:
      "Enforce server-side authorization on every object, route and state-changing action.",
  },
  {
    key: "A02",
    title: "Cryptographic Failures",
    match: /A02|crypto|cryptographic|tls|ssl|cookie|secret|token|password/i,
    remediation:
      "Harden TLS, protect secrets and enforce secure session and cookie handling.",
  },
  {
    key: "A03",
    title: "Injection",
    match: /A03|injection|xss|sql|command|template|ldap|nosql|script/i,
    remediation:
      "Validate inputs, parameterize queries and encode untrusted output by context.",
  },
  {
    key: "A04",
    title: "Insecure Design",
    match: /A04|business logic|workflow|design|abuse|rate limit|state/i,
    remediation:
      "Add threat-model review for sensitive workflows and enforce explicit abuse controls.",
  },
  {
    key: "A05",
    title: "Security Misconfiguration",
    match: /A05|misconfiguration|header|cors|csp|exposed|debug|directory/i,
    remediation:
      "Apply secure defaults, remove exposed debug surfaces and validate headers continuously.",
  },
  {
    key: "A06",
    title: "Vulnerable and Outdated Components",
    match: /A06|component|dependency|outdated|version|library|package|cve/i,
    remediation:
      "Patch vulnerable components and maintain inventory-driven dependency review.",
  },
  {
    key: "A07",
    title: "Identification and Authentication Failures",
    match: /A07|authentication|login|session|mfa|credential|reset/i,
    remediation:
      "Strengthen authentication, session expiry, credential recovery and brute-force controls.",
  },
  {
    key: "A08",
    title: "Software and Data Integrity Failures",
    match: /A08|integrity|supply chain|ci\/cd|unsigned|deserialization/i,
    remediation:
      "Verify build, deployment and update integrity with signed, reviewed release paths.",
  },
  {
    key: "A09",
    title: "Security Logging and Monitoring Failures",
    match: /A09|logging|monitoring|audit|alert|detection/i,
    remediation:
      "Log security-relevant activity, alert on high-risk events and preserve evidence trails.",
  },
  {
    key: "A10",
    title: "Server-Side Request Forgery",
    match: /A10|ssrf|server-side request|url fetch|webhook|redirect/i,
    remediation:
      "Restrict server-side fetch targets with allowlists, network egress controls and URL validation.",
  },
] as const;

const pciStyleControls = [
  {
    control: "PCI-WEB-01",
    title: "Encrypted transport and secure cookies",
    match: /tls|ssl|https|cookie|secure|hsts|cryptographic|crypto/i,
    evidence: "TLS, header and cookie observations from the scan.",
    remediation:
      "Enforce HTTPS, modern TLS settings, secure cookies and strict transport controls.",
  },
  {
    control: "PCI-WEB-02",
    title: "Authentication and session control",
    match: /authentication|login|session|credential|mfa|password/i,
    evidence: "Login, session and credential-handling findings.",
    remediation:
      "Harden authentication, session lifecycle, account recovery and brute-force protections.",
  },
  {
    control: "PCI-WEB-03",
    title: "Access control for cardholder-like data paths",
    match:
      /access control|idor|authorization|privilege|tenant|ownership|admin/i,
    evidence: "Authorization and cross-account access-control findings.",
    remediation:
      "Enforce least privilege and object-level authorization on sensitive records and exports.",
  },
  {
    control: "PCI-WEB-04",
    title: "Secure configuration and exposed surface",
    match:
      /misconfiguration|header|cors|csp|debug|exposed|directory|admin route/i,
    evidence: "Configuration, header and exposed route observations.",
    remediation:
      "Remove unnecessary exposure and apply secure application and web-server defaults.",
  },
  {
    control: "PCI-WEB-05",
    title: "Application vulnerability management",
    match: /injection|xss|component|dependency|cve|vulnerab|scanner|finding/i,
    evidence: "Confirmed and review-needed application findings.",
    remediation:
      "Prioritize high-risk remediation, document accepted risk and complete targeted retests.",
  },
  {
    control: "PCI-WEB-06",
    title: "Security logging and retained evidence",
    match: /logging|monitoring|audit|evidence|alert/i,
    evidence: "Audit, evidence and notification records created by Probeveil.",
    remediation:
      "Retain request/response evidence, scanner logs and notification outcomes for review.",
  },
] as const;

const soc2Controls = [
  {
    control: "CC6",
    title: "Logical access controls",
    match:
      /access control|idor|authorization|authentication|session|privilege|admin/i,
    evidence: "Role, session and object-access findings.",
    remediation:
      "Track access-control remediation through owner notes, status changes and retest evidence.",
  },
  {
    control: "CC7",
    title: "System operations and vulnerability monitoring",
    match: /vulnerab|scanner|monitoring|alert|finding|evasion|crawl|coverage/i,
    evidence:
      "Scan coverage, scanner stages, findings, evasion signals and notifications.",
    remediation:
      "Use scheduled scans, high-severity alerts and new-finding diffs for continuous monitoring.",
  },
  {
    control: "CC8",
    title: "Change management evidence",
    match: /component|dependency|technology|asset|route|api|version|changed/i,
    evidence: "Technology, route, API and asset inventory changes.",
    remediation:
      "Review changed assets and dependency signals during release and patch cycles.",
  },
  {
    control: "CC9",
    title: "Risk mitigation and vendor-facing exposure",
    match: /external|third-party|service|domain|tls|cors|webhook|ssrf/i,
    evidence: "External domains, services, APIs and exposure findings.",
    remediation:
      "Classify exposed assets, document risk treatment and retest remediated high-risk paths.",
  },
] as const;

export function isComplianceReportKind(
  kind: SecurityReportKind,
): kind is ComplianceReportKind {
  return !["executive", "technical"].includes(kind);
}

export function complianceRowsForKind(
  scan: ReportScanData,
  kind: SecurityReportKind,
) {
  if (kind === "owasp-top-10") return owaspTop10Rows(scan);
  if (kind === "cwe") return cweRows(scan);
  if (kind === "pci-web-controls") return pciStyleRows(scan);
  if (kind === "soc2-evidence") return soc2EvidenceRows(scan);
  if (kind === "executive-risk") return executiveRiskRows(scan);
  if (kind === "remediation-tracking") return remediationControlRows(scan);
  return [];
}

export function owaspTop10Rows(scan: ReportScanData): ComplianceRow[] {
  return owaspControls.map((control) => {
    const findings = scan.findings.filter((finding) =>
      control.match.test(findingText(finding)),
    );
    return controlRow({
      framework: "OWASP Top 10 2021",
      control: control.key,
      title: control.title,
      findings,
      evidence: evidenceSummary(findings, "No automated findings mapped."),
      remediation: control.remediation,
    });
  });
}

export function cweRows(scan: ReportScanData): ComplianceRow[] {
  const grouped = new Map<string, Finding[]>();
  scan.findings.forEach((finding) => {
    const key = finding.cwe?.trim() || "CWE-Unclassified";
    grouped.set(key, [...(grouped.get(key) ?? []), finding]);
  });

  if (!grouped.size) {
    return [
      {
        framework: "CWE",
        control: "CWE",
        title: "No CWE-mapped findings",
        status: "No automated findings",
        findingCount: 0,
        highestSeverity: "-",
        evidence: "The scan did not record CWE-linked vulnerabilities.",
        remediation: "Maintain periodic scanning and classify future findings.",
      },
    ];
  }

  return [...grouped.entries()]
    .sort((a, b) => severitySort(highestSeverity(a[1]), highestSeverity(b[1])))
    .map(([cwe, findings]) =>
      controlRow({
        framework: "CWE",
        control: cwe,
        title: topCategories(findings),
        findings,
        evidence: evidenceSummary(
          findings,
          "Mapped findings without URL data.",
        ),
        remediation: topRemediation(findings),
      }),
    );
}

export function pciStyleRows(scan: ReportScanData): ComplianceRow[] {
  return pciStyleControls.map((control) => {
    const findings = scan.findings.filter((finding) =>
      control.match.test(findingText(finding)),
    );
    return controlRow({
      framework: "PCI-style web controls",
      control: control.control,
      title: control.title,
      findings,
      evidence: findings.length
        ? evidenceSummary(findings, control.evidence)
        : control.evidence,
      remediation: control.remediation,
    });
  });
}

export function soc2EvidenceRows(scan: ReportScanData): ComplianceRow[] {
  return soc2Controls.map((control) => {
    const findings = scan.findings.filter((finding) =>
      control.match.test(findingText(finding)),
    );
    return controlRow({
      framework: "SOC 2 evidence support",
      control: control.control,
      title: control.title,
      findings,
      evidence: findings.length
        ? evidenceSummary(findings, control.evidence)
        : control.evidence,
      remediation: control.remediation,
    });
  });
}

export function executiveRiskRows(scan: ReportScanData): ComplianceRow[] {
  const criticalHigh = scan.findings.filter((finding) =>
    ["CRITICAL", "HIGH"].includes(finding.severity),
  );
  const manualReview = scan.findings.filter(
    (finding) => finding.confidence === "MANUAL_REVIEW",
  );
  const recurringIssues = scan.findings.filter(
    (finding) => (finding.issue?.occurrenceCount ?? 0) > 1,
  );
  const evasionSignals = scan.findings.filter(
    (finding) =>
      finding.category === "Evasion signal" ||
      finding.scannerRuleId?.startsWith("evasion/"),
  );

  return [
    riskRow("RISK-01", "Material exploitable vulnerabilities", criticalHigh),
    riskRow("RISK-02", "Items requiring manual decision", manualReview),
    riskRow("RISK-03", "Recurring issue history", recurringIssues),
    riskRow("RISK-04", "Coverage and evasion uncertainty", evasionSignals),
  ];
}

export function remediationTrackingRows(
  scan: ReportScanData,
): RemediationTrackingRow[] {
  const rows = sortFindings(scan.findings).map((finding) => ({
    priority: priorityFor(finding.severity),
    issueId: finding.issueId ?? finding.id,
    status: finding.issue?.status ?? finding.status,
    severity: finding.severity,
    title: finding.title,
    affectedLocation: finding.affectedUrl ?? "Not captured",
    ownerAction: finding.remediation,
    retestScope:
      finding.retestInstructions ??
      "Rerun a targeted retest against the affected route and evidence condition.",
  }));

  return rows.length
    ? rows
    : [
        {
          priority: "Monitor",
          issueId: "-",
          status: "No automated findings",
          severity: "-",
          title: "No remediation items recorded",
          affectedLocation: "-",
          ownerAction: "Maintain scheduled scans and evidence retention.",
          retestScope: "Next scheduled scan.",
        },
      ];
}

function remediationControlRows(scan: ReportScanData): ComplianceRow[] {
  const rows = remediationTrackingRows(scan);
  const grouped = new Map<string, RemediationTrackingRow[]>();
  rows.forEach((row) => {
    grouped.set(row.status, [...(grouped.get(row.status) ?? []), row]);
  });
  return [...grouped.entries()].map(([status, items]) => ({
    framework: "Remediation tracking",
    control: status,
    title: `${items.length} item${items.length === 1 ? "" : "s"} in ${status}`,
    status,
    findingCount: items.length,
    highestSeverity: highestSeverityFromValues(
      items.map((item) => item.severity),
    ),
    evidence: items
      .map((item) => `${item.issueId}: ${item.affectedLocation}`)
      .slice(0, 3)
      .join("; "),
    remediation:
      "Assign owner action, update status notes and complete targeted retest.",
  }));
}

function controlRow({
  framework,
  control,
  title,
  findings,
  evidence,
  remediation,
}: {
  framework: string;
  control: string;
  title: string;
  findings: Finding[];
  evidence: string;
  remediation: string;
}): ComplianceRow {
  const severity = highestSeverity(findings);
  return {
    framework,
    control,
    title,
    status: controlStatus(findings, severity),
    findingCount: findings.length,
    highestSeverity: severity,
    evidence,
    remediation,
  };
}

function riskRow(control: string, title: string, findings: Finding[]) {
  return controlRow({
    framework: "Executive risk summary",
    control,
    title,
    findings,
    evidence: evidenceSummary(findings, "No active automated evidence."),
    remediation:
      findings.length > 0
        ? "Review ownership, remediation due date, accepted-risk rationale and retest status."
        : "Maintain monitoring and revisit if new evidence appears.",
  });
}

function controlStatus(findings: Finding[], severity: string) {
  if (!findings.length) return "No automated findings";
  if (["CRITICAL", "HIGH"].includes(severity)) return "Needs remediation";
  if (severity === "MEDIUM") return "Needs review";
  return "Monitor";
}

function evidenceSummary(findings: Finding[], fallback: string) {
  const locations = [
    ...new Set(findings.map((finding) => finding.affectedUrl).filter(Boolean)),
  ];
  if (locations.length) return locations.slice(0, 3).join(", ");
  const titles = findings.map((finding) => finding.title).filter(Boolean);
  return titles.length ? titles.slice(0, 3).join(", ") : fallback;
}

function topCategories(findings: Finding[]) {
  const counts = new Map<string, number>();
  findings.forEach((finding) =>
    counts.set(finding.category, (counts.get(finding.category) ?? 0) + 1),
  );
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([category]) => category)
    .slice(0, 3)
    .join(", ");
}

function topRemediation(findings: Finding[]) {
  return (
    sortFindings(findings)[0]?.remediation ??
    "Classify and remediate the recorded weakness."
  );
}

function findingText(finding: Finding) {
  return [
    finding.owaspCategory,
    finding.cwe,
    finding.category,
    finding.title,
    finding.description,
    finding.impact,
    finding.remediation,
    finding.scannerRuleId,
    finding.affectedUrl,
    finding.component,
    finding.parameter,
  ]
    .filter(Boolean)
    .join(" ");
}

function highestSeverity(findings: Finding[]) {
  return highestSeverityFromValues(findings.map((finding) => finding.severity));
}

function highestSeverityFromValues(values: string[]) {
  const severity = values.filter(Boolean).sort((a, b) => severitySort(a, b))[0];
  return severity ?? "-";
}

function severitySort(a: string, b: string) {
  return (severityRank[a] ?? 9) - (severityRank[b] ?? 9);
}

function sortFindings(findings: Finding[]) {
  return [...findings].sort((a, b) => severitySort(a.severity, b.severity));
}

function priorityFor(severity: string) {
  if (["CRITICAL", "HIGH"].includes(severity)) return "Immediate";
  if (severity === "MEDIUM") return "Short term";
  if (severity === "LOW") return "Medium term";
  return "Monitor";
}
