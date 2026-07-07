type RemediationFinding = {
  affectedUrl?: string | null;
  category: string;
  component?: string | null;
  confidence: string;
  cwe?: string | null;
  description: string;
  httpMethod?: string | null;
  impact: string;
  owaspCategory?: string | null;
  parameter?: string | null;
  remediation: string;
  reproductionSteps: unknown;
  retestInstructions?: string | null;
  scannerName: string;
  scannerRuleId: string;
  severity: string;
  sourceFile?: string | null;
  lineNumber?: number | null;
  title: string;
};

type RemediationScan = {
  finalUrl?: string | null;
  normalizedUrl: string;
  mode: string;
};

export type RemediationAssistant = {
  affectedCodePattern: string;
  developerTicket: string;
  fixGuidance: string[];
  verificationSteps: string[];
};

export function buildRemediationAssistant(
  finding: RemediationFinding,
  scan?: RemediationScan | null,
): RemediationAssistant {
  const fixGuidance = buildFixGuidance(finding);
  const verificationSteps = buildVerificationSteps(finding);
  return {
    affectedCodePattern: buildAffectedCodePattern(finding),
    developerTicket: buildDeveloperTicketMarkdown(
      finding,
      scan,
      fixGuidance,
      verificationSteps,
    ),
    fixGuidance,
    verificationSteps,
  };
}

function buildAffectedCodePattern(finding: RemediationFinding) {
  const location = finding.sourceFile
    ? `${finding.sourceFile}${finding.lineNumber ? `:${finding.lineNumber}` : ""}`
    : finding.affectedUrl
      ? `${finding.httpMethod ?? "GET"} ${finding.affectedUrl}`
      : finding.component
        ? finding.component
        : "Application route, middleware, or service handling this behavior";
  const parameter = finding.parameter
    ? ` Input or control point: ${finding.parameter}.`
    : "";
  return `${location}. Look for code matching ${finding.scannerRuleId} in the ${finding.category.toLowerCase()} path.${parameter}`;
}

function buildFixGuidance(finding: RemediationFinding) {
  const text = [
    finding.title,
    finding.category,
    finding.scannerRuleId,
    finding.description,
    finding.remediation,
    finding.cwe ?? "",
    finding.owaspCategory ?? "",
  ]
    .join(" ")
    .toLowerCase();

  if (
    /idor|access control|authorization|privilege|role|tenant|account/.test(text)
  ) {
    return [
      "Add server-side authorization on the exact handler that returns or mutates this resource; client-side checks are not enough.",
      "Bind every database lookup to the authenticated actor, tenant, role, and resource owner before returning data.",
      "Add negative tests for anonymous users, normal users, admins, and cross-account access so the same issue cannot reappear silently.",
    ];
  }

  if (/xss|script|html injection|content security policy|csp/.test(text)) {
    return [
      "Encode untrusted data at the output boundary for the specific context: HTML body, attribute, URL, JavaScript, or CSS.",
      "Sanitize rich HTML with an allow-list sanitizer and remove inline event handlers, script URLs, and unsafe DOM sinks.",
      "Tighten Content-Security-Policy to reduce exploitability, then verify the root injection is fixed rather than relying only on CSP.",
    ];
  }

  if (
    /sql|injection|nosql|ldap|command|template|ssti|deserialization/.test(text)
  ) {
    return [
      "Replace dynamic string-built queries or commands with parameterized APIs, typed builders, or allow-listed command arguments.",
      "Validate input shape, type, length, and allowed values before it reaches the vulnerable sink.",
      "Add regression tests with the captured payload and nearby variants to prove the sink no longer interprets user input as code.",
    ];
  }

  if (/cookie|session|csrf|same.?site|httponly|secure/.test(text)) {
    return [
      "Set security attributes at the session/cookie creation point: Secure, HttpOnly, and an appropriate SameSite policy.",
      "Protect state-changing routes with CSRF tokens or same-origin request validation.",
      "Rotate affected sessions after the fix if the weakness could expose or replay authentication material.",
    ];
  }

  if (/cors|origin|cross-origin/.test(text)) {
    return [
      "Replace reflected or wildcard origins with an explicit allow-list of trusted origins.",
      "Return credentials only for approved origins and avoid combining credentials with broad CORS access.",
      "Test disallowed origins, null origins, and subdomain lookalikes before closing the finding.",
    ];
  }

  if (/tls|ssl|certificate|cipher|hsts|transport/.test(text)) {
    return [
      "Update the edge/server TLS policy to disable weak protocols and ciphers, then deploy a valid certificate chain.",
      "Enable HSTS only after HTTPS is consistently available for the target host and subdomains in scope.",
      "Retest from a clean external network path to confirm the public endpoint presents the corrected transport settings.",
    ];
  }

  if (
    /header|clickjacking|frame|x-frame|referrer|permissions-policy/.test(text)
  ) {
    return [
      "Set the missing or weak response header at the shared edge, reverse proxy, or framework middleware layer.",
      "Use the narrowest policy that still supports legitimate product behavior.",
      "Verify the header appears on HTML routes, redirects, error pages, and authenticated views.",
    ];
  }

  if (
    /api|graphql|openapi|swagger|mass assignment|parameter|pagination|export/.test(
      text,
    )
  ) {
    return [
      "Enforce schema validation and explicit field allow-lists for request bodies, filters, exports, and mutations.",
      "Compare responses across roles and accounts to confirm sensitive fields and objects are never returned to the wrong actor.",
      "Add API contract tests for rejected extra fields, unauthorized IDs, oversized pagination, and export boundaries.",
    ];
  }

  const base = finding.remediation.trim();
  return [
    base ||
      "Fix the vulnerable behavior at the server-side control point identified by the finding.",
    "Add a regression test that uses the recorded affected URL, parameter, and scanner rule.",
    "Retest the finding after deployment and attach before/after evidence to the lifecycle record.",
  ];
}

function buildVerificationSteps(finding: RemediationFinding) {
  const reproduction = normalizeSteps(finding.reproductionSteps);
  const steps = reproduction.length
    ? reproduction
    : [
        `Open ${finding.affectedUrl ?? "the affected route"} as the role that originally triggered the finding.`,
        `Exercise the behavior covered by ${finding.scannerRuleId}.`,
      ];
  if (finding.retestInstructions) steps.push(finding.retestInstructions);
  steps.push(
    "Run the targeted retest from Probeveil and confirm the status changes to retest passed.",
  );
  steps.push(
    "Confirm no new higher-severity finding appears for the same route, parameter, or issue identity.",
  );
  return dedupe(steps);
}

function normalizeSteps(value: unknown) {
  if (Array.isArray(value))
    return value
      .map((step) => (typeof step === "string" ? step.trim() : ""))
      .filter(Boolean);
  if (typeof value === "string" && value.trim()) return [value.trim()];
  return [];
}

function buildDeveloperTicketMarkdown(
  finding: RemediationFinding,
  scan: RemediationScan | null | undefined,
  fixGuidance: string[],
  verificationSteps: string[],
) {
  const lines = [
    `# ${finding.title}`,
    "",
    `Severity: ${finding.severity}`,
    `Confidence: ${finding.confidence}`,
    `Rule: ${finding.scannerName} / ${finding.scannerRuleId}`,
    `Target: ${scan?.finalUrl ?? scan?.normalizedUrl ?? finding.affectedUrl ?? "Unknown"}`,
    `Affected URL: ${finding.affectedUrl ?? "Unknown"}`,
    `Method: ${finding.httpMethod ?? "Unknown"}`,
    `Parameter: ${finding.parameter ?? "None recorded"}`,
    `Category: ${finding.category}`,
    `CWE: ${finding.cwe ?? "Unmapped"}`,
    "",
    "## Impact",
    finding.impact,
    "",
    "## Affected Code Pattern",
    buildAffectedCodePattern(finding),
    "",
    "## Exact Fix Guidance",
    ...fixGuidance.map((step) => `- ${step}`),
    "",
    "## Verification Steps",
    ...verificationSteps.map((step, index) => `${index + 1}. ${step}`),
    "",
    "## Scanner Evidence Summary",
    finding.description,
  ];
  return `${lines.join("\n")}\n`;
}

function dedupe(values: string[]) {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}
