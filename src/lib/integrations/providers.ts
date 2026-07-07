import "server-only";
import {
  IntegrationDeliveryStatus,
  IntegrationEventType,
  IntegrationProvider,
  type Finding,
  type Prisma,
  type Scan,
} from "@prisma/client";
import { db } from "@/lib/db";
export { getIntegrationStatuses } from "@/lib/integrations/status";

type FindingWithScan = Finding & { scan: Scan };

type DeliveryResult = {
  error?: string;
  externalId?: string;
  externalUrl?: string;
  responseStatus?: number;
  status: IntegrationDeliveryStatus;
  target?: string;
};

const highSeverities = new Set(["CRITICAL", "HIGH"]);

export async function processScanIntegrations(scanId: string) {
  const scan = await db.scan.findUnique({
    include: {
      findings: {
        orderBy: [{ severity: "asc" }, { detectedAt: "desc" }],
      },
    },
    where: { id: scanId },
  });
  if (!scan) return;

  const highFindings = scan.findings.filter((finding) =>
    highSeverities.has(finding.severity),
  );

  if (scan.status === "COMPLETED") {
    await sendChatEvent({
      eventType: IntegrationEventType.SCAN_SUMMARY,
      payload: scanSummaryPayload(scan),
      scan,
      subject: `Probeveil scan summary: ${hostLabel(scan.normalizedUrl)}`,
    });
  }

  if (scan.status === "FAILED") {
    await sendChatEvent({
      eventType: IntegrationEventType.FAILED_SCAN,
      payload: failedScanPayload(scan),
      scan,
      subject: `Probeveil failed scan: ${hostLabel(scan.normalizedUrl)}`,
    });
  }

  if (scan.status === "COMPLETED" && highFindings.length) {
    await sendChatEvent({
      eventType: IntegrationEventType.HIGH_SEVERITY_ALERT,
      payload: highSeverityPayload(scan, highFindings),
      scan,
      subject: `Probeveil high severity alert: ${highFindings.length} finding${highFindings.length === 1 ? "" : "s"}`,
    });

    for (const finding of highFindings) {
      await createTrackingWork({ ...finding, scan });
    }
  }
}

async function sendChatEvent(input: {
  eventType: IntegrationEventType;
  payload: Record<string, unknown>;
  scan: Scan & { findings: Finding[] };
  subject: string;
}) {
  const providers = [
    [IntegrationProvider.SLACK, process.env.SLACK_WEBHOOK_URL],
    [IntegrationProvider.DISCORD, process.env.DISCORD_WEBHOOK_URL],
    [IntegrationProvider.TEAMS, process.env.TEAMS_WEBHOOK_URL],
  ] as const;

  for (const [provider, webhookUrl] of providers) {
    if (await alreadyDelivered(provider, input.eventType, input.scan.id))
      continue;
    const result = webhookUrl
      ? await sendWebhook(provider, webhookUrl, input.subject, input.payload)
      : {
          status: IntegrationDeliveryStatus.NOT_CONFIGURED,
          target: provider,
        };
    await recordDelivery({
      eventType: input.eventType,
      provider,
      result,
      scanId: input.scan.id,
      subject: input.subject,
      payload: input.payload,
    });
  }
}

async function createTrackingWork(finding: FindingWithScan) {
  const providers = [
    [IntegrationProvider.JIRA, jiraConfigured()],
    [
      IntegrationProvider.LINEAR,
      Boolean(process.env.LINEAR_API_KEY && process.env.LINEAR_TEAM_ID),
    ],
    [
      IntegrationProvider.GITHUB,
      Boolean(
        process.env.GITHUB_ISSUES_TOKEN && process.env.GITHUB_ISSUES_REPO,
      ),
    ],
  ] as const;

  for (const [provider, configured] of providers) {
    if (
      await alreadyDelivered(
        provider,
        IntegrationEventType.HIGH_SEVERITY_FINDING,
        finding.scanId,
        finding.id,
      )
    )
      continue;
    const payload = findingIssuePayload(finding);
    const result = configured
      ? await createIssue(provider, finding, payload)
      : {
          status: IntegrationDeliveryStatus.NOT_CONFIGURED,
          target: provider,
        };
    await recordDelivery({
      eventType: IntegrationEventType.HIGH_SEVERITY_FINDING,
      findingId: finding.id,
      provider,
      result,
      scanId: finding.scanId,
      subject: issueTitle(finding),
      payload,
    });
  }
}

async function createIssue(
  provider: IntegrationProvider,
  finding: FindingWithScan,
  payload: Record<string, unknown>,
) {
  if (provider === IntegrationProvider.JIRA)
    return createJiraIssue(finding, payload);
  if (provider === IntegrationProvider.LINEAR)
    return createLinearIssue(finding, payload);
  return createGitHubIssue(finding, payload);
}

async function createJiraIssue(
  finding: FindingWithScan,
  payload: Record<string, unknown>,
): Promise<DeliveryResult> {
  const baseUrl = process.env.JIRA_BASE_URL?.replace(/\/$/, "");
  const email = process.env.JIRA_EMAIL;
  const token = process.env.JIRA_API_TOKEN;
  const projectKey = process.env.JIRA_PROJECT_KEY;
  if (!baseUrl || !email || !token || !projectKey)
    return { status: IntegrationDeliveryStatus.NOT_CONFIGURED };

  const response = await fetch(`${baseUrl}/rest/api/3/issue`, {
    body: JSON.stringify({
      fields: {
        description: jiraDescription(finding),
        issuetype: { name: process.env.JIRA_ISSUE_TYPE ?? "Task" },
        labels: ["probeveil", `severity-${finding.severity.toLowerCase()}`],
        project: { key: projectKey },
        summary: issueTitle(finding),
      },
    }),
    headers: {
      Authorization: `Basic ${Buffer.from(`${email}:${token}`).toString("base64")}`,
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    method: "POST",
  });
  const data = await response.json().catch(() => ({}));
  return {
    error: response.ok ? undefined : stringifyError(data),
    externalId: typeof data.key === "string" ? data.key : undefined,
    externalUrl:
      typeof data.key === "string"
        ? `${baseUrl}/browse/${data.key}`
        : undefined,
    responseStatus: response.status,
    status: response.ok
      ? IntegrationDeliveryStatus.SENT
      : IntegrationDeliveryStatus.FAILED,
    target: projectKey,
  };
}

async function createLinearIssue(
  finding: FindingWithScan,
  payload: Record<string, unknown>,
): Promise<DeliveryResult> {
  const apiKey = process.env.LINEAR_API_KEY;
  const teamId = process.env.LINEAR_TEAM_ID;
  if (!apiKey || !teamId)
    return { status: IntegrationDeliveryStatus.NOT_CONFIGURED };

  const response = await fetch("https://api.linear.app/graphql", {
    body: JSON.stringify({
      query:
        "mutation ProbeveilCreateIssue($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url } } }",
      variables: {
        input: {
          description: markdownDescription(finding),
          labelIds: process.env.LINEAR_LABEL_ID
            ? [process.env.LINEAR_LABEL_ID]
            : undefined,
          priority: finding.severity === "CRITICAL" ? 1 : 2,
          teamId,
          title: issueTitle(finding),
        },
      },
    }),
    headers: {
      Authorization: apiKey,
      "Content-Type": "application/json",
    },
    method: "POST",
  });
  const data = await response.json().catch(() => ({}));
  const issue = data?.data?.issueCreate?.issue;
  const success = response.ok && data?.data?.issueCreate?.success === true;
  return {
    error: success ? undefined : stringifyError(data),
    externalId:
      typeof issue?.identifier === "string" ? issue.identifier : undefined,
    externalUrl: typeof issue?.url === "string" ? issue.url : undefined,
    responseStatus: response.status,
    status: success
      ? IntegrationDeliveryStatus.SENT
      : IntegrationDeliveryStatus.FAILED,
    target: teamId,
  };
}

async function createGitHubIssue(
  finding: FindingWithScan,
  payload: Record<string, unknown>,
): Promise<DeliveryResult> {
  const token = process.env.GITHUB_ISSUES_TOKEN;
  const repo = process.env.GITHUB_ISSUES_REPO;
  if (!token || !repo)
    return { status: IntegrationDeliveryStatus.NOT_CONFIGURED };

  const response = await fetch(`https://api.github.com/repos/${repo}/issues`, {
    body: JSON.stringify({
      body: markdownDescription(finding),
      labels: ["probeveil", finding.severity.toLowerCase()],
      title: issueTitle(finding),
    }),
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      "User-Agent": "Probeveil",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    method: "POST",
  });
  const data = await response.json().catch(() => ({}));
  return {
    error: response.ok ? undefined : stringifyError(data),
    externalId:
      typeof data.number === "number" ? String(data.number) : undefined,
    externalUrl: typeof data.html_url === "string" ? data.html_url : undefined,
    responseStatus: response.status,
    status: response.ok
      ? IntegrationDeliveryStatus.SENT
      : IntegrationDeliveryStatus.FAILED,
    target: repo,
  };
}

async function sendWebhook(
  provider: IntegrationProvider,
  url: string,
  subject: string,
  payload: Record<string, unknown>,
): Promise<DeliveryResult> {
  const response = await fetch(url, {
    body: JSON.stringify(webhookBody(provider, subject, payload)),
    headers: { "Content-Type": "application/json" },
    method: "POST",
  });
  const text = response.ok ? "" : await response.text().catch(() => "");
  return {
    error: response.ok ? undefined : text || `HTTP ${response.status}`,
    responseStatus: response.status,
    status: response.ok
      ? IntegrationDeliveryStatus.SENT
      : IntegrationDeliveryStatus.FAILED,
    target: webhookTarget(url),
  };
}

async function recordDelivery(input: {
  eventType: IntegrationEventType;
  findingId?: string;
  payload: Record<string, unknown>;
  provider: IntegrationProvider;
  result: DeliveryResult;
  scanId?: string;
  subject: string;
}) {
  await db.integrationDelivery.create({
    data: {
      error: input.result.error,
      eventType: input.eventType,
      externalId: input.result.externalId,
      externalUrl: input.result.externalUrl,
      findingId: input.findingId,
      payload: input.payload as Prisma.InputJsonValue,
      provider: input.provider,
      responseStatus: input.result.responseStatus,
      scanId: input.scanId,
      sentAt:
        input.result.status === IntegrationDeliveryStatus.SENT
          ? new Date()
          : null,
      status: input.result.status,
      subject: input.subject,
      target: input.result.target,
    },
  });
}

async function alreadyDelivered(
  provider: IntegrationProvider,
  eventType: IntegrationEventType,
  scanId?: string,
  findingId?: string,
) {
  const delivery = await db.integrationDelivery.findFirst({
    where: {
      eventType,
      findingId,
      provider,
      scanId,
      status: {
        in: [IntegrationDeliveryStatus.SENT, IntegrationDeliveryStatus.SKIPPED],
      },
    },
  });
  return Boolean(delivery);
}

function scanSummaryPayload(scan: Scan & { findings: Finding[] }) {
  const counts = severityCounts(scan.findings);
  return {
    coverageScore: scan.coverageScore,
    findingCount: scan.findings.length,
    mode: scan.mode,
    scanId: scan.id,
    securityScore: scan.securityScore,
    severityCounts: counts,
    status: scan.status,
    target: scan.normalizedUrl,
  };
}

function failedScanPayload(scan: Scan) {
  return {
    error: scan.error,
    mode: scan.mode,
    scanId: scan.id,
    status: scan.status,
    target: scan.normalizedUrl,
  };
}

function highSeverityPayload(scan: Scan, findings: Finding[]) {
  return {
    findings: findings.slice(0, 20).map((finding) => ({
      affectedUrl: finding.affectedUrl,
      id: finding.id,
      severity: finding.severity,
      title: finding.title,
    })),
    scanId: scan.id,
    target: scan.normalizedUrl,
    total: findings.length,
  };
}

function findingIssuePayload(finding: FindingWithScan) {
  return {
    affectedUrl: finding.affectedUrl,
    category: finding.category,
    cwe: finding.cwe,
    findingId: finding.id,
    impact: finding.impact,
    remediation: finding.remediation,
    scanId: finding.scanId,
    scanner: finding.scannerName,
    severity: finding.severity,
    target: finding.scan.normalizedUrl,
    title: finding.title,
  };
}

function webhookBody(
  provider: IntegrationProvider,
  subject: string,
  payload: Record<string, unknown>,
) {
  const text = `${subject}\n${plainPayload(payload)}`;
  if (provider === IntegrationProvider.DISCORD)
    return { content: text.slice(0, 1900) };
  if (provider === IntegrationProvider.TEAMS)
    return { text: text.replace(/\n/g, "<br>") };
  return { text };
}

function issueTitle(finding: Finding) {
  return `[Probeveil ${finding.severity}] ${finding.title}`.slice(0, 180);
}

function markdownDescription(finding: FindingWithScan) {
  return [
    `Probeveil detected a ${finding.severity.toLowerCase()} severity finding.`,
    "",
    `Target: ${finding.scan.normalizedUrl}`,
    `Affected URL: ${finding.affectedUrl ?? "N/A"}`,
    `Scanner: ${finding.scannerName}`,
    `Rule: ${finding.scannerRuleId}`,
    `CWE: ${finding.cwe ?? "N/A"}`,
    "",
    "Impact:",
    finding.impact,
    "",
    "Remediation:",
    finding.remediation,
    "",
    `Finding ID: ${finding.id}`,
    `Scan ID: ${finding.scanId}`,
  ].join("\n");
}

function jiraDescription(finding: FindingWithScan) {
  return {
    content: [
      ...markdownDescription(finding)
        .split("\n")
        .map((text) => ({
          content: text ? [{ text, type: "text" }] : [],
          type: "paragraph",
        })),
    ],
    type: "doc",
    version: 1,
  };
}

function severityCounts(findings: Finding[]) {
  return findings.reduce(
    (counts, finding) => {
      counts[finding.severity] += 1;
      return counts;
    },
    { CRITICAL: 0, HIGH: 0, INFO: 0, LOW: 0, MEDIUM: 0 },
  );
}

function jiraConfigured() {
  return Boolean(
    process.env.JIRA_BASE_URL &&
      process.env.JIRA_EMAIL &&
      process.env.JIRA_API_TOKEN &&
      process.env.JIRA_PROJECT_KEY,
  );
}

function hostLabel(value: string) {
  try {
    return new URL(value).hostname;
  } catch {
    return value;
  }
}

function webhookTarget(value?: string) {
  if (!value) return "Missing webhook";
  try {
    return new URL(value).hostname;
  } catch {
    return "Configured webhook";
  }
}

function plainPayload(payload: Record<string, unknown>) {
  return Object.entries(payload)
    .map(([key, value]) => `${key}: ${formatValue(value)}`)
    .join("\n");
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "-";
  if (typeof value === "object") return JSON.stringify(value).slice(0, 1000);
  return String(value);
}

function stringifyError(value: unknown) {
  if (typeof value === "string") return value;
  const serialized = JSON.stringify(value);
  return typeof serialized === "string" ? serialized.slice(0, 2000) : String(value);
}
