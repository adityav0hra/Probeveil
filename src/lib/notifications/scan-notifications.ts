import "server-only";
import {
  NotificationDeliveryStatus,
  NotificationType,
  type Finding,
  type Scan,
  type ScanSchedule,
} from "@prisma/client";
import type { Prisma } from "@prisma/client";
import { db } from "@/lib/db";
import { notificationDefaultEmail } from "@/lib/email/config";
import { diffFindings, type FindingDiffInput } from "@/lib/scheduling";
import { sendNotificationEmailDetailed } from "./email";

type AutomationSettings = {
  differentialReports: boolean;
  highSeverityAlerts: boolean;
  notificationEmail: string;
  summaryEmails?: boolean;
};

const defaultAutomationSettings: AutomationSettings = {
  differentialReports: true,
  highSeverityAlerts: true,
  notificationEmail: "",
  summaryEmails: true,
};

const severityOrder = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

export async function processScanNotifications(scanId: string) {
  const existing = await db.scanNotification.count({ where: { scanId } });
  if (existing > 0) return;

  const scan = await db.scan.findUnique({
    include: {
      findings: {
        orderBy: [{ severity: "asc" }, { detectedAt: "desc" }],
      },
      schedule: true,
    },
    where: { id: scanId },
  });
  if (!scan) return;

  const settings = await readAutomationSettings();
  const preferences = notificationPreferences(scan.schedule, settings);
  if (!preferences.enabled) return;

  const previous = await previousComparableScan(scan);
  const diff = previous
    ? diffFindings(scan.findings, previous.findings)
    : { fixedFindings: [], newFindings: [] };
  const highSeverityFindings = scan.findings.filter((finding) =>
    ["CRITICAL", "HIGH"].includes(finding.severity),
  );

  const jobs: Array<{
    body: string;
    metadata: Prisma.InputJsonValue;
    subject: string;
    type: NotificationType;
  }> = [];

  if (scan.status === "FAILED" && preferences.failedScanAlerts) {
    jobs.push({
      body: renderFailedScan(scan),
      metadata: {
        error: scan.error,
        normalizedUrl: scan.normalizedUrl,
      },
      subject: `Probeveil failed scan alert: ${new URL(scan.normalizedUrl).hostname}`,
      type: NotificationType.FAILED_SCAN,
    });
  }

  if (scan.status === "COMPLETED" && preferences.summaryEmails) {
    jobs.push({
      body: renderSummary(scan, previous, diff),
      metadata: summaryMetadata(scan, previous, diff),
      subject: `Probeveil scan summary: ${new URL(scan.normalizedUrl).hostname}`,
      type: NotificationType.SCAN_SUMMARY,
    });
  }

  if (
    scan.status === "COMPLETED" &&
    preferences.highSeverityAlerts &&
    highSeverityFindings.length
  ) {
    jobs.push({
      body: renderHighSeverityAlert(scan, highSeverityFindings),
      metadata: {
        count: highSeverityFindings.length,
        findings: compactFindings(highSeverityFindings),
      },
      subject: `Probeveil high severity alert: ${highSeverityFindings.length} finding${highSeverityFindings.length === 1 ? "" : "s"}`,
      type: NotificationType.HIGH_SEVERITY_ALERT,
    });
  }

  if (
    scan.status === "COMPLETED" &&
    preferences.newFindingDiffs &&
    previous &&
    diff.newFindings.length
  ) {
    jobs.push({
      body: renderDiff(scan, previous, diff),
      metadata: {
        fixedFindings: compactFindings(diff.fixedFindings),
        newFindings: compactFindings(diff.newFindings),
        previousScanId: previous.id,
      },
      subject: `Probeveil new finding diff: ${diff.newFindings.length} new`,
      type: NotificationType.NEW_FINDING_DIFF,
    });
  }

  for (const job of jobs) {
    await createAndSendNotification({
      ...job,
      scan,
      toEmail: preferences.email,
    });
  }
}

async function createAndSendNotification(input: {
  body: string;
  metadata: Prisma.InputJsonValue;
  scan: Scan & { schedule: ScanSchedule | null };
  subject: string;
  toEmail?: string | null;
  type: NotificationType;
}) {
  const toEmail = input.toEmail || notificationDefaultEmail() || null;
  let status: NotificationDeliveryStatus =
    NotificationDeliveryStatus.NOT_CONFIGURED;
  let error: string | undefined;
  try {
    const result = await sendNotificationEmailDetailed({
      subject: input.subject,
      text: input.body,
      to: toEmail,
    });
    status =
      result.status === "SENT"
        ? NotificationDeliveryStatus.SENT
        : result.status === "FAILED"
          ? NotificationDeliveryStatus.FAILED
          : NotificationDeliveryStatus.NOT_CONFIGURED;
    error = result.error;
  } catch (caught) {
    status = NotificationDeliveryStatus.FAILED;
    error = caught instanceof Error ? caught.message : String(caught);
  }

  await db.scanNotification.create({
    data: {
      body: input.body,
      error,
      metadata: input.metadata,
      scanId: input.scan.id,
      scheduleId: input.scan.scheduleId,
      sentAt: status === NotificationDeliveryStatus.SENT ? new Date() : null,
      status,
      subject: input.subject,
      toEmail,
      type: input.type,
    },
  });
}

async function previousComparableScan(
  scan: Scan & { findings: Finding[]; schedule: ScanSchedule | null },
) {
  return db.scan.findFirst({
    include: { findings: true },
    orderBy: { createdAt: "desc" },
    where: {
      id: { not: scan.id },
      normalizedHash: scan.normalizedHash,
      ...(scan.scheduleId ? { scheduleId: scan.scheduleId } : {}),
      status: "COMPLETED",
      createdAt: { lt: scan.createdAt },
    },
  });
}

async function readAutomationSettings() {
  const row = await db.systemSetting.findUnique({
    where: { key: "scan_automation" },
  });
  if (!row?.value || typeof row.value !== "object")
    return {
      ...defaultAutomationSettings,
      notificationEmail: notificationDefaultEmail() ?? "",
    };
  return {
    ...defaultAutomationSettings,
    notificationEmail: notificationDefaultEmail() ?? "",
    ...(row.value as Partial<AutomationSettings>),
  };
}

function notificationPreferences(
  schedule: ScanSchedule | null,
  settings: AutomationSettings,
) {
  if (schedule) {
    return {
      email: schedule.notificationEmail || settings.notificationEmail,
      enabled:
        schedule.summaryEmails ||
        schedule.failedScanAlerts ||
        schedule.highSeverityAlerts ||
        schedule.newFindingDiffs,
      failedScanAlerts: schedule.failedScanAlerts,
      highSeverityAlerts: schedule.highSeverityAlerts,
      newFindingDiffs: schedule.newFindingDiffs,
      summaryEmails: schedule.summaryEmails,
    };
  }
  return {
    email: settings.notificationEmail || notificationDefaultEmail(),
    enabled: Boolean(settings.notificationEmail || notificationDefaultEmail()),
    failedScanAlerts: true,
    highSeverityAlerts: settings.highSeverityAlerts,
    newFindingDiffs: settings.differentialReports,
    summaryEmails: settings.summaryEmails ?? true,
  };
}

function renderFailedScan(scan: Scan) {
  return [
    "Probeveil scan failed",
    "",
    `Target: ${scan.normalizedUrl}`,
    `Mode: ${scan.mode}`,
    `Scan ID: ${scan.id}`,
    `Error: ${scan.error ?? "Worker failed before returning details."}`,
    "",
    "Open the admin console to inspect the failed run and queue a replacement scan.",
  ].join("\n");
}

function renderSummary(
  scan: Scan & { findings: Finding[] },
  previous: (Scan & { findings: Finding[] }) | null,
  diff: ReturnType<typeof diffFindings>,
) {
  const counts = severityCounts(scan.findings);
  return [
    "Probeveil scan summary",
    "",
    `Target: ${scan.normalizedUrl}`,
    `Mode: ${scan.mode}`,
    `Status: ${scan.status}`,
    `Security score: ${scan.securityScore ?? "Not scored"}`,
    `Coverage score: ${scan.coverageScore ?? "Not scored"}`,
    `Findings: ${scan.findings.length}`,
    `Critical: ${counts.CRITICAL}, High: ${counts.HIGH}, Medium: ${counts.MEDIUM}, Low: ${counts.LOW}, Info: ${counts.INFO}`,
    previous
      ? `Compared with: ${previous.id}`
      : "Compared with: no previous completed scan",
    `New since last scan: ${diff.newFindings.length}`,
    `No longer reproduced: ${diff.fixedFindings.length}`,
  ].join("\n");
}

function renderHighSeverityAlert(scan: Scan, findings: Finding[]) {
  return [
    "Probeveil high severity alert",
    "",
    `Target: ${scan.normalizedUrl}`,
    `Scan ID: ${scan.id}`,
    "",
    ...compactFindings(findings)
      .slice(0, 10)
      .map(
        (finding) =>
          `- ${finding.severity}: ${finding.title}${finding.affectedUrl ? ` (${finding.affectedUrl})` : ""}`,
      ),
  ].join("\n");
}

function renderDiff(
  scan: Scan,
  previous: Scan,
  diff: ReturnType<typeof diffFindings>,
) {
  return [
    "Probeveil new finding diff",
    "",
    `Target: ${scan.normalizedUrl}`,
    `Current scan: ${scan.id}`,
    `Previous scan: ${previous.id}`,
    "",
    "New findings:",
    ...compactFindings(diff.newFindings)
      .slice(0, 20)
      .map(
        (finding) =>
          `- ${finding.severity}: ${finding.title}${finding.affectedUrl ? ` (${finding.affectedUrl})` : ""}`,
      ),
    "",
    `No longer reproduced: ${diff.fixedFindings.length}`,
  ].join("\n");
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

function compactFindings(findings: Array<FindingDiffInput & { id?: string }>) {
  return findings
    .slice()
    .sort(
      (a, b) =>
        severityOrder[a.severity as keyof typeof severityOrder] -
          severityOrder[b.severity as keyof typeof severityOrder] ||
        a.title.localeCompare(b.title),
    )
    .map((finding) => ({
      affectedUrl: finding.affectedUrl,
      id: finding.id,
      parameter: finding.parameter,
      scannerRuleId: finding.scannerRuleId,
      severity: finding.severity,
      title: finding.title,
    }));
}

function summaryMetadata(
  scan: Scan & { findings: Finding[] },
  previous: (Scan & { findings: Finding[] }) | null,
  diff: ReturnType<typeof diffFindings>,
) {
  return {
    coverageScore: scan.coverageScore,
    fixedFindings: diff.fixedFindings.length,
    findingCount: scan.findings.length,
    previousScanId: previous?.id,
    securityScore: scan.securityScore,
    severityCounts: severityCounts(scan.findings),
    newFindings: diff.newFindings.length,
  } satisfies Prisma.InputJsonValue;
}
