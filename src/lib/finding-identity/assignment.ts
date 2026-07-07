import "server-only";
import {
  FindingStatus,
  IssueLifecycleEventType,
  IssueLifecycleStatus,
  type Severity,
} from "@prisma/client";
import { db } from "@/lib/db";
import { findingIdentityKey } from "@/lib/finding-identity/key";

const activeIssueStatuses = [
  IssueLifecycleStatus.ACTIVE,
  IssueLifecycleStatus.REOPENED,
];

const severityRank: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export async function assignFindingIssues(scanId: string) {
  const scan = await db.scan.findUnique({
    include: {
      findings: {
        orderBy: [{ severity: "asc" }, { detectedAt: "desc" }],
      },
    },
    where: { id: scanId },
  });
  if (!scan || scan.status !== "COMPLETED") return;

  const seenAt = scan.completedAt ?? new Date();

  for (const finding of scan.findings) {
    const identityKey = findingIdentityKey(finding);
    if (finding.issueId) continue;
    const existing = await db.findingIssue.findUnique({
      where: {
        normalizedHash_identityKey: {
          identityKey,
          normalizedHash: scan.normalizedHash,
        },
      },
    });
    const issue = existing
      ? await db.findingIssue.update({
          where: { id: existing.id },
          data: {
            affectedUrl: finding.affectedUrl,
            category: finding.category,
            cwe: finding.cwe,
            lastResolvedAt:
              existing.status === IssueLifecycleStatus.FIXED
                ? null
                : existing.lastResolvedAt,
            lastScanId: scan.id,
            lastSeenAt: seenAt,
            occurrenceCount: { increment: 1 },
            parameter: finding.parameter,
            scannerRuleId: finding.scannerRuleId,
            severity: worseSeverity(existing.severity, finding.severity),
            status: nextObservedStatus(existing.status),
            title: finding.title,
          },
        })
      : await db.findingIssue.create({
          data: {
            affectedUrl: finding.affectedUrl,
            category: finding.category,
            cwe: finding.cwe,
            firstSeenAt: finding.detectedAt,
            identityKey,
            lastScanId: scan.id,
            lastSeenAt: seenAt,
            normalizedHash: scan.normalizedHash,
            occurrenceCount: 1,
            parameter: finding.parameter,
            scannerRuleId: finding.scannerRuleId,
            severity: finding.severity,
            status: IssueLifecycleStatus.ACTIVE,
            title: finding.title,
          },
        });
    const findingStatus = findingStatusForIssue(issue.status);
    await db.finding.update({
      where: { id: finding.id },
      data: {
        issueId: issue.id,
        ...(findingStatus ? { status: findingStatus } : {}),
      },
    });
    await db.findingIssueEvent.create({
      data: {
        eventType:
          existing?.status === IssueLifecycleStatus.FIXED
            ? IssueLifecycleEventType.REOPENED
            : IssueLifecycleEventType.OBSERVED,
        findingId: finding.id,
        fromStatus: existing?.status,
        issueId: issue.id,
        scanId: scan.id,
        severity: finding.severity,
        summary:
          existing?.status === IssueLifecycleStatus.FIXED
            ? `Issue reopened by finding ${finding.id} in scan ${scan.id}.`
            : `Issue observed in scan ${scan.id}.`,
        toStatus: issue.status,
      },
    });
  }

  const staleIssues = await db.findingIssue.findMany({
    where: {
      lastScanId: { not: scan.id },
      normalizedHash: scan.normalizedHash,
      status: { in: activeIssueStatuses },
    },
  });
  for (const issue of staleIssues) {
    await db.findingIssue.update({
      where: { id: issue.id },
      data: {
        lastResolvedAt: seenAt,
        lastScanId: scan.id,
        status: IssueLifecycleStatus.FIXED,
      },
    });
    await db.findingIssueEvent.create({
      data: {
        eventType: IssueLifecycleEventType.FIXED,
        fromStatus: issue.status,
        issueId: issue.id,
        scanId: scan.id,
        severity: issue.severity,
        summary: `Issue was not observed in completed scan ${scan.id}.`,
        toStatus: IssueLifecycleStatus.FIXED,
      },
    });
  }
}

export async function updateIssueFromFindingReview(input: {
  explanation?: string;
  findingId: string;
  nextStatus: FindingStatus;
  previousStatus: FindingStatus;
  userId: string;
}) {
  const issueStatus = issueStatusForFinding(input.nextStatus);
  if (!issueStatus) return;
  const finding = await db.finding.findUnique({
    where: { id: input.findingId },
    select: { issueId: true, scanId: true, severity: true },
  });
  if (!finding?.issueId) return;
  const issue = await db.findingIssue.findUnique({
    where: { id: finding.issueId },
  });
  if (!issue || issue.status === issueStatus) return;

  await db.$transaction([
    db.findingIssue.update({
      where: { id: issue.id },
      data: {
        lastResolvedAt:
          issueStatus === IssueLifecycleStatus.FIXED ? new Date() : undefined,
        status: issueStatus,
      },
    }),
    db.findingIssueEvent.create({
      data: {
        eventType: IssueLifecycleEventType.TRIAGED,
        findingId: input.findingId,
        fromStatus: issue.status,
        issueId: issue.id,
        scanId: finding.scanId,
        severity: finding.severity,
        summary:
          input.explanation ||
          `Issue status changed from ${issue.status} to ${issueStatus}.`,
        toStatus: issueStatus,
      },
    }),
  ]);
}

function nextObservedStatus(status: IssueLifecycleStatus) {
  if (status === IssueLifecycleStatus.FIXED)
    return IssueLifecycleStatus.REOPENED;
  if (
    status === IssueLifecycleStatus.ACCEPTED_RISK ||
    status === IssueLifecycleStatus.FALSE_POSITIVE
  )
    return status;
  return IssueLifecycleStatus.ACTIVE;
}

function findingStatusForIssue(status: IssueLifecycleStatus) {
  if (status === IssueLifecycleStatus.ACCEPTED_RISK)
    return FindingStatus.ACCEPTED_RISK;
  if (status === IssueLifecycleStatus.FALSE_POSITIVE)
    return FindingStatus.FALSE_POSITIVE;
  return undefined;
}

function issueStatusForFinding(status: FindingStatus) {
  if (status === FindingStatus.ACCEPTED_RISK)
    return IssueLifecycleStatus.ACCEPTED_RISK;
  if (status === FindingStatus.FALSE_POSITIVE)
    return IssueLifecycleStatus.FALSE_POSITIVE;
  if (status === FindingStatus.FIXED || status === FindingStatus.RETEST_PASSED)
    return IssueLifecycleStatus.FIXED;
  if (status === FindingStatus.CONFIRMED || status === FindingStatus.OPEN)
    return IssueLifecycleStatus.ACTIVE;
  if (status === FindingStatus.RETEST_FAILED)
    return IssueLifecycleStatus.REOPENED;
  return undefined;
}

function worseSeverity(current: Severity, next: Severity) {
  return severityRank[next] > severityRank[current] ? next : current;
}
