-- CreateEnum
CREATE TYPE "IssueLifecycleStatus" AS ENUM ('ACTIVE', 'FIXED', 'REOPENED', 'ACCEPTED_RISK', 'FALSE_POSITIVE');

-- CreateEnum
CREATE TYPE "IssueLifecycleEventType" AS ENUM ('OBSERVED', 'FIXED', 'REOPENED', 'TRIAGED');

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "issueId" TEXT;

-- CreateTable
CREATE TABLE "FindingIssue" (
    "id" TEXT NOT NULL,
    "normalizedHash" TEXT NOT NULL,
    "identityKey" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "cwe" TEXT,
    "scannerRuleId" TEXT NOT NULL,
    "affectedUrl" TEXT,
    "parameter" TEXT,
    "severity" "Severity" NOT NULL,
    "status" "IssueLifecycleStatus" NOT NULL DEFAULT 'ACTIVE',
    "firstSeenAt" TIMESTAMP(3) NOT NULL,
    "lastSeenAt" TIMESTAMP(3) NOT NULL,
    "lastResolvedAt" TIMESTAMP(3),
    "lastScanId" TEXT,
    "occurrenceCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "FindingIssue_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FindingIssueEvent" (
    "id" TEXT NOT NULL,
    "issueId" TEXT NOT NULL,
    "scanId" TEXT,
    "findingId" TEXT,
    "eventType" "IssueLifecycleEventType" NOT NULL,
    "fromStatus" "IssueLifecycleStatus",
    "toStatus" "IssueLifecycleStatus" NOT NULL,
    "severity" "Severity",
    "summary" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "FindingIssueEvent_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "FindingIssue_normalizedHash_status_idx" ON "FindingIssue"("normalizedHash", "status");

-- CreateIndex
CREATE INDEX "FindingIssue_status_severity_lastSeenAt_idx" ON "FindingIssue"("status", "severity", "lastSeenAt");

-- CreateIndex
CREATE UNIQUE INDEX "FindingIssue_normalizedHash_identityKey_key" ON "FindingIssue"("normalizedHash", "identityKey");

-- CreateIndex
CREATE INDEX "FindingIssueEvent_issueId_createdAt_idx" ON "FindingIssueEvent"("issueId", "createdAt");

-- CreateIndex
CREATE INDEX "FindingIssueEvent_scanId_eventType_idx" ON "FindingIssueEvent"("scanId", "eventType");

-- CreateIndex
CREATE INDEX "Finding_issueId_detectedAt_idx" ON "Finding"("issueId", "detectedAt");

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_issueId_fkey" FOREIGN KEY ("issueId") REFERENCES "FindingIssue"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FindingIssueEvent" ADD CONSTRAINT "FindingIssueEvent_issueId_fkey" FOREIGN KEY ("issueId") REFERENCES "FindingIssue"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FindingIssueEvent" ADD CONSTRAINT "FindingIssueEvent_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE SET NULL ON UPDATE CASCADE;

