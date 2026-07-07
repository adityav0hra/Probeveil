-- CreateEnum
CREATE TYPE "Role" AS ENUM ('ADMIN', 'AUDITOR');

-- CreateEnum
CREATE TYPE "ScanMode" AS ENUM ('QUICK', 'FULL', 'MAXIMUM');

-- CreateEnum
CREATE TYPE "ScanStatus" AS ENUM ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "StageStatus" AS ENUM ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'SKIPPED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');

-- CreateEnum
CREATE TYPE "Confidence" AS ENUM ('CONFIRMED', 'HIGH', 'PROBABLE', 'POTENTIAL', 'INFORMATIONAL', 'MANUAL_REVIEW');

-- CreateEnum
CREATE TYPE "FindingStatus" AS ENUM ('OPEN', 'CONFIRMED', 'FALSE_POSITIVE', 'ACCEPTED_RISK', 'FIXED', 'RETEST_PASSED', 'RETEST_FAILED');

-- CreateEnum
CREATE TYPE "ReportType" AS ENUM ('EXECUTIVE_HTML', 'TECHNICAL_HTML', 'JSON', 'CSV', 'SARIF', 'CYCLONEDX', 'SPDX', 'RAW_ARCHIVE', 'EVIDENCE_ARCHIVE');

-- CreateEnum
CREATE TYPE "RetestStatus" AS ENUM ('QUEUED', 'RUNNING', 'PASSED', 'FAILED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "ContactEnquiryType" AS ENUM ('PRODUCT_ENQUIRY', 'SECURITY_REVIEW', 'DEMO_REQUEST', 'PARTNERSHIP', 'TECHNICAL_SUPPORT', 'OTHER');

-- CreateEnum
CREATE TYPE "ContactScanDepth" AS ENUM ('NOT_SURE', 'QUICK_SCAN', 'DEEP_SCAN', 'EXHAUSTIVE_SCAN');

-- CreateEnum
CREATE TYPE "ContactEnquiryStatus" AS ENUM ('NEW', 'IN_REVIEW', 'RESPONDED', 'CLOSED', 'SPAM');

-- CreateEnum
CREATE TYPE "ContactEmailStatus" AS ENUM ('NOT_CONFIGURED', 'SENT', 'FAILED');

-- CreateEnum
CREATE TYPE "ScheduleCadence" AS ENUM ('WEEKLY', 'MONTHLY');

-- CreateEnum
CREATE TYPE "NotificationType" AS ENUM ('SCAN_SUMMARY', 'FAILED_SCAN', 'HIGH_SEVERITY_ALERT', 'NEW_FINDING_DIFF');

-- CreateEnum
CREATE TYPE "NotificationDeliveryStatus" AS ENUM ('NOT_CONFIGURED', 'SENT', 'FAILED');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "name" TEXT,
    "email" TEXT NOT NULL,
    "emailVerified" TIMESTAMP(3),
    "image" TEXT,
    "passwordHash" TEXT,
    "role" "Role" NOT NULL DEFAULT 'ADMIN',
    "mfaEnabled" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Account" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "providerAccountId" TEXT NOT NULL,
    "refresh_token" TEXT,
    "access_token" TEXT,
    "expires_at" INTEGER,
    "token_type" TEXT,
    "scope" TEXT,
    "id_token" TEXT,
    "session_state" TEXT,

    CONSTRAINT "Account_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Session" (
    "id" TEXT NOT NULL,
    "sessionToken" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "expires" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VerificationToken" (
    "identifier" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "expires" TIMESTAMP(3) NOT NULL
);

-- CreateTable
CREATE TABLE "Scan" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "scheduleId" TEXT,
    "originalUrl" TEXT NOT NULL,
    "normalizedUrl" TEXT NOT NULL,
    "finalUrl" TEXT,
    "normalizedHash" TEXT NOT NULL,
    "mode" "ScanMode" NOT NULL,
    "status" "ScanStatus" NOT NULL DEFAULT 'QUEUED',
    "securityScore" INTEGER,
    "coverageScore" INTEGER,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "cancelledAt" TIMESTAMP(3),
    "error" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Scan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanSchedule" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "originalUrl" TEXT NOT NULL,
    "normalizedUrl" TEXT NOT NULL,
    "normalizedHash" TEXT NOT NULL,
    "mode" "ScanMode" NOT NULL,
    "cadence" "ScheduleCadence" NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "features" JSONB,
    "notificationEmail" TEXT,
    "summaryEmails" BOOLEAN NOT NULL DEFAULT true,
    "failedScanAlerts" BOOLEAN NOT NULL DEFAULT true,
    "highSeverityAlerts" BOOLEAN NOT NULL DEFAULT true,
    "newFindingDiffs" BOOLEAN NOT NULL DEFAULT true,
    "nextRunAt" TIMESTAMP(3) NOT NULL,
    "lastRunAt" TIMESTAMP(3),
    "lastScanId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScanSchedule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanTarget" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "inScope" BOOLEAN NOT NULL DEFAULT false,
    "reason" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScanTarget_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanProfile" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "mode" "ScanMode" NOT NULL,
    "stageConfig" JSONB NOT NULL,
    "limits" JSONB NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScanProfile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanStage" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "order" INTEGER NOT NULL,
    "status" "StageStatus" NOT NULL DEFAULT 'PENDING',
    "progress" INTEGER NOT NULL DEFAULT 0,
    "message" TEXT,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScanStage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Endpoint" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "method" TEXT NOT NULL DEFAULT 'GET',
    "statusCode" INTEGER,
    "contentType" TEXT,
    "title" TEXT,
    "depth" INTEGER NOT NULL DEFAULT 0,
    "tested" BOOLEAN NOT NULL DEFAULT false,
    "external" BOOLEAN NOT NULL DEFAULT false,
    "discoveredBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Endpoint_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Parameter" (
    "id" TEXT NOT NULL,
    "endpointId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "location" TEXT NOT NULL,
    "dataType" TEXT,
    "tested" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "Parameter_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Service" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "host" TEXT NOT NULL,
    "ip" TEXT,
    "port" INTEGER,
    "protocol" TEXT NOT NULL,
    "tls" JSONB,
    "external" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "Service_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Technology" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "version" TEXT,
    "category" TEXT,
    "evidence" TEXT,

    CONSTRAINT "Technology_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Finding" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "cwe" TEXT,
    "owaspCategory" TEXT,
    "severity" "Severity" NOT NULL,
    "confidence" "Confidence" NOT NULL,
    "status" "FindingStatus" NOT NULL DEFAULT 'OPEN',
    "cvssScore" DOUBLE PRECISION,
    "affectedUrl" TEXT,
    "sourceFile" TEXT,
    "lineNumber" INTEGER,
    "httpMethod" TEXT,
    "parameter" TEXT,
    "component" TEXT,
    "userRole" TEXT,
    "payload" TEXT,
    "scannerName" TEXT NOT NULL,
    "scannerRuleId" TEXT NOT NULL,
    "scannerVersion" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reproductionSteps" JSONB NOT NULL,
    "impact" TEXT NOT NULL,
    "remediation" TEXT NOT NULL,
    "references" JSONB NOT NULL,
    "retestInstructions" TEXT,
    "adminNotes" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Finding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FindingEvidence" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "content" TEXT,
    "artifactId" TEXT,
    "sha256" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "FindingEvidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FindingReview" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "previousValue" JSONB,
    "newValue" JSONB,
    "explanation" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "FindingReview_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AttackPath" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "confidence" "Confidence" NOT NULL,
    "nodes" JSONB NOT NULL,
    "edges" JSONB NOT NULL,
    "impact" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AttackPath_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Retest" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "findingId" TEXT,
    "status" "RetestStatus" NOT NULL DEFAULT 'QUEUED',
    "previousEvidence" JSONB,
    "newEvidence" JSONB,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Retest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScannerTool" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "capabilities" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScannerTool_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScannerRule" (
    "id" TEXT NOT NULL,
    "toolId" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "configuration" JSONB,

    CONSTRAINT "ScannerRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Report" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "type" "ReportType" NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'READY',
    "path" TEXT,
    "sha256" TEXT,
    "size" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Report_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EvidenceArtifact" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "storageKey" TEXT NOT NULL,
    "sha256" TEXT NOT NULL,
    "size" INTEGER NOT NULL,
    "contentType" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),

    CONSTRAINT "EvidenceArtifact_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanNotification" (
    "id" TEXT NOT NULL,
    "scanId" TEXT,
    "scheduleId" TEXT,
    "type" "NotificationType" NOT NULL,
    "status" "NotificationDeliveryStatus" NOT NULL DEFAULT 'NOT_CONFIGURED',
    "toEmail" TEXT,
    "subject" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "metadata" JSONB,
    "sentAt" TIMESTAMP(3),
    "error" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScanNotification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UploadedArtifact" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "storageKey" TEXT NOT NULL,
    "sha256" TEXT NOT NULL,
    "size" INTEGER NOT NULL,
    "contentType" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UploadedArtifact_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ContactEnquiry" (
    "id" TEXT NOT NULL,
    "fullName" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "company" TEXT,
    "role" TEXT,
    "enquiryType" "ContactEnquiryType" NOT NULL,
    "websiteUrl" TEXT,
    "estimatedWebsiteCount" INTEGER,
    "preferredScanDepth" "ContactScanDepth",
    "message" TEXT NOT NULL,
    "consentAt" TIMESTAMP(3) NOT NULL,
    "status" "ContactEnquiryStatus" NOT NULL DEFAULT 'NEW',
    "sourcePage" TEXT NOT NULL,
    "ipHash" TEXT,
    "userAgent" TEXT,
    "messageHash" TEXT NOT NULL,
    "assignedAdminId" TEXT,
    "adminNotes" TEXT,
    "emailDeliveryStatus" "ContactEmailStatus" NOT NULL DEFAULT 'NOT_CONFIGURED',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ContactEnquiry_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "action" TEXT NOT NULL,
    "resourceType" TEXT NOT NULL,
    "resourceId" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SystemSetting" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "value" JSONB NOT NULL,
    "encrypted" BOOLEAN NOT NULL DEFAULT false,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SystemSetting_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WorkerJob" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "queueJobId" TEXT NOT NULL,
    "workerType" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "lastError" TEXT,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "WorkerJob_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "Account_userId_idx" ON "Account"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "Account_provider_providerAccountId_key" ON "Account"("provider", "providerAccountId");

-- CreateIndex
CREATE UNIQUE INDEX "Session_sessionToken_key" ON "Session"("sessionToken");

-- CreateIndex
CREATE INDEX "Session_userId_idx" ON "Session"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "VerificationToken_identifier_token_key" ON "VerificationToken"("identifier", "token");

-- CreateIndex
CREATE INDEX "Scan_status_createdAt_idx" ON "Scan"("status", "createdAt");

-- CreateIndex
CREATE INDEX "Scan_normalizedHash_status_idx" ON "Scan"("normalizedHash", "status");

-- CreateIndex
CREATE INDEX "Scan_scheduleId_createdAt_idx" ON "Scan"("scheduleId", "createdAt");

-- CreateIndex
CREATE INDEX "Scan_userId_idx" ON "Scan"("userId");

-- CreateIndex
CREATE INDEX "ScanSchedule_enabled_nextRunAt_idx" ON "ScanSchedule"("enabled", "nextRunAt");

-- CreateIndex
CREATE INDEX "ScanSchedule_normalizedHash_idx" ON "ScanSchedule"("normalizedHash");

-- CreateIndex
CREATE INDEX "ScanSchedule_userId_idx" ON "ScanSchedule"("userId");

-- CreateIndex
CREATE INDEX "ScanTarget_scanId_inScope_idx" ON "ScanTarget"("scanId", "inScope");

-- CreateIndex
CREATE UNIQUE INDEX "ScanTarget_scanId_url_key" ON "ScanTarget"("scanId", "url");

-- CreateIndex
CREATE UNIQUE INDEX "ScanProfile_name_key" ON "ScanProfile"("name");

-- CreateIndex
CREATE INDEX "ScanStage_scanId_order_idx" ON "ScanStage"("scanId", "order");

-- CreateIndex
CREATE UNIQUE INDEX "ScanStage_scanId_key_key" ON "ScanStage"("scanId", "key");

-- CreateIndex
CREATE INDEX "Endpoint_scanId_tested_idx" ON "Endpoint"("scanId", "tested");

-- CreateIndex
CREATE UNIQUE INDEX "Endpoint_scanId_url_method_key" ON "Endpoint"("scanId", "url", "method");

-- CreateIndex
CREATE UNIQUE INDEX "Parameter_endpointId_name_location_key" ON "Parameter"("endpointId", "name", "location");

-- CreateIndex
CREATE INDEX "Service_scanId_idx" ON "Service"("scanId");

-- CreateIndex
CREATE UNIQUE INDEX "Technology_scanId_name_version_key" ON "Technology"("scanId", "name", "version");

-- CreateIndex
CREATE INDEX "Finding_scanId_severity_status_idx" ON "Finding"("scanId", "severity", "status");

-- CreateIndex
CREATE INDEX "Finding_cwe_idx" ON "Finding"("cwe");

-- CreateIndex
CREATE UNIQUE INDEX "Finding_scanId_fingerprint_key" ON "Finding"("scanId", "fingerprint");

-- CreateIndex
CREATE INDEX "FindingEvidence_findingId_idx" ON "FindingEvidence"("findingId");

-- CreateIndex
CREATE INDEX "FindingReview_findingId_createdAt_idx" ON "FindingReview"("findingId", "createdAt");

-- CreateIndex
CREATE INDEX "AttackPath_scanId_idx" ON "AttackPath"("scanId");

-- CreateIndex
CREATE INDEX "Retest_scanId_status_idx" ON "Retest"("scanId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "ScannerTool_name_key" ON "ScannerTool"("name");

-- CreateIndex
CREATE UNIQUE INDEX "ScannerRule_toolId_externalId_version_key" ON "ScannerRule"("toolId", "externalId", "version");

-- CreateIndex
CREATE UNIQUE INDEX "Report_scanId_type_key" ON "Report"("scanId", "type");

-- CreateIndex
CREATE INDEX "EvidenceArtifact_scanId_type_idx" ON "EvidenceArtifact"("scanId", "type");

-- CreateIndex
CREATE INDEX "ScanNotification_scanId_type_idx" ON "ScanNotification"("scanId", "type");

-- CreateIndex
CREATE INDEX "ScanNotification_scheduleId_createdAt_idx" ON "ScanNotification"("scheduleId", "createdAt");

-- CreateIndex
CREATE INDEX "ScanNotification_status_createdAt_idx" ON "ScanNotification"("status", "createdAt");

-- CreateIndex
CREATE INDEX "ContactEnquiry_status_createdAt_idx" ON "ContactEnquiry"("status", "createdAt");

-- CreateIndex
CREATE INDEX "ContactEnquiry_enquiryType_createdAt_idx" ON "ContactEnquiry"("enquiryType", "createdAt");

-- CreateIndex
CREATE INDEX "ContactEnquiry_email_createdAt_idx" ON "ContactEnquiry"("email", "createdAt");

-- CreateIndex
CREATE INDEX "ContactEnquiry_ipHash_createdAt_idx" ON "ContactEnquiry"("ipHash", "createdAt");

-- CreateIndex
CREATE INDEX "ContactEnquiry_messageHash_createdAt_idx" ON "ContactEnquiry"("messageHash", "createdAt");

-- CreateIndex
CREATE INDEX "AuditLog_createdAt_idx" ON "AuditLog"("createdAt");

-- CreateIndex
CREATE INDEX "AuditLog_resourceType_resourceId_idx" ON "AuditLog"("resourceType", "resourceId");

-- CreateIndex
CREATE UNIQUE INDEX "SystemSetting_key_key" ON "SystemSetting"("key");

-- CreateIndex
CREATE UNIQUE INDEX "WorkerJob_queueJobId_key" ON "WorkerJob"("queueJobId");

-- CreateIndex
CREATE INDEX "WorkerJob_scanId_status_idx" ON "WorkerJob"("scanId", "status");

-- AddForeignKey
ALTER TABLE "Account" ADD CONSTRAINT "Account_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Session" ADD CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_scheduleId_fkey" FOREIGN KEY ("scheduleId") REFERENCES "ScanSchedule"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanSchedule" ADD CONSTRAINT "ScanSchedule_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanTarget" ADD CONSTRAINT "ScanTarget_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanStage" ADD CONSTRAINT "ScanStage_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Endpoint" ADD CONSTRAINT "Endpoint_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Parameter" ADD CONSTRAINT "Parameter_endpointId_fkey" FOREIGN KEY ("endpointId") REFERENCES "Endpoint"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Service" ADD CONSTRAINT "Service_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Technology" ADD CONSTRAINT "Technology_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FindingEvidence" ADD CONSTRAINT "FindingEvidence_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FindingEvidence" ADD CONSTRAINT "FindingEvidence_artifactId_fkey" FOREIGN KEY ("artifactId") REFERENCES "EvidenceArtifact"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FindingReview" ADD CONSTRAINT "FindingReview_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FindingReview" ADD CONSTRAINT "FindingReview_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AttackPath" ADD CONSTRAINT "AttackPath_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Retest" ADD CONSTRAINT "Retest_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Retest" ADD CONSTRAINT "Retest_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScannerRule" ADD CONSTRAINT "ScannerRule_toolId_fkey" FOREIGN KEY ("toolId") REFERENCES "ScannerTool"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Report" ADD CONSTRAINT "Report_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EvidenceArtifact" ADD CONSTRAINT "EvidenceArtifact_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanNotification" ADD CONSTRAINT "ScanNotification_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanNotification" ADD CONSTRAINT "ScanNotification_scheduleId_fkey" FOREIGN KEY ("scheduleId") REFERENCES "ScanSchedule"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ContactEnquiry" ADD CONSTRAINT "ContactEnquiry_assignedAdminId_fkey" FOREIGN KEY ("assignedAdminId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WorkerJob" ADD CONSTRAINT "WorkerJob_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

