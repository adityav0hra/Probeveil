-- CreateEnum
CREATE TYPE "IntegrationProvider" AS ENUM ('SLACK', 'DISCORD', 'TEAMS', 'JIRA', 'LINEAR', 'GITHUB', 'EMAIL');

-- CreateEnum
CREATE TYPE "IntegrationEventType" AS ENUM ('SCAN_SUMMARY', 'FAILED_SCAN', 'HIGH_SEVERITY_ALERT', 'HIGH_SEVERITY_FINDING');

-- CreateEnum
CREATE TYPE "IntegrationDeliveryStatus" AS ENUM ('NOT_CONFIGURED', 'SENT', 'FAILED', 'SKIPPED');

-- CreateTable
CREATE TABLE "IntegrationDelivery" (
    "id" TEXT NOT NULL,
    "scanId" TEXT,
    "findingId" TEXT,
    "provider" "IntegrationProvider" NOT NULL,
    "eventType" "IntegrationEventType" NOT NULL,
    "status" "IntegrationDeliveryStatus" NOT NULL DEFAULT 'NOT_CONFIGURED',
    "target" TEXT,
    "subject" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "externalId" TEXT,
    "externalUrl" TEXT,
    "responseStatus" INTEGER,
    "error" TEXT,
    "sentAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IntegrationDelivery_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "IntegrationDelivery_scanId_eventType_idx" ON "IntegrationDelivery"("scanId", "eventType");

-- CreateIndex
CREATE INDEX "IntegrationDelivery_findingId_provider_eventType_idx" ON "IntegrationDelivery"("findingId", "provider", "eventType");

-- CreateIndex
CREATE INDEX "IntegrationDelivery_provider_status_createdAt_idx" ON "IntegrationDelivery"("provider", "status", "createdAt");

-- AddForeignKey
ALTER TABLE "IntegrationDelivery" ADD CONSTRAINT "IntegrationDelivery_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IntegrationDelivery" ADD CONSTRAINT "IntegrationDelivery_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

