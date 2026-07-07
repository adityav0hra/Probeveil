-- CreateEnum
CREATE TYPE "AssetKind" AS ENUM ('DOMAIN', 'ENDPOINT', 'API', 'LOGIN_PAGE', 'ADMIN_ROUTE', 'TECHNOLOGY', 'SERVICE');

-- CreateEnum
CREATE TYPE "AssetStatus" AS ENUM ('ACTIVE', 'MISSING');

-- CreateEnum
CREATE TYPE "AssetEventType" AS ENUM ('DISCOVERED', 'OBSERVED', 'CHANGED', 'MISSING');

-- CreateTable
CREATE TABLE "AssetInventoryItem" (
    "id" TEXT NOT NULL,
    "normalizedHash" TEXT NOT NULL,
    "identityKey" TEXT NOT NULL,
    "kind" "AssetKind" NOT NULL,
    "status" "AssetStatus" NOT NULL DEFAULT 'ACTIVE',
    "label" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "url" TEXT,
    "hostname" TEXT,
    "method" TEXT,
    "port" INTEGER,
    "protocol" TEXT,
    "technologyName" TEXT,
    "technologyVersion" TEXT,
    "metadata" JSONB,
    "firstSeenAt" TIMESTAMP(3) NOT NULL,
    "lastSeenAt" TIMESTAMP(3) NOT NULL,
    "lastChangedAt" TIMESTAMP(3),
    "lastMissingAt" TIMESTAMP(3),
    "lastScanId" TEXT,
    "observationCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AssetInventoryItem_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AssetInventoryEvent" (
    "id" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "scanId" TEXT,
    "eventType" "AssetEventType" NOT NULL,
    "previousStatus" "AssetStatus",
    "nextStatus" "AssetStatus" NOT NULL,
    "summary" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AssetInventoryEvent_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AssetInventoryItem_normalizedHash_status_idx" ON "AssetInventoryItem"("normalizedHash", "status");

-- CreateIndex
CREATE INDEX "AssetInventoryItem_kind_status_lastSeenAt_idx" ON "AssetInventoryItem"("kind", "status", "lastSeenAt");

-- CreateIndex
CREATE INDEX "AssetInventoryItem_hostname_idx" ON "AssetInventoryItem"("hostname");

-- CreateIndex
CREATE UNIQUE INDEX "AssetInventoryItem_normalizedHash_kind_identityKey_key" ON "AssetInventoryItem"("normalizedHash", "kind", "identityKey");

-- CreateIndex
CREATE INDEX "AssetInventoryEvent_assetId_createdAt_idx" ON "AssetInventoryEvent"("assetId", "createdAt");

-- CreateIndex
CREATE INDEX "AssetInventoryEvent_scanId_eventType_idx" ON "AssetInventoryEvent"("scanId", "eventType");

-- CreateIndex
CREATE INDEX "AssetInventoryEvent_eventType_createdAt_idx" ON "AssetInventoryEvent"("eventType", "createdAt");

-- AddForeignKey
ALTER TABLE "AssetInventoryItem" ADD CONSTRAINT "AssetInventoryItem_lastScanId_fkey" FOREIGN KEY ("lastScanId") REFERENCES "Scan"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AssetInventoryEvent" ADD CONSTRAINT "AssetInventoryEvent_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "AssetInventoryItem"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AssetInventoryEvent" ADD CONSTRAINT "AssetInventoryEvent_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE SET NULL ON UPDATE CASCADE;

