-- CreateTable
CREATE TABLE "DomainApproval" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "normalizedHostname" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "proofToken" TEXT NOT NULL,
    "proofMethod" TEXT NOT NULL DEFAULT 'DNS_TXT',
    "proofValue" TEXT NOT NULL,
    "approvedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "notes" TEXT,
    "maxRequestsPerScan" INTEGER NOT NULL DEFAULT 250,
    "requestsPerMinute" INTEGER NOT NULL DEFAULT 60,
    "businessHoursEnabled" BOOLEAN NOT NULL DEFAULT false,
    "businessTimezone" TEXT NOT NULL DEFAULT 'Australia/Sydney',
    "businessDays" JSONB NOT NULL DEFAULT '[1,2,3,4,5]',
    "businessStart" TEXT NOT NULL DEFAULT '09:00',
    "businessEnd" TEXT NOT NULL DEFAULT '17:00',
    "excludedDangerousPayloads" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DomainApproval_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "DomainApproval_proofToken_key" ON "DomainApproval"("proofToken");

-- CreateIndex
CREATE INDEX "DomainApproval_normalizedHostname_status_idx" ON "DomainApproval"("normalizedHostname", "status");

-- CreateIndex
CREATE INDEX "DomainApproval_status_expiresAt_idx" ON "DomainApproval"("status", "expiresAt");

-- CreateIndex
CREATE INDEX "DomainApproval_userId_status_idx" ON "DomainApproval"("userId", "status");

-- AddForeignKey
ALTER TABLE "DomainApproval" ADD CONSTRAINT "DomainApproval_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

