-- CreateTable
CREATE TABLE "AuthCredentialProfile" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'CUSTOM',
    "targetOrigin" TEXT,
    "targetHostname" TEXT,
    "encryptedPayload" TEXT NOT NULL,
    "payloadFingerprint" TEXT NOT NULL,
    "verificationPath" TEXT,
    "expectedTextConfigured" BOOLEAN NOT NULL DEFAULT false,
    "routeSeedCount" INTEGER NOT NULL DEFAULT 0,
    "expiresAt" TIMESTAMP(3),
    "reminderDaysBefore" INTEGER NOT NULL DEFAULT 7,
    "lastValidatedAt" TIMESTAMP(3),
    "lastValidationStatus" TEXT,
    "lastValidationScanId" TEXT,
    "lastValidationMessage" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AuthCredentialProfile_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AuthCredentialProfile_enabled_expiresAt_idx" ON "AuthCredentialProfile"("enabled", "expiresAt");

-- CreateIndex
CREATE INDEX "AuthCredentialProfile_targetHostname_idx" ON "AuthCredentialProfile"("targetHostname");

-- CreateIndex
CREATE INDEX "AuthCredentialProfile_userId_enabled_idx" ON "AuthCredentialProfile"("userId", "enabled");

-- AddForeignKey
ALTER TABLE "AuthCredentialProfile" ADD CONSTRAINT "AuthCredentialProfile_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

