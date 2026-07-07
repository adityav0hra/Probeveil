-- AlterTable
ALTER TABLE "Scan" ADD COLUMN     "profileId" TEXT;

-- AlterTable
ALTER TABLE "ScanProfile" ADD COLUMN     "alertThresholds" JSONB,
ADD COLUMN     "authConfig" JSONB,
ADD COLUMN     "cadence" "ScheduleCadence",
ADD COLUMN     "description" TEXT,
ADD COLUMN     "engines" JSONB,
ADD COLUMN     "features" JSONB,
ADD COLUMN     "slug" TEXT;

UPDATE "ScanProfile"
SET
  "alertThresholds" = '{"notifyAt":["HIGH","CRITICAL"],"failBuildAt":"CRITICAL","newFindingDiffs":true}'::jsonb,
  "authConfig" = '{"authenticated":false,"roleComparison":false,"routeSeeds":[]}'::jsonb,
  "description" = COALESCE("description", 'Baseline Probeveil scan policy.'),
  "engines" = CASE
    WHEN "mode" = 'QUICK' THEN '{"probeveilPassive":true,"browserCrawler":false,"apiSpecific":false,"nuclei":false,"zapBaseline":false,"tlsDiagnostics":true,"niktoStyle":false,"semgrepJs":false,"technologyChecks":true}'::jsonb
    WHEN "mode" = 'MAXIMUM' THEN '{"probeveilPassive":true,"browserCrawler":true,"apiSpecific":true,"nuclei":true,"zapBaseline":true,"tlsDiagnostics":true,"niktoStyle":true,"semgrepJs":true,"technologyChecks":true}'::jsonb
    ELSE '{"probeveilPassive":true,"browserCrawler":true,"apiSpecific":true,"nuclei":true,"zapBaseline":false,"tlsDiagnostics":true,"niktoStyle":true,"semgrepJs":true,"technologyChecks":true}'::jsonb
  END,
  "features" = CASE
    WHEN "mode" = 'QUICK' THEN '{"browserRendering":false,"apiDiscovery":false,"screenshots":false,"evidenceArchive":true}'::jsonb
    ELSE '{"browserRendering":true,"apiDiscovery":true,"screenshots":true,"evidenceArchive":true}'::jsonb
  END,
  "slug" = COALESCE(
    "slug",
    lower(regexp_replace(regexp_replace("name", '[^a-zA-Z0-9]+', '-', 'g'), '(^-|-$)', '', 'g'))
  );

ALTER TABLE "ScanProfile"
ALTER COLUMN "alertThresholds" SET NOT NULL,
ALTER COLUMN "authConfig" SET NOT NULL,
ALTER COLUMN "engines" SET NOT NULL,
ALTER COLUMN "features" SET NOT NULL,
ALTER COLUMN "slug" SET NOT NULL;

-- AlterTable
ALTER TABLE "ScanSchedule" ADD COLUMN     "profileId" TEXT;

-- CreateIndex
CREATE INDEX "Scan_profileId_idx" ON "Scan"("profileId");

-- CreateIndex
CREATE UNIQUE INDEX "ScanProfile_slug_key" ON "ScanProfile"("slug");

-- CreateIndex
CREATE INDEX "ScanSchedule_profileId_idx" ON "ScanSchedule"("profileId");

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_profileId_fkey" FOREIGN KEY ("profileId") REFERENCES "ScanProfile"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanSchedule" ADD CONSTRAINT "ScanSchedule_profileId_fkey" FOREIGN KEY ("profileId") REFERENCES "ScanProfile"("id") ON DELETE SET NULL ON UPDATE CASCADE;
