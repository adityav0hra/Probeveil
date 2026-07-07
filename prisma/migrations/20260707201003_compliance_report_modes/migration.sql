-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "ReportType" ADD VALUE 'OWASP_TOP_10';
ALTER TYPE "ReportType" ADD VALUE 'CWE';
ALTER TYPE "ReportType" ADD VALUE 'PCI_WEB_CONTROLS';
ALTER TYPE "ReportType" ADD VALUE 'SOC2_EVIDENCE';
ALTER TYPE "ReportType" ADD VALUE 'EXECUTIVE_RISK';
ALTER TYPE "ReportType" ADD VALUE 'REMEDIATION_TRACKING';

