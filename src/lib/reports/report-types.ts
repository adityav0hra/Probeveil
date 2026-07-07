import type { ReportType as PrismaReportType } from "@prisma/client";

export type SecurityReportKind =
  | "executive"
  | "technical"
  | "owasp-top-10"
  | "cwe"
  | "pci-web-controls"
  | "soc2-evidence"
  | "executive-risk"
  | "remediation-tracking";

export const reportKindConfig = {
  executive: {
    label: "Executive Security Report",
    filenameLabel: "Executive-Security-Report",
    prismaType: "EXECUTIVE_HTML" as PrismaReportType,
  },
  technical: {
    label: "Full Technical Security Report",
    filenameLabel: "Full-Technical-Security-Report",
    prismaType: "TECHNICAL_HTML" as PrismaReportType,
  },
  "owasp-top-10": {
    label: "OWASP Top 10 Report",
    filenameLabel: "OWASP-Top-10-Report",
    prismaType: "OWASP_TOP_10" as PrismaReportType,
  },
  cwe: {
    label: "CWE Mapping Report",
    filenameLabel: "CWE-Mapping-Report",
    prismaType: "CWE" as PrismaReportType,
  },
  "pci-web-controls": {
    label: "PCI-Style Web Controls Report",
    filenameLabel: "PCI-Style-Web-Controls-Report",
    prismaType: "PCI_WEB_CONTROLS" as PrismaReportType,
  },
  "soc2-evidence": {
    label: "SOC 2 Evidence Support Report",
    filenameLabel: "SOC-2-Evidence-Support-Report",
    prismaType: "SOC2_EVIDENCE" as PrismaReportType,
  },
  "executive-risk": {
    label: "Executive Risk Summary",
    filenameLabel: "Executive-Risk-Summary",
    prismaType: "EXECUTIVE_RISK" as PrismaReportType,
  },
  "remediation-tracking": {
    label: "Remediation Tracking Report",
    filenameLabel: "Remediation-Tracking-Report",
    prismaType: "REMEDIATION_TRACKING" as PrismaReportType,
  },
} satisfies Record<
  SecurityReportKind,
  { filenameLabel: string; label: string; prismaType: PrismaReportType }
>;

export function parseReportKind(value: string | null): SecurityReportKind {
  if (value && value in reportKindConfig) return value as SecurityReportKind;
  return "technical";
}
