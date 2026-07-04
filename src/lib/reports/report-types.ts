import type { ReportType as PrismaReportType } from "@prisma/client";

export type SecurityReportKind = "executive" | "technical";

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
} satisfies Record<
  SecurityReportKind,
  { filenameLabel: string; label: string; prismaType: PrismaReportType }
>;

export function parseReportKind(value: string | null): SecurityReportKind {
  return value === "executive" ? "executive" : "technical";
}
