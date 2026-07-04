export type ScanJob = {
  scanId: string;
  url: string;
  mode: "QUICK" | "FULL" | "MAXIMUM";
  token: string;
};
export type FindingInput = {
  scannerName?: string;
  scannerVersion?: string;
  title: string;
  description: string;
  category: string;
  cwe?: string;
  owaspCategory?: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  confidence:
    | "CONFIRMED"
    | "HIGH"
    | "PROBABLE"
    | "POTENTIAL"
    | "INFORMATIONAL"
    | "MANUAL_REVIEW";
  affectedUrl?: string;
  httpMethod?: string;
  parameter?: string;
  payload?: string;
  scannerRuleId: string;
  fingerprint: string;
  impact: string;
  remediation: string;
  reproductionSteps: string[];
  references: string[];
  evidence: Array<{ type: string; title: string; content: string }>;
};
