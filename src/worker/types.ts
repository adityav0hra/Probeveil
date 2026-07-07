export type ScanJob = {
  auth?: {
    contextName?: string;
    expectedText?: string;
    routeSeeds?: string[];
    verificationPath?: string;
  };
  authHeaders?: Record<string, string>;
  comparisonProfiles?: Array<{
    authHeaders?: Record<string, string>;
    name: string;
    role: "ANONYMOUS" | "NORMAL_USER" | "ADMIN" | "USER_A" | "USER_B" | "CUSTOM";
  }>;
  features?: {
    apiDiscovery?: boolean;
    browserRendering?: boolean;
    screenshots?: boolean;
  };
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
