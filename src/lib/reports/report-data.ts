export type ReportScanData = {
  id: string;
  originalUrl: string;
  normalizedUrl: string;
  finalUrl?: string | null;
  normalizedHash?: string;
  mode: string;
  status: string;
  securityScore: number | null;
  coverageScore: number | null;
  createdAt: Date | string;
  startedAt?: Date | string | null;
  completedAt?: Date | string | null;
  error?: string | null;
  stages: Array<{
    key: string;
    label: string;
    status: string;
    progress?: number;
    message?: string | null;
    startedAt?: Date | string | null;
    completedAt?: Date | string | null;
  }>;
  endpoints: Array<{
    url: string;
    method?: string;
    statusCode?: number | null;
    contentType?: string | null;
    tested?: boolean;
    external?: boolean;
    discoveredBy?: string | null;
    parameters?: Array<{
      name: string;
      location: string;
      dataType?: string | null;
      tested?: boolean;
    }>;
  }>;
  services: Array<{
    host?: string;
    ip?: string | null;
    port?: number | null;
    protocol?: string;
    external?: boolean;
  }>;
  technologies: Array<{
    name: string;
    version?: string | null;
    category?: string | null;
    evidence?: string | null;
  }>;
  findings: Array<{
    id: string;
    issueId?: string | null;
    issue?: {
      id: string;
      status: string;
      occurrenceCount: number;
      firstSeenAt: Date | string;
      lastSeenAt: Date | string;
      lastResolvedAt?: Date | string | null;
    } | null;
    title: string;
    description: string;
    severity: string;
    confidence: string;
    status: string;
    category: string;
    cwe?: string | null;
    owaspCategory?: string | null;
    cvssScore?: number | null;
    affectedUrl?: string | null;
    httpMethod?: string | null;
    parameter?: string | null;
    component?: string | null;
    scannerRuleId?: string;
    scannerName?: string;
    detectedAt?: Date | string;
    impact: string;
    remediation: string;
    reproductionSteps: unknown;
    references?: unknown;
    retestInstructions?: string | null;
    evidence: Array<{
      id?: string;
      type?: string;
      title?: string;
      content?: string | null;
      sha256?: string;
      metadata?: unknown;
    }>;
  }>;
  attackPaths: Array<{
    id: string;
    title: string;
    confidence: string;
    nodes: unknown;
    edges: unknown;
    impact: string;
  }>;
};

export function canonicalScanUrl(
  scan: Pick<ReportScanData, "finalUrl" | "normalizedUrl">,
) {
  return scan.finalUrl || scan.normalizedUrl;
}

export function scanHostname(
  scan: Pick<ReportScanData, "finalUrl" | "normalizedUrl">,
) {
  try {
    return new URL(canonicalScanUrl(scan)).hostname;
  } catch {
    return "unknown-website";
  }
}
