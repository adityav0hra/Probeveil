type ScoredFinding = { severity: string; confidence: string };
const weights: Record<string, number> = { CRITICAL: 30, HIGH: 18, MEDIUM: 9, LOW: 3, INFO: 0 };
const confidence: Record<string, number> = { CONFIRMED: 1, HIGH: .9, PROBABLE: .7, POTENTIAL: .45, INFORMATIONAL: .2, MANUAL_REVIEW: .35 };

export function calculateSecurityScore(findings: ScoredFinding[]) {
  const risk = findings.reduce((sum, f) => sum + (weights[f.severity] ?? 0) * (confidence[f.confidence] ?? .5), 0);
  return Math.max(0, Math.round(100 - Math.min(100, risk)));
}

export function calculateCoverageScore(input: { completedStages: number; totalStages: number; endpointsTested: number; endpointsDiscovered: number }) {
  const stage = input.totalStages ? input.completedStages / input.totalStages : 0;
  const endpoint = input.endpointsDiscovered ? input.endpointsTested / input.endpointsDiscovered : 0;
  return Math.round(Math.min(1, stage * .7 + endpoint * .3) * 100);
}
