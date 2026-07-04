import { describe, expect, it } from "vitest";
import { calculateCoverageScore, calculateSecurityScore } from "@/lib/scoring";
describe("scoring", () => {
  it("deducts risk by severity and confidence", () => { expect(calculateSecurityScore([])).toBe(100); expect(calculateSecurityScore([{ severity: "CRITICAL", confidence: "CONFIRMED" }])).toBe(70); });
  it("keeps coverage separate", () => expect(calculateCoverageScore({ completedStages: 8, totalStages: 10, endpointsTested: 5, endpointsDiscovered: 10 })).toBe(71));
});
