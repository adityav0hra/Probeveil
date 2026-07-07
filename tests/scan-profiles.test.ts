import { describe, expect, it } from "vitest";
import {
  defaultScanProfiles,
  scanPolicyFromProfile,
} from "@/lib/scan-profiles";

describe("scan profiles", () => {
  it("defines the professional default policy set", () => {
    expect(defaultScanProfiles.map((profile) => profile.name)).toEqual([
      "Light weekly",
      "Deep monthly",
      "Authenticated app",
      "API heavy",
      "Compliance evidence",
    ]);
  });

  it("parses profile JSON into typed policy controls", () => {
    const source = defaultScanProfiles.find(
      (profile) => profile.slug === "authenticated-app",
    )!;
    const policy = scanPolicyFromProfile({
      alertThresholds: source.alertThresholds,
      authConfig: source.authConfig,
      cadence: source.cadence ?? null,
      description: source.description,
      engines: source.engines,
      features: source.features,
      id: "profile_1",
      limits: source.limits,
      mode: source.mode,
      name: source.name,
      slug: source.slug,
      stageConfig: source.stageConfig,
    });

    expect(policy.mode).toBe("MAXIMUM");
    expect(policy.authConfig.authenticated).toBe(true);
    expect(policy.authConfig.roleComparison).toBe(true);
    expect(policy.features.browserRendering).toBe(true);
    expect(policy.features.screenshots).toBe(true);
    expect(policy.engines.zapBaseline).toBe(true);
    expect(policy.limits.maxRoutes).toBe(300);
    expect(policy.alertThresholds.notifyAt).toContain("HIGH");
  });
});
