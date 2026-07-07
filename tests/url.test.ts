import { describe, expect, it } from "vitest";
import { createScanSchema, normalizeUrlInput, urlFingerprint } from "@/lib/url";
describe("URL normalisation", () => {
  it("trims and adds HTTPS", () =>
    expect(normalizeUrlInput("  Example.COM/path  ")).toBe(
      "https://example.com/path",
    ));
  it("removes fragments and default ports", () =>
    expect(normalizeUrlInput("https://EXAMPLE.com:443/a#secret")).toBe(
      "https://example.com/a",
    ));
  it("rejects credentials", () =>
    expect(() => normalizeUrlInput("https://user:pass@example.com")).toThrow(
      /credentials/,
    ));
  it("rejects non-web protocols", () =>
    expect(() => normalizeUrlInput("file:///etc/passwd")).toThrow(/HTTP/));
  it("creates stable fingerprints", () =>
    expect(urlFingerprint("https://example.com")).toBe(
      urlFingerprint("https://example.com"),
    ));
  it("accepts authenticated scan options", () => {
    const parsed = createScanSchema.parse({
      apiDiscovery: "on",
      authContextName: "Admin session",
      authCredentialProfileId: "cred_primary",
      authExpectedText: "Dashboard",
      authHeader: "Bearer token",
      authRouteSeeds: "/dashboard\n/settings",
      authVerificationPath: "/dashboard",
      cookieHeader: "sid=abc",
      normalUserCredentialProfileId: "cred_normal",
      normalUserCookieHeader: "sid=normal",
      adminUserCredentialProfileId: "cred_admin",
      adminUserCookieHeader: "sid=admin",
      userACredentialProfileId: "cred_a",
      userACookieHeader: "sid=user-a",
      userBCredentialProfileId: "cred_b",
      userBCookieHeader: "sid=user-b",
      mode: "FULL",
      url: "https://example.com",
    });
    expect(parsed.apiDiscovery).toBe(true);
    expect(parsed.adminUserCookieHeader).toBe("sid=admin");
    expect(parsed.authCredentialProfileId).toBe("cred_primary");
    expect(parsed.userBCredentialProfileId).toBe("cred_b");
    expect(parsed.authVerificationPath).toBe("/dashboard");
    expect(parsed.authRouteSeeds).toContain("/settings");
  });
});
