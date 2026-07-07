import { describe, expect, it } from "vitest";
import {
  comparableUrl,
  findingIdentityBasis,
  findingIdentityKey,
} from "@/lib/finding-identity/key";

describe("finding identity", () => {
  it("normalizes equivalent finding locations into the same identity", () => {
    const first = findingIdentityKey({
      affectedUrl: "https://Example.com/admin#ignored",
      category: "Security headers",
      parameter: " returnUrl ",
      scannerRuleId: " missing-csp ",
      title: "Missing   CSP",
    });
    const second = findingIdentityKey({
      affectedUrl: "https://example.com/admin",
      category: "security headers",
      parameter: "returnurl",
      scannerRuleId: "MISSING-CSP",
      title: "missing csp",
    });

    expect(first).toBe(second);
  });

  it("keeps meaningfully different affected locations separate", () => {
    const admin = findingIdentityBasis({
      affectedUrl: "https://example.com/admin",
      category: "Security headers",
      scannerRuleId: "missing-csp",
      title: "Missing CSP",
    });
    const exportRoute = findingIdentityBasis({
      affectedUrl: "https://example.com/export",
      category: "Security headers",
      scannerRuleId: "missing-csp",
      title: "Missing CSP",
    });

    expect(admin).not.toBe(exportRoute);
  });

  it("strips URL fragments before comparison", () => {
    expect(comparableUrl("https://example.com/path?a=1#section")).toBe(
      "example.com/path?a=1",
    );
  });
});
