import { describe, expect, it } from "vitest";
import { normalizeUrlInput, urlFingerprint } from "@/lib/url";
describe("URL normalisation", () => {
  it("trims and adds HTTPS", () => expect(normalizeUrlInput("  Example.COM/path  ")).toBe("https://example.com/path"));
  it("removes fragments and default ports", () => expect(normalizeUrlInput("https://EXAMPLE.com:443/a#secret")).toBe("https://example.com/a"));
  it("rejects credentials", () => expect(() => normalizeUrlInput("https://user:pass@example.com")).toThrow(/credentials/));
  it("rejects non-web protocols", () => expect(() => normalizeUrlInput("file:///etc/passwd")).toThrow(/HTTP/));
  it("creates stable fingerprints", () => expect(urlFingerprint("https://example.com")).toBe(urlFingerprint("https://example.com")));
});
