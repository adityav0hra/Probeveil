import { describe, expect, it } from "vitest";
import { assertAddressesAllowed, hostMatchesAllowlist, isPrivateAddress } from "@/lib/scope";
describe("scope policy", () => {
  it("detects private and reserved addresses", () => { expect(isPrivateAddress("127.0.0.1")).toBe(true); expect(isPrivateAddress("169.254.169.254")).toBe(true); expect(isPrivateAddress("8.8.8.8")).toBe(false); });
  it("matches exact hosts and suffixes", () => { expect(hostMatchesAllowlist("app.internal", [".internal"])).toBe(true); expect(hostMatchesAllowlist("evilinternal", [".internal"])).toBe(false); });
  it("blocks private addresses without explicit policy", () => expect(() => assertAddressesAllowed("localhost", ["127.0.0.1"], false)).toThrow(/private/));
  it("allows an explicitly allowlisted private target", () => { process.env.SCAN_ALLOWED_HOSTS = "localhost"; expect(() => assertAddressesAllowed("localhost", ["127.0.0.1"], true)).not.toThrow(); });
});
