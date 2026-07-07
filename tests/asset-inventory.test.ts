import { AssetKind } from "@prisma/client";
import { describe, expect, it } from "vitest";
import {
  assetIdentityBasis,
  assetIdentityKey,
  normalizeAssetUrl,
} from "@/lib/asset-inventory/key";

describe("asset inventory identity", () => {
  it("normalizes equivalent endpoint URLs before identity generation", () => {
    const first = assetIdentityKey({
      kind: AssetKind.ENDPOINT,
      method: "get",
      value: normalizeAssetUrl("https://Example.com/admin/#section"),
    });
    const second = assetIdentityKey({
      kind: AssetKind.ENDPOINT,
      method: "GET",
      value: normalizeAssetUrl("https://example.com/admin"),
    });

    expect(first).toBe(second);
  });

  it("keeps service ports and protocols separate", () => {
    const https = assetIdentityBasis({
      kind: AssetKind.SERVICE,
      port: 443,
      protocol: "https",
      value: "example.com",
    });
    const http = assetIdentityBasis({
      kind: AssetKind.SERVICE,
      port: 80,
      protocol: "http",
      value: "example.com",
    });

    expect(https).not.toBe(http);
  });

  it("removes URL fragments from inventory URLs", () => {
    expect(normalizeAssetUrl("https://example.com/login/#form")).toBe(
      "https://example.com/login",
    );
  });
});
