import { createHash } from "node:crypto";
import type { AssetKind } from "@prisma/client";

export type AssetIdentityInput = {
  kind: AssetKind;
  method?: string | null;
  port?: number | null;
  protocol?: string | null;
  value: string;
};

export function assetIdentityKey(input: AssetIdentityInput) {
  return createHash("sha256").update(assetIdentityBasis(input)).digest("hex");
}

export function assetIdentityBasis(input: AssetIdentityInput) {
  return [
    input.kind,
    normalizeValue(input.value),
    input.method?.trim().toUpperCase() ?? "",
    input.protocol?.trim().toLowerCase() ?? "",
    input.port ?? "",
  ].join("|");
}

export function normalizeAssetUrl(value: string) {
  try {
    const url = new URL(value);
    url.hash = "";
    if (url.pathname !== "/" && url.pathname.endsWith("/"))
      url.pathname = url.pathname.replace(/\/+$/, "");
    return url.toString();
  } catch {
    return normalizeValue(value);
  }
}

function normalizeValue(value: string) {
  return value.trim().toLowerCase().replace(/\s+/g, " ");
}
