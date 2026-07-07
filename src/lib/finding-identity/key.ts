import { createHash } from "node:crypto";

export type FindingIdentityInput = {
  affectedUrl?: string | null;
  category?: string | null;
  parameter?: string | null;
  scannerRuleId: string;
  title: string;
};

export function findingIdentityKey(finding: FindingIdentityInput) {
  return createHash("sha256")
    .update(findingIdentityBasis(finding))
    .digest("hex");
}

export function findingIdentityBasis(finding: FindingIdentityInput) {
  return [
    normalizeText(finding.scannerRuleId),
    comparableUrl(finding.affectedUrl),
    normalizeText(finding.parameter),
    normalizeText(finding.category),
    normalizeText(finding.title),
  ].join("|");
}

export function comparableUrl(value?: string | null) {
  if (!value) return "";
  try {
    const url = new URL(value);
    url.hash = "";
    return `${url.hostname.toLowerCase()}${url.pathname}${url.search}`;
  } catch {
    return normalizeText(value);
  }
}

function normalizeText(value?: string | null) {
  return value?.trim().toLowerCase().replace(/\s+/g, " ") ?? "";
}
