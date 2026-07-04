import { domainToASCII } from "node:url";
import { getReportProductName } from "./report-version";
import { reportKindConfig, type SecurityReportKind } from "./report-types";

export function hostnameFromScanUrl(value: string | null | undefined) {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.hostname || null;
  } catch {
    try {
      const url = new URL(`https://${value}`);
      return url.hostname || null;
    } catch {
      return null;
    }
  }
}

export function sanitiseWebsiteName(hostname: string | null | undefined) {
  const ascii = domainToASCII(hostname ?? "").toLowerCase();
  const safe = ascii
    .replace(/^\.+|\.+$/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  return (safe || "unknown-website").slice(0, 90).replace(/-$/g, "");
}

export function reportDateStamp(value: Date | string | null | undefined) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime()))
    return new Date().toISOString().slice(0, 10);
  return date.toISOString().slice(0, 10);
}

export function buildReportFilename({
  completedAt,
  kind,
  productName = getReportProductName(),
  url,
}: {
  completedAt?: Date | string | null;
  kind: SecurityReportKind;
  productName?: string;
  url?: string | null;
}) {
  const product =
    productName
      .replace(/[^a-z0-9]+/gi, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "") || "Probeveil";
  const website = sanitiseWebsiteName(hostnameFromScanUrl(url));
  return `${product}-${website}-${reportKindConfig[kind].filenameLabel}-${reportDateStamp(completedAt)}.pdf`;
}

export function contentDisposition(filename: string) {
  const asciiFilename = filename.replace(/[^a-zA-Z0-9._-]/g, "-");
  return `attachment; filename="${asciiFilename}"; filename*=UTF-8''${encodeURIComponent(filename)}`;
}
