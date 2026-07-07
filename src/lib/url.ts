import { createHash } from "node:crypto";
import { z } from "zod";

export const scanModeSchema = z.enum(["QUICK", "FULL", "MAXIMUM"]);
export const createScanSchema = z.object({
  apiDiscovery: z
    .union([z.literal("on"), z.boolean()])
    .optional()
    .transform(Boolean),
  authContextName: z.string().trim().max(120).optional().default(""),
  authExpectedText: z.string().trim().max(500).optional().default(""),
  authHeader: z.string().trim().max(2000).optional().default(""),
  authRouteSeeds: z.string().trim().max(6000).optional().default(""),
  authVerificationPath: z.string().trim().max(2048).optional().default(""),
  browserRendering: z
    .union([z.literal("on"), z.boolean()])
    .optional()
    .transform(Boolean),
  cookieHeader: z.string().trim().max(4000).optional().default(""),
  mode: scanModeSchema,
  screenshotCapture: z
    .union([z.literal("on"), z.boolean()])
    .optional()
    .transform(Boolean),
  url: z.string().trim().min(1).max(2048),
});

export function normalizeUrlInput(input: string) {
  let value = input.trim();
  if (!/^[a-z][a-z\d+.-]*:\/\//i.test(value)) value = `https://${value}`;
  let url: URL;
  try { url = new URL(value); } catch { throw new Error("Enter a valid website URL."); }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error("Only HTTP and HTTPS websites can be scanned.");
  if (url.username || url.password) throw new Error("URLs containing credentials are not accepted.");
  if (!url.hostname || url.hostname.length > 253) throw new Error("Enter a valid hostname.");
  url.hash = "";
  url.hostname = url.hostname.toLowerCase();
  if ((url.protocol === "https:" && url.port === "443") || (url.protocol === "http:" && url.port === "80")) url.port = "";
  if (url.pathname === "") url.pathname = "/";
  return url.toString();
}

export function urlFingerprint(url: string) { return createHash("sha256").update(url).digest("hex"); }

export function isSameOriginOrSubdomain(candidate: URL, root: URL) {
  return candidate.hostname === root.hostname || candidate.hostname.endsWith(`.${root.hostname}`);
}
