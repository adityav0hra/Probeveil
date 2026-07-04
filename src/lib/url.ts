import { createHash } from "node:crypto";
import { z } from "zod";

export const scanModeSchema = z.enum(["QUICK", "FULL", "MAXIMUM"]);
export const createScanSchema = z.object({ url: z.string().trim().min(1).max(2048), mode: scanModeSchema });

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
