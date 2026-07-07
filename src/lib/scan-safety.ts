import "server-only";
import { randomBytes } from "node:crypto";
import { promises as dns } from "node:dns";
import type { DomainApproval } from "@prisma/client";
import { db } from "@/lib/db";
export {
  assertBusinessWindow,
  dangerousPayloadClasses,
  isWithinBusinessWindow,
  type ScanSafetyPolicy,
} from "./scan-safety-shared";
import {
  dangerousPayloadClasses,
  type ScanSafetyPolicy,
} from "./scan-safety-shared";

export function generateProofToken() {
  return `probeveil-verify-${randomBytes(18).toString("base64url")}`;
}

export function normalizeApprovalHostname(value: string) {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed) throw new Error("Enter a hostname.");
  const url = /^[a-z][a-z\d+.-]*:\/\//i.test(trimmed)
    ? new URL(trimmed)
    : new URL(`https://${trimmed}`);
  if (!url.hostname) throw new Error("Enter a valid hostname.");
  return url.hostname.replace(/\.$/, "").toLowerCase();
}

export async function approvedDomainForUrl(url: string) {
  const hostname = new URL(url).hostname.toLowerCase();
  const candidates = hostnameCandidates(hostname);
  const approvals = await db.domainApproval.findMany({
    orderBy: { approvedAt: "desc" },
    where: {
      normalizedHostname: { in: candidates },
      status: "APPROVED",
    },
  });
  const now = Date.now();
  return approvals.find(
    (approval) => !approval.expiresAt || approval.expiresAt.getTime() > now,
  );
}

export function safetyPolicyFromApproval(
  approval: Pick<
    DomainApproval,
    | "businessDays"
    | "businessEnd"
    | "businessHoursEnabled"
    | "businessStart"
    | "businessTimezone"
    | "excludedDangerousPayloads"
    | "id"
    | "maxRequestsPerScan"
    | "requestsPerMinute"
  >,
  fallbackMaxRequests: number,
): ScanSafetyPolicy {
  return {
    approvalId: approval.id,
    businessHours: {
      days: dayValues(approval.businessDays),
      enabled: approval.businessHoursEnabled,
      end: approval.businessEnd,
      start: approval.businessStart,
      timezone: approval.businessTimezone,
    },
    excludedDangerousPayloadClasses: stringArray(
      approval.excludedDangerousPayloads,
      [...dangerousPayloadClasses],
    ),
    maxRequestsPerScan: clamp(
      approval.maxRequestsPerScan || fallbackMaxRequests,
      1,
      2500,
    ),
    requestsPerMinute: clamp(approval.requestsPerMinute || 60, 1, 600),
  };
}

export async function verifyDomainApprovalProof(approval: DomainApproval) {
  const expected = approval.proofToken;
  if (approval.proofMethod === "HTTP_FILE") {
    const url = `https://${approval.normalizedHostname}/.well-known/probeveil-ownership.txt`;
    const response = await fetch(url, {
      cache: "no-store",
      signal: AbortSignal.timeout(15_000),
    });
    const body = await response.text();
    return body.includes(expected);
  }
  const records = await dns
    .resolveTxt(`_probeveil.${approval.normalizedHostname}`)
    .catch(() => []);
  return records.flat().some((item) => item.includes(expected));
}

export function proofValueFor(hostname: string, method: string, token: string) {
  if (method === "HTTP_FILE")
    return `https://${hostname}/.well-known/probeveil-ownership.txt must contain: ${token}`;
  return `_probeveil.${hostname} TXT ${token}`;
}

function hostnameCandidates(hostname: string) {
  const parts = hostname.split(".");
  return parts.map((_, index) => parts.slice(index).join("."));
}

function stringArray(value: unknown, fallback: string[]) {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : fallback;
}

function dayValues(value: unknown) {
  return Array.isArray(value)
    ? value.filter((item): item is number => typeof item === "number")
    : [1, 2, 3, 4, 5];
}

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, Math.round(value)));
}
