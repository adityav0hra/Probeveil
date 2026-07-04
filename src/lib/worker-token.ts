import { createHmac, timingSafeEqual } from "node:crypto";

export function signWorkerToken(scanId: string, issuedAt = Date.now()) {
  const body = `${scanId}.${issuedAt}`;
  const signature = createHmac("sha256", process.env.WORKER_SIGNING_SECRET ?? "development-only-worker-secret").update(body).digest("hex");
  return `${body}.${signature}`;
}

export function verifyWorkerToken(token: string, scanId: string, maxAgeMs = 6 * 60 * 60 * 1000) {
  const [id, timestamp, signature] = token.split(".");
  if (id !== scanId || !timestamp || !signature || Math.abs(Date.now() - Number(timestamp)) > maxAgeMs) return false;
  const expected = signWorkerToken(id, Number(timestamp)).split(".").at(-1)!;
  return signature.length === expected.length && timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}
