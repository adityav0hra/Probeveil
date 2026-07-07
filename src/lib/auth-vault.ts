import "server-only";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import { z } from "zod";

const aad = Buffer.from("probeveil.auth-credential-profile.v1");

export const credentialRoleValues = [
  "CUSTOM",
  "NORMAL_USER",
  "ADMIN",
  "USER_A",
  "USER_B",
] as const;

export const vaultPayloadSchema = z.object({
  authHeader: z.string().trim().max(2000).default(""),
  contextName: z.string().trim().max(120).default(""),
  cookieHeader: z.string().trim().max(4000).default(""),
  expectedText: z.string().trim().max(500).default(""),
  routeSeeds: z.array(z.string().trim().min(1).max(2048)).max(60).default([]),
  verificationPath: z.string().trim().max(2048).default(""),
});

export type VaultPayload = z.infer<typeof vaultPayloadSchema>;

export function encryptVaultPayload(payload: VaultPayload) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", vaultKey(), iv);
  cipher.setAAD(aad);
  const plaintext = Buffer.from(
    JSON.stringify(vaultPayloadSchema.parse(payload)),
  );
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ["v1", b64(iv), b64(tag), b64(encrypted)].join(":");
}

export function decryptVaultPayload(value: string): VaultPayload {
  const [version, iv, tag, encrypted] = value.split(":");
  if (version !== "v1" || !iv || !tag || !encrypted)
    throw new Error("Unsupported credential payload format.");
  const decipher = createDecipheriv("aes-256-gcm", vaultKey(), ub64(iv));
  decipher.setAAD(aad);
  decipher.setAuthTag(ub64(tag));
  const plaintext = Buffer.concat([
    decipher.update(ub64(encrypted)),
    decipher.final(),
  ]);
  return vaultPayloadSchema.parse(JSON.parse(plaintext.toString("utf8")));
}

export function payloadFingerprint(payload: VaultPayload) {
  const parsed = vaultPayloadSchema.parse(payload);
  return createHash("sha256")
    .update(
      JSON.stringify({
        authHeader: parsed.authHeader ? hashSecret(parsed.authHeader) : "",
        cookieHeader: parsed.cookieHeader
          ? hashSecret(parsed.cookieHeader)
          : "",
        contextName: parsed.contextName,
        routeSeeds: parsed.routeSeeds,
        verificationPath: parsed.verificationPath,
      }),
    )
    .digest("hex");
}

export function authHeadersFromPayload(payload: VaultPayload) {
  return {
    ...(payload.authHeader ? { authorization: payload.authHeader } : {}),
    ...(payload.cookieHeader ? { cookie: payload.cookieHeader } : {}),
  };
}

export function authOptionsFromPayload(payload: VaultPayload) {
  return {
    ...(payload.contextName ? { contextName: payload.contextName } : {}),
    ...(payload.expectedText ? { expectedText: payload.expectedText } : {}),
    ...(payload.verificationPath
      ? { verificationPath: payload.verificationPath }
      : {}),
    routeSeeds: payload.routeSeeds,
  };
}

export function routeSeedsFromVaultText(value: string) {
  return [
    ...new Set(
      value
        .split(/\r?\n|,/)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ].slice(0, 60);
}

export function normalizeTargetOrigin(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return { hostname: null, origin: null };
  const withProtocol = /^[a-z][a-z\d+.-]*:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;
  const url = new URL(withProtocol);
  if (!["http:", "https:"].includes(url.protocol))
    throw new Error("Credential profiles require an HTTP or HTTPS target.");
  url.pathname = "/";
  url.search = "";
  url.hash = "";
  url.username = "";
  url.password = "";
  return { hostname: url.hostname.toLowerCase(), origin: url.origin };
}

function vaultKey() {
  const explicit = process.env.PROBEVEIL_VAULT_KEY;
  if (explicit) {
    const raw = explicit.startsWith("base64:")
      ? Buffer.from(explicit.slice(7), "base64")
      : /^[a-f0-9]{64}$/i.test(explicit)
        ? Buffer.from(explicit, "hex")
        : Buffer.from(explicit);
    return raw.length === 32 ? raw : createHash("sha256").update(raw).digest();
  }
  const fallback =
    process.env.AUTH_SECRET ??
    process.env.NEXTAUTH_SECRET ??
    process.env.WORKER_SIGNING_SECRET;
  if (!fallback && process.env.NODE_ENV === "production")
    throw new Error(
      "Set PROBEVEIL_VAULT_KEY or AUTH_SECRET before using the credential vault.",
    );
  return createHash("sha256")
    .update(fallback ?? "development-only-probeveil-vault-key")
    .digest();
}

function hashSecret(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function b64(value: Buffer) {
  return value.toString("base64url");
}

function ub64(value: string) {
  return Buffer.from(value, "base64url");
}
