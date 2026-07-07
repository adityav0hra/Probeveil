import type { Metadata } from "next";
import { revalidatePath } from "next/cache";
import { KeyRound, ShieldCheck, Trash2 } from "lucide-react";
import { requireRole } from "@/lib/auth";
import {
  authHeadersFromPayload,
  credentialRoleValues,
  decryptVaultPayload,
  encryptVaultPayload,
  normalizeTargetOrigin,
  payloadFingerprint,
  routeSeedsFromVaultText,
  vaultPayloadSchema,
} from "@/lib/auth-vault";
import { db } from "@/lib/db";

export const metadata: Metadata = { title: "Credential Vault" };

export default async function CredentialVaultPage() {
  await requireRole(["ADMIN"]);
  const profiles = await db.authCredentialProfile.findMany({
    include: { user: { select: { email: true, name: true } } },
    orderBy: [{ enabled: "desc" }, { updatedAt: "desc" }],
  });
  const now = Date.now();

  return (
    <div className="mx-auto max-w-6xl py-10">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Settings</p>
          <h1 className="mt-2 text-3xl font-semibold">Secrets vault</h1>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-500">
            Store encrypted authenticated scan profiles once, then reuse them
            across primary authenticated scans and role comparison.
          </p>
        </div>
        <div className="rounded-lg border border-line bg-white/[.025] px-4 py-3 text-xs text-slate-400">
          Secret values are encrypted and never displayed after saving.
        </div>
      </div>

      <section className="panel mt-8 p-5">
        <div className="flex items-center gap-2">
          <KeyRound size={18} className="text-signal" />
          <h2 className="text-lg font-semibold text-slate-100">
            Add credential profile
          </h2>
        </div>
        <form action={createCredentialProfile} className="mt-5 grid gap-4">
          <div className="grid gap-4 md:grid-cols-3">
            <label className="block">
              <span className="text-sm font-medium text-slate-200">Name</span>
              <input
                className="input mt-2"
                name="name"
                placeholder="Admin dashboard session"
                required
              />
            </label>
            <label className="block">
              <span className="text-sm font-medium text-slate-200">Role</span>
              <select className="input mt-2" name="role" defaultValue="CUSTOM">
                {credentialRoleValues.map((role) => (
                  <option key={role} value={role}>
                    {roleLabel(role)}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Target origin
              </span>
              <input
                className="input mt-2"
                name="targetOrigin"
                placeholder="https://example.com"
              />
            </label>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Authorization header
              </span>
              <input
                autoComplete="off"
                className="input mt-2"
                name="authHeader"
                placeholder="Bearer ey..."
                type="password"
              />
            </label>
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Cookie header
              </span>
              <input
                autoComplete="off"
                className="input mt-2"
                name="cookieHeader"
                placeholder="session=..."
                type="password"
              />
            </label>
          </div>
          <div className="grid gap-4 md:grid-cols-3">
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Context name
              </span>
              <input
                className="input mt-2"
                name="contextName"
                placeholder="Signed-in admin"
              />
            </label>
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Verification path
              </span>
              <input
                className="input mt-2"
                name="verificationPath"
                placeholder="/dashboard"
              />
            </label>
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Expected signed-in text
              </span>
              <input
                className="input mt-2"
                name="expectedText"
                placeholder="Dashboard, Account, Sign out"
              />
            </label>
          </div>
          <div className="grid gap-4 md:grid-cols-[1fr_220px_180px]">
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Authenticated route seeds
              </span>
              <textarea
                className="input mt-2 min-h-24 resize-y"
                name="routeSeeds"
                placeholder={"/dashboard\n/account\n/admin\n/settings"}
              />
            </label>
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Expires at
              </span>
              <input className="input mt-2" name="expiresAt" type="date" />
            </label>
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Reminder days
              </span>
              <input
                className="input mt-2"
                defaultValue="7"
                min="1"
                name="reminderDaysBefore"
                type="number"
              />
            </label>
          </div>
          <button className="button h-11 w-fit px-5" type="submit">
            <ShieldCheck size={16} />
            Save encrypted profile
          </button>
        </form>
      </section>

      <section className="panel mt-8 overflow-hidden p-0">
        <div className="border-b border-line p-5">
          <p className="eyebrow">Stored profiles</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-white/[.03] text-xs uppercase tracking-[.18em] text-slate-500">
              <tr>
                <th className="px-5 py-3">Profile</th>
                <th className="px-5 py-3">Expiry</th>
                <th className="px-5 py-3">Validation</th>
                <th className="px-5 py-3">Scope</th>
                <th className="px-5 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {profiles.map((profile) => {
                const expiresAt = profile.expiresAt?.getTime();
                const expired = Boolean(expiresAt && expiresAt < now);
                const expiring =
                  Boolean(expiresAt) &&
                  !expired &&
                  expiresAt! - now <=
                    profile.reminderDaysBefore * 24 * 60 * 60 * 1000;
                return (
                  <tr
                    className={!profile.enabled ? "opacity-45" : ""}
                    key={profile.id}
                  >
                    <td className="px-5 py-4">
                      <p className="font-medium text-slate-100">
                        {profile.name}
                      </p>
                      <p className="mt-1 text-xs text-slate-500">
                        {roleLabel(profile.role)} · by{" "}
                        {profile.user.name ?? profile.user.email}
                      </p>
                    </td>
                    <td className="px-5 py-4 text-xs text-slate-400">
                      <span
                        className={
                          expired
                            ? "text-red-300"
                            : expiring
                              ? "text-amber-200"
                              : "text-slate-400"
                        }
                      >
                        {profile.expiresAt
                          ? formatDate(profile.expiresAt)
                          : "No expiry"}
                      </span>
                      {expiring && <p className="mt-1">Renew soon</p>}
                    </td>
                    <td className="px-5 py-4 text-xs text-slate-400">
                      <p>{profile.lastValidationStatus ?? "Not validated"}</p>
                      <p className="mt-1">
                        {profile.lastValidatedAt
                          ? formatDateTime(profile.lastValidatedAt)
                          : "No validation run"}
                      </p>
                    </td>
                    <td className="px-5 py-4 text-xs text-slate-400">
                      <p>{profile.targetHostname ?? "Any target"}</p>
                      <p className="mt-1">
                        {profile.routeSeedCount} route seed
                        {profile.routeSeedCount === 1 ? "" : "s"} · expected
                        text {profile.expectedTextConfigured ? "set" : "unset"}
                      </p>
                    </td>
                    <td className="px-5 py-4">
                      <div className="flex flex-wrap gap-2">
                        <form action={validateCredentialProfile}>
                          <input name="id" type="hidden" value={profile.id} />
                          <button className="button-secondary px-3 py-2 text-xs">
                            Validate
                          </button>
                        </form>
                        {profile.enabled && (
                          <form action={disableCredentialProfile}>
                            <input name="id" type="hidden" value={profile.id} />
                            <button className="button-secondary px-3 py-2 text-xs">
                              <Trash2 size={13} />
                              Disable
                            </button>
                          </form>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
              {!profiles.length && (
                <tr>
                  <td
                    className="px-5 py-10 text-center text-slate-500"
                    colSpan={5}
                  >
                    No credential profiles stored yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

async function createCredentialProfile(formData: FormData) {
  "use server";
  const session = await requireRole(["ADMIN"]);
  const name = value(formData, "name");
  const role = credentialRoleValues.includes(value(formData, "role") as never)
    ? value(formData, "role")
    : "CUSTOM";
  const { hostname, origin } = normalizeTargetOrigin(
    value(formData, "targetOrigin"),
  );
  const payload = vaultPayloadSchema.parse({
    authHeader: value(formData, "authHeader"),
    contextName: value(formData, "contextName") || name,
    cookieHeader: value(formData, "cookieHeader"),
    expectedText: value(formData, "expectedText"),
    routeSeeds: routeSeedsFromVaultText(value(formData, "routeSeeds")),
    verificationPath: value(formData, "verificationPath"),
  });
  if (!payload.authHeader && !payload.cookieHeader)
    throw new Error("Add an Authorization header or Cookie header.");
  const expiresAt = value(formData, "expiresAt");
  const reminderDaysBefore = Math.max(
    1,
    Number(value(formData, "reminderDaysBefore") || 7),
  );
  const profile = await db.authCredentialProfile.create({
    data: {
      encryptedPayload: encryptVaultPayload(payload),
      expectedTextConfigured: Boolean(payload.expectedText),
      expiresAt: expiresAt ? new Date(`${expiresAt}T23:59:59.000Z`) : null,
      name,
      payloadFingerprint: payloadFingerprint(payload),
      reminderDaysBefore,
      role,
      routeSeedCount: payload.routeSeeds.length,
      targetHostname: hostname,
      targetOrigin: origin,
      userId: session.user.id,
      verificationPath: payload.verificationPath || null,
    },
  });
  await db.auditLog.create({
    data: {
      action: "CREDENTIAL_PROFILE_CREATED",
      metadata: {
        expectedTextConfigured: Boolean(payload.expectedText),
        routeSeedCount: payload.routeSeeds.length,
        targetHostname: hostname,
      },
      resourceId: profile.id,
      resourceType: "AuthCredentialProfile",
      userId: session.user.id,
    },
  });
  revalidatePath("/settings/vault");
  revalidatePath("/scans/new");
}

async function disableCredentialProfile(formData: FormData) {
  "use server";
  const session = await requireRole(["ADMIN"]);
  const id = value(formData, "id");
  await db.authCredentialProfile.update({
    data: { enabled: false },
    where: { id },
  });
  await db.auditLog.create({
    data: {
      action: "CREDENTIAL_PROFILE_DISABLED",
      resourceId: id,
      resourceType: "AuthCredentialProfile",
      userId: session.user.id,
    },
  });
  revalidatePath("/settings/vault");
  revalidatePath("/scans/new");
}

async function validateCredentialProfile(formData: FormData) {
  "use server";
  await requireRole(["ADMIN"]);
  const id = value(formData, "id");
  const profile = await db.authCredentialProfile.findUnique({ where: { id } });
  if (!profile) return;
  try {
    const payload = decryptVaultPayload(profile.encryptedPayload);
    const result = await validatePayload(profile.targetOrigin, payload);
    await db.authCredentialProfile.update({
      data: {
        lastValidatedAt: new Date(),
        lastValidationMessage: result.message,
        lastValidationStatus: result.ok ? "SUCCESS" : "FAILED",
      },
      where: { id },
    });
  } catch (error) {
    await db.authCredentialProfile.update({
      data: {
        lastValidatedAt: new Date(),
        lastValidationMessage:
          error instanceof Error ? error.message : "Validation failed.",
        lastValidationStatus: "FAILED",
      },
      where: { id },
    });
  }
  revalidatePath("/settings/vault");
}

async function validatePayload(
  origin: string | null,
  payload: {
    authHeader?: string;
    cookieHeader?: string;
    expectedText?: string;
    verificationPath?: string;
  },
) {
  if (!origin)
    return { message: "Set a target origin before validation.", ok: false };
  const target = new URL(payload.verificationPath || "/", origin);
  const response = await fetch(target, {
    cache: "no-store",
    headers: authHeadersFromPayload(vaultPayloadSchema.parse(payload)),
    redirect: "follow",
    signal: AbortSignal.timeout(15_000),
  });
  const body = await response.text();
  const expected = payload.expectedText
    ? body.toLowerCase().includes(payload.expectedText.toLowerCase())
    : true;
  const loginLike =
    /\/(?:login|sign-in|signin|auth|session)(?:\/|$|\?)/i.test(
      new URL(response.url).pathname,
    ) ||
    /\b(?:sign in|log in|login|password|authentication required|access denied|unauthorized)\b/i.test(
      body.slice(0, 12000),
    );
  const ok = response.status < 400 && expected && !loginLike;
  return {
    message: `HTTP ${response.status} at ${response.url}${expected ? "" : "; expected text not found"}${loginLike ? "; response looks like login or denial" : ""}`,
    ok,
  };
}

function value(formData: FormData, key: string) {
  const item = formData.get(key);
  return typeof item === "string" ? item.trim() : "";
}

function roleLabel(value: string) {
  return value
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatDate(value: Date) {
  return value.toISOString().slice(0, 10);
}

function formatDateTime(value: Date) {
  return value.toISOString().replace("T", " ").slice(0, 16);
}
