import { ArrowRight } from "lucide-react";
import {
  scanPolicyFromProfile,
  type ScanProfileLike,
} from "@/lib/scan-profiles";

const modes = [
  ["QUICK", "Quick Scan", "Fast passive scan"],
  ["FULL", "Full Scan", "Deep application scan"],
  ["MAXIMUM", "Maximum Scan", "Maximum practical coverage"],
] as const;

type ScanMode = (typeof modes)[number][0];

type CredentialProfileOption = {
  expiresAt: string | null;
  id: string;
  lastValidatedAt: string | null;
  lastValidationStatus: string | null;
  name: string;
  role: string;
  targetHostname: string | null;
};

export function isScanMode(
  value: string | null | undefined,
): value is ScanMode {
  return modes.some(([mode]) => mode === value);
}

export function NewScanForm({
  credentialProfiles = [],
  error,
  initialMode = "FULL",
  initialUrl = "",
  profiles = [],
}: {
  credentialProfiles?: CredentialProfileOption[];
  error?: string;
  initialMode?: ScanMode;
  initialUrl?: string;
  profiles?: ScanProfileLike[];
}) {
  const policies = profiles.map(scanPolicyFromProfile);
  return (
    <form action="/api/scans" className="mt-8 space-y-7" method="post">
      <label className="block">
        <span className="text-sm font-medium text-slate-200">Website URL</span>
        <input
          autoComplete="url"
          autoFocus
          className="input mt-2 h-12"
          defaultValue={initialUrl}
          inputMode="url"
          name="url"
          placeholder="https://target-website.com"
          required
          type="text"
        />
      </label>
      {policies.length > 0 && (
        <fieldset className="rounded-xl border border-line bg-white/[.015] p-4">
          <legend className="px-2 text-sm font-medium text-slate-200">
            Scan policy
          </legend>
          <select className="input mt-2" name="profileId" defaultValue="">
            <option value="">Custom configuration</option>
            {policies.map((policy) => (
              <option key={policy.id} value={policy.id}>
                {policy.name}
              </option>
            ))}
          </select>
          <div className="mt-4 grid gap-3 lg:grid-cols-2">
            {policies.map((policy) => (
              <div
                className="rounded-lg border border-line bg-black/20 p-4"
                key={policy.id}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <p className="text-sm font-semibold text-slate-100">
                    {policy.name}
                  </p>
                  <span className="rounded-full bg-emerald-400/10 px-2 py-0.5 text-[11px] font-medium text-emerald-200">
                    {policy.mode.toLowerCase()}
                  </span>
                  {policy.cadence && (
                    <span className="rounded-full bg-white/[.05] px-2 py-0.5 text-[11px] text-slate-300">
                      {policy.cadence.toLowerCase()}
                    </span>
                  )}
                </div>
                <p className="mt-2 text-xs leading-5 text-slate-500">
                  {policy.description}
                </p>
                <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-slate-400">
                  <span>{policy.limits.maxRoutes} routes</span>
                  <span>depth {policy.limits.maxDepth}</span>
                  <span>{enabledEngineCount(policy.engines)} engines</span>
                  {policy.authConfig.authenticated && <span>auth</span>}
                  {policy.features.screenshots && <span>screenshots</span>}
                </div>
              </div>
            ))}
          </div>
        </fieldset>
      )}
      <fieldset>
        <legend className="text-sm font-medium text-slate-200">
          Scan Mode
        </legend>
        <div className="mt-3 grid gap-3 sm:grid-cols-3">
          {modes.map(([value, label, description]) => (
            <label
              className="flex cursor-pointer items-start gap-3 rounded-xl border border-line bg-white/[.015] p-4 text-left transition hover:border-slate-600"
              key={value}
            >
              <input
                className="mt-1 size-4 shrink-0 accent-signal"
                defaultChecked={initialMode === value}
                name="mode"
                type="radio"
                value={value}
              />
              <span className="block">
                <span className="block text-sm font-semibold text-slate-100">
                  {label}
                </span>
                <span className="mt-1 block text-xs leading-5 text-slate-500">
                  {description}
                </span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>
      <fieldset className="rounded-xl border border-line bg-white/[.015] p-4">
        <legend className="px-2 text-sm font-medium text-slate-200">
          Advanced coverage
        </legend>
        <div className="grid gap-3 sm:grid-cols-3">
          {[
            ["browserRendering", "Browser rendering"],
            ["apiDiscovery", "API discovery"],
            ["screenshotCapture", "Screenshots"],
          ].map(([name, label]) => (
            <label
              className="flex items-center gap-3 rounded-lg border border-line bg-black/20 px-3 py-2 text-sm text-slate-300"
              key={name}
            >
              <input
                className="size-4 accent-signal"
                name={name}
                type="checkbox"
              />
              {label}
            </label>
          ))}
        </div>
        <div className="mt-4 grid gap-4">
          {credentialProfiles.length > 0 && (
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Stored authenticated profile
              </span>
              <select
                className="input mt-2"
                name="authCredentialProfileId"
                defaultValue=""
              >
                <option value="">No stored profile</option>
                {credentialProfiles.map((profile) => (
                  <option key={profile.id} value={profile.id}>
                    {profileLabel(profile)}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label className="block">
            <span className="text-sm font-medium text-slate-200">
              Authenticated context name
            </span>
            <input
              autoComplete="off"
              className="input mt-2"
              name="authContextName"
              placeholder="Admin session, normal user, billing user"
              type="text"
            />
          </label>
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
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Verify signed-in path
              </span>
              <input
                autoComplete="off"
                className="input mt-2"
                name="authVerificationPath"
                placeholder="/dashboard or https://site.com/account"
                type="text"
              />
            </label>
            <label className="block">
              <span className="text-sm font-medium text-slate-200">
                Expected signed-in text
              </span>
              <input
                autoComplete="off"
                className="input mt-2"
                name="authExpectedText"
                placeholder="Dashboard, Account, Sign out"
                type="text"
              />
            </label>
          </div>
          <label className="block">
            <span className="text-sm font-medium text-slate-200">
              Authenticated route seeds
            </span>
            <textarea
              className="input mt-2 min-h-28 resize-y"
              name="authRouteSeeds"
              placeholder={
                "/dashboard\n/account\n/admin\n/settings\n/invoices\n/export"
              }
            />
          </label>
        </div>
      </fieldset>
      <fieldset className="rounded-xl border border-line bg-white/[.015] p-4">
        <legend className="px-2 text-sm font-medium text-slate-200">
          Role comparison
        </legend>
        <p className="mb-4 text-xs leading-5 text-slate-500">
          Add approved sessions for role and account comparison. Values are used
          for same-origin requests only.
        </p>
        <div className="grid gap-4">
          {[
            ["normalUser", "Normal user", "NORMAL_USER"],
            ["adminUser", "Admin", "ADMIN"],
            ["userA", "User A", "USER_A"],
            ["userB", "User B", "USER_B"],
          ].map(([prefix, label, role]) => (
            <div
              className="rounded-lg border border-line bg-black/20 p-3"
              key={prefix}
            >
              <p className="text-sm font-medium text-slate-200">{label}</p>
              <div className="mt-3 grid gap-3 sm:grid-cols-2">
                {credentialProfiles.length > 0 && (
                  <select
                    className="input sm:col-span-2"
                    name={`${prefix}CredentialProfileId`}
                    defaultValue=""
                  >
                    <option value="">
                      No stored {label.toLowerCase()} profile
                    </option>
                    {credentialProfiles
                      .filter(
                        (profile) =>
                          profile.role === role || profile.role === "CUSTOM",
                      )
                      .map((profile) => (
                        <option key={profile.id} value={profile.id}>
                          {profileLabel(profile)}
                        </option>
                      ))}
                  </select>
                )}
                <input
                  autoComplete="off"
                  className="input"
                  name={`${prefix}AuthHeader`}
                  placeholder={`${label} Authorization header`}
                  type="password"
                />
                <input
                  autoComplete="off"
                  className="input"
                  name={`${prefix}CookieHeader`}
                  placeholder={`${label} Cookie header`}
                  type="password"
                />
              </div>
            </div>
          ))}
        </div>
      </fieldset>
      {error && (
        <p
          className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-300"
          role="alert"
        >
          {error}
        </p>
      )}
      <button className="button h-12 w-full" type="submit">
        Start Security Scan
        <ArrowRight size={16} />
      </button>
    </form>
  );
}

function enabledEngineCount(engines: Record<string, unknown>) {
  return Object.values(engines).filter(Boolean).length;
}

function profileLabel(profile: CredentialProfileOption) {
  const scope = profile.targetHostname ? ` · ${profile.targetHostname}` : "";
  const validation = profile.lastValidationStatus
    ? ` · ${profile.lastValidationStatus.toLowerCase()}`
    : "";
  const expiry = profile.expiresAt
    ? ` · expires ${profile.expiresAt.slice(0, 10)}`
    : "";
  return `${profile.name}${scope}${validation}${expiry}`;
}
