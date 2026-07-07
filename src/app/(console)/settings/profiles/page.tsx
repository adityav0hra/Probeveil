import { ShieldCheck } from "lucide-react";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";
import { scanPolicyFromProfile } from "@/lib/scan-profiles";

export default async function ScanProfilesPage() {
  await requireRole(["ADMIN", "AUDITOR"]);
  const profiles = await db.scanProfile.findMany({
    orderBy: [{ enabled: "desc" }, { name: "asc" }],
  });
  const policies = profiles.map(scanPolicyFromProfile);

  return (
    <>
      <p className="eyebrow">System configuration</p>
      <h1 className="mt-2 text-3xl font-semibold">Scan profiles</h1>
      <p className="muted mt-2">
        Saved policies for scan depth, engines, authenticated coverage, evidence
        capture and alert thresholds.
      </p>

      <div className="mt-8 grid gap-5 xl:grid-cols-2">
        {policies.map((policy) => (
          <section className="panel p-6" key={policy.id}>
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <div className="flex flex-wrap items-center gap-3">
                  <ShieldCheck className="text-signal" size={20} />
                  <h2 className="text-lg font-semibold">{policy.name}</h2>
                  <span className="rounded-full bg-emerald-400/10 px-2.5 py-1 text-xs font-medium text-emerald-200">
                    {policy.mode.toLowerCase()}
                  </span>
                </div>
                <p className="mt-3 text-sm leading-6 text-slate-400">
                  {policy.description}
                </p>
              </div>
              {policy.cadence && (
                <span className="h-fit rounded-full bg-white/[.05] px-2.5 py-1 text-xs text-slate-300">
                  {policy.cadence.toLowerCase()}
                </span>
              )}
            </div>

            <div className="mt-5 grid gap-3 sm:grid-cols-4">
              <Metric label="Routes" value={String(policy.limits.maxRoutes)} />
              <Metric label="Depth" value={String(policy.limits.maxDepth)} />
              <Metric
                label="API endpoints"
                value={String(policy.limits.maxApiEndpoints)}
              />
              <Metric
                label="Runtime"
                value={`${policy.limits.maxRuntimeMinutes}m`}
              />
            </div>

            <div className="mt-5 grid gap-4 lg:grid-cols-3">
              <ProfileBlock
                items={[
                  ["Browser", policy.features.browserRendering],
                  ["Screenshots", policy.features.screenshots],
                  ["API discovery", policy.features.apiDiscovery],
                  ["Evidence archive", policy.features.evidenceArchive],
                ]}
                title="Coverage"
              />
              <ProfileBlock
                items={Object.entries(policy.engines).map(([key, enabled]) => [
                  engineLabel(key),
                  Boolean(enabled),
                ])}
                title="Engines"
              />
              <ProfileBlock
                items={[
                  ["Authenticated", policy.authConfig.authenticated],
                  ["Role comparison", policy.authConfig.roleComparison],
                  [
                    `${policy.authConfig.routeSeeds.length} route seeds`,
                    policy.authConfig.routeSeeds.length > 0,
                  ],
                  [
                    `Notify ${policy.alertThresholds.notifyAt.join(", ")}`,
                    true,
                  ],
                ]}
                title="Auth and alerts"
              />
            </div>
          </section>
        ))}
      </div>
    </>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-line bg-black/20 p-3">
      <p className="text-xs text-slate-500">{label}</p>
      <p className="mt-1 text-sm font-semibold text-slate-100">{value}</p>
    </div>
  );
}

function ProfileBlock({
  items,
  title,
}: {
  items: Array<[string, boolean]>;
  title: string;
}) {
  return (
    <div className="rounded-lg border border-line bg-black/20 p-4">
      <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
      <div className="mt-3 flex flex-wrap gap-2">
        {items.map(([label, enabled]) => (
          <span
            className={
              enabled
                ? "rounded-full bg-emerald-400/10 px-2 py-1 text-xs text-emerald-200"
                : "rounded-full bg-slate-500/10 px-2 py-1 text-xs text-slate-500"
            }
            key={label}
          >
            {label}
          </span>
        ))}
      </div>
    </div>
  );
}

function engineLabel(value: string) {
  return value
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/^./, (character) => character.toUpperCase());
}
