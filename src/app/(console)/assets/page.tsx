import Link from "next/link";
import { ArrowUpRight, Boxes } from "lucide-react";
import { AssetKind, AssetStatus } from "@prisma/client";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";
import { StatusPill } from "@/components/status-pill";

export default async function AssetsPage() {
  await requireRole(["ADMIN", "AUDITOR"]);
  const [assets, events] = await Promise.all([
    db.assetInventoryItem.findMany({
      include: {
        events: { orderBy: { createdAt: "desc" }, take: 1 },
        lastScan: { select: { id: true, normalizedUrl: true, status: true } },
      },
      orderBy: [{ status: "asc" }, { kind: "asc" }, { lastSeenAt: "desc" }],
      take: 300,
    }),
    db.assetInventoryEvent.findMany({
      include: {
        asset: { select: { kind: true, label: true, status: true } },
        scan: { select: { id: true, normalizedUrl: true } },
      },
      orderBy: { createdAt: "desc" },
      take: 30,
    }),
  ]);
  const active = assets.filter((asset) => asset.status === AssetStatus.ACTIVE);
  const missing = assets.filter(
    (asset) => asset.status === AssetStatus.MISSING,
  );

  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Asset inventory</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight">
            Long-term attack surface
          </h1>
          <p className="muted mt-2">
            Domains, endpoints, APIs, services, technologies and sensitive
            routes tracked across scans.
          </p>
        </div>
      </div>

      <div className="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ["Tracked assets", assets.length],
          ["Active", active.length],
          ["Missing since last scan", missing.length],
          [
            "APIs and sensitive routes",
            assets.filter((asset) =>
              (
                [
                AssetKind.API,
                AssetKind.ADMIN_ROUTE,
                AssetKind.LOGIN_PAGE,
              ] as AssetKind[]
              ).includes(asset.kind),
            ).length,
          ],
        ].map(([label, value]) => (
          <div className="panel p-5" key={label}>
            <p className="eyebrow">{label}</p>
            <p className="mt-3 text-3xl font-semibold">{value}</p>
          </div>
        ))}
      </div>

      <section className="panel mt-6 overflow-hidden">
        <div className="flex items-center justify-between border-b border-line p-5">
          <div>
            <h2 className="font-semibold">Inventory</h2>
            <p className="mt-1 text-xs text-slate-500">
              First seen, last seen and change state are maintained across
              completed scans.
            </p>
          </div>
        </div>
        {assets.length === 0 ? (
          <div className="px-5 py-16 text-center">
            <Boxes className="mx-auto text-slate-700" size={28} />
            <p className="mt-3 text-slate-300">No assets tracked yet</p>
            <p className="muted mt-2">
              Completed scans will populate the inventory automatically.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-white/[.02] text-[10px] uppercase tracking-wider text-slate-600">
                <tr>
                  <th className="px-5 py-3">Asset</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Seen</th>
                  <th>First seen</th>
                  <th>Last seen</th>
                  <th>Latest scan</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {assets.map((asset) => (
                  <tr
                    className="border-t border-line/70 hover:bg-white/[.015]"
                    key={asset.id}
                  >
                    <td className="max-w-xl px-5 py-4">
                      <p className="truncate font-medium text-slate-200">
                        {asset.label}
                      </p>
                      <p className="mt-1 truncate text-xs text-slate-600">
                        {asset.hostname ?? asset.url ?? asset.value}
                      </p>
                      {asset.events[0] ? (
                        <p className="mt-2 text-xs text-slate-500">
                          {asset.events[0].summary}
                        </p>
                      ) : null}
                    </td>
                    <td>
                      <StatusPill value={asset.kind} />
                    </td>
                    <td>
                      <StatusPill value={asset.status} />
                    </td>
                    <td>{asset.observationCount}</td>
                    <td className="text-xs text-slate-500">
                      {asset.firstSeenAt.toLocaleString()}
                    </td>
                    <td className="text-xs text-slate-500">
                      {asset.lastSeenAt.toLocaleString()}
                    </td>
                    <td className="max-w-xs truncate text-xs text-slate-500">
                      {asset.lastScan?.normalizedUrl ?? "—"}
                    </td>
                    <td>
                      {asset.lastScanId ? (
                        <Link
                          aria-label="Open latest scan"
                          className="text-slate-500 hover:text-signal"
                          href={`/scans/${asset.lastScanId}`}
                        >
                          <ArrowUpRight size={16} />
                        </Link>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel mt-6 overflow-hidden">
        <div className="border-b border-line p-5">
          <h2 className="font-semibold">Recent changes</h2>
          <p className="mt-1 text-xs text-slate-500">
            Discovery, observation, change and missing events.
          </p>
        </div>
        {events.length ? (
          <div className="divide-y divide-line">
            {events.map((event) => (
              <div className="grid gap-3 p-4 lg:grid-cols-[1fr_auto]" key={event.id}>
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusPill value={event.eventType} />
                    <StatusPill value={event.asset.kind} />
                    <span className="text-sm font-medium text-slate-200">
                      {event.asset.label}
                    </span>
                  </div>
                  <p className="mt-2 text-xs text-slate-500">
                    {event.summary}
                  </p>
                  <p className="mt-1 text-xs text-slate-600">
                    {event.createdAt.toLocaleString()}
                  </p>
                </div>
                {event.scanId ? (
                  <Link
                    className="button-secondary h-fit"
                    href={`/scans/${event.scanId}`}
                  >
                    <ArrowUpRight size={14} />
                    Open scan
                  </Link>
                ) : null}
              </div>
            ))}
          </div>
        ) : (
          <p className="p-6 text-sm text-slate-500">
            No inventory events have been recorded yet.
          </p>
        )}
      </section>
    </>
  );
}
