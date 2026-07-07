import Link from "next/link";
import { ExternalLink, PlugZap } from "lucide-react";
import { requireRole } from "@/lib/auth";
import { db } from "@/lib/db";
import { getIntegrationStatuses } from "@/lib/integrations/providers";

export default async function IntegrationsPage() {
  await requireRole(["ADMIN", "AUDITOR"]);
  const [deliveries, statuses] = await Promise.all([
    db.integrationDelivery.findMany({
      include: {
        finding: { select: { id: true, severity: true, title: true } },
        scan: { select: { id: true, normalizedUrl: true, status: true } },
      },
      orderBy: { createdAt: "desc" },
      take: 40,
    }),
    Promise.resolve(getIntegrationStatuses()),
  ]);

  return (
    <>
      <p className="eyebrow">System configuration</p>
      <h1 className="mt-2 text-3xl font-semibold">Integrations</h1>
      <p className="muted mt-2">
        Route scan summaries, failed scan alerts and high severity work items to
        the systems your team already uses.
      </p>

      <section className="mt-8 grid gap-4 xl:grid-cols-3">
        {statuses.map((status) => (
          <div className="panel p-5" key={status.provider}>
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <PlugZap className="text-signal" size={18} />
                <h2 className="text-sm font-semibold text-slate-100">
                  {status.label}
                </h2>
              </div>
              <span className={statusClass(status.configured)}>
                {status.configured ? "Configured" : "Missing"}
              </span>
            </div>
            <p className="mt-3 truncate text-xs text-slate-500">
              {status.target}
            </p>
            <p className="mt-2 text-xs text-slate-600">{status.type}</p>
          </div>
        ))}
      </section>

      <section className="mt-8">
        <h2 className="text-xl font-semibold">Recent deliveries</h2>
        <div className="panel mt-4 overflow-hidden">
          {deliveries.length === 0 ? (
            <p className="p-6 text-sm text-slate-400">
              Integration delivery history will appear after scans complete.
            </p>
          ) : (
            <div className="divide-y divide-line">
              {deliveries.map((delivery) => (
                <div
                  className="grid gap-3 p-4 lg:grid-cols-[1fr_auto]"
                  key={delivery.id}
                >
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-semibold text-slate-100">
                        {delivery.subject}
                      </span>
                      <span className={deliveryClass(delivery.status)}>
                        {delivery.status.replaceAll("_", " ").toLowerCase()}
                      </span>
                    </div>
                    <p className="mt-1 text-xs text-slate-500">
                      {delivery.provider.toLowerCase()} ·{" "}
                      {delivery.eventType.replaceAll("_", " ").toLowerCase()} ·{" "}
                      {formatDate(delivery.createdAt)}
                    </p>
                    {delivery.error && (
                      <p className="mt-2 max-w-3xl break-words text-xs text-red-300">
                        {delivery.error}
                      </p>
                    )}
                    <div className="mt-2 flex flex-wrap gap-3 text-xs">
                      {delivery.scan && (
                        <Link
                          className="text-signal hover:text-emerald-200"
                          href={`/scans/${delivery.scan.id}`}
                        >
                          {delivery.scan.normalizedUrl}
                        </Link>
                      )}
                      {delivery.finding && (
                        <Link
                          className="text-signal hover:text-emerald-200"
                          href={`/findings/${delivery.finding.id}`}
                        >
                          {delivery.finding.severity}: {delivery.finding.title}
                        </Link>
                      )}
                    </div>
                  </div>
                  {delivery.externalUrl && (
                    <a
                      className="button-secondary h-fit"
                      href={delivery.externalUrl}
                      rel="noreferrer"
                      target="_blank"
                    >
                      <ExternalLink size={16} />
                      Open work item
                    </a>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </section>
    </>
  );
}

function formatDate(date: Date) {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function statusClass(configured: boolean) {
  return configured
    ? "rounded-full bg-emerald-400/10 px-2.5 py-1 text-xs font-medium text-emerald-200"
    : "rounded-full bg-amber-400/10 px-2.5 py-1 text-xs font-medium text-amber-200";
}

function deliveryClass(status: string) {
  if (status === "SENT")
    return "rounded-full bg-emerald-400/10 px-2 py-0.5 text-[11px] text-emerald-200";
  if (status === "FAILED")
    return "rounded-full bg-red-500/10 px-2 py-0.5 text-[11px] text-red-300";
  if (status === "SKIPPED")
    return "rounded-full bg-slate-500/10 px-2 py-0.5 text-[11px] text-slate-300";
  return "rounded-full bg-amber-400/10 px-2 py-0.5 text-[11px] text-amber-200";
}
