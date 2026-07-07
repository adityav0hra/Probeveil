import Link from "next/link";
import { ArrowUpRight, Plus } from "lucide-react";
import { db } from "@/lib/db";
import { StatusPill } from "@/components/status-pill";
import { DeleteScanHistoryButton } from "@/components/delete-scan-history-button";

export default async function AdminDashboardPage() {
  const scans = await db.scan.findMany({
    orderBy: { createdAt: "desc" },
    take: 30,
    include: { findings: { select: { severity: true, confidence: true } } },
  });
  const completed = scans.filter((scan) => scan.status === "COMPLETED");
  const findings = scans.flatMap((scan) => scan.findings);

  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Security operations</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight">
            Scan overview
          </h1>
          <p className="muted mt-2">
            Live posture across every submitted website.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <DeleteScanHistoryButton />
          <Link className="button" href="/scans/new">
            <Plus size={16} />
            New scan
          </Link>
        </div>
      </div>
      <div className="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ["Total scans", scans.length],
          ["Completed", completed.length],
          [
            "Critical findings",
            findings.filter((finding) => finding.severity === "CRITICAL")
              .length,
          ],
          [
            "Average coverage",
            completed.length
              ? `${Math.round(
                  completed.reduce(
                    (total, scan) => total + (scan.coverageScore ?? 0),
                    0,
                  ) / completed.length,
                )}%`
              : "-",
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
            <h2 className="font-semibold">Recent scans</h2>
            <p className="mt-1 text-xs text-slate-500">
              URL is the primary scan identifier
            </p>
          </div>
        </div>
        {scans.length === 0 ? (
          <div className="px-5 py-16 text-center">
            <p className="text-slate-300">No scans yet</p>
            <p className="muted mt-2">
              Start with a URL and Probeveil handles the rest.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-white/[.02] text-[10px] uppercase tracking-wider text-slate-600">
                <tr>
                  <th className="px-5 py-3">Website</th>
                  <th>Mode</th>
                  <th>Status</th>
                  <th>Security</th>
                  <th>Coverage</th>
                  <th>Findings</th>
                  <th>Started</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr
                    className="border-t border-line/70 hover:bg-white/[.015]"
                    key={scan.id}
                  >
                    <td className="max-w-sm truncate px-5 py-4 font-medium text-slate-200">
                      {scan.finalUrl ?? scan.normalizedUrl}
                    </td>
                    <td className="text-xs text-slate-500">{scan.mode}</td>
                    <td>
                      <StatusPill value={scan.status} />
                    </td>
                    <td>{scan.securityScore ?? "-"}</td>
                    <td>
                      {scan.coverageScore === null
                        ? "-"
                        : `${scan.coverageScore}%`}
                    </td>
                    <td>{scan.findings.length}</td>
                    <td className="text-xs text-slate-500">
                      {scan.createdAt.toLocaleString()}
                    </td>
                    <td>
                      <Link
                        aria-label="Open scan"
                        className="text-slate-500 hover:text-signal"
                        href={`/scans/${scan.id}`}
                      >
                        <ArrowUpRight size={16} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
