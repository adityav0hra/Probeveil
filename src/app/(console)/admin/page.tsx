import Link from "next/link";
import {
  ArrowUpRight,
  BookOpenText,
  CircleAlert,
  ClipboardList,
  FileText,
  Plus,
} from "lucide-react";
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
  const active = scans.filter((scan) =>
    ["QUEUED", "RUNNING"].includes(scan.status),
  );
  const failed = scans.filter((scan) => scan.status === "FAILED");
  const findings = scans.flatMap((scan) => scan.findings);
  const criticalOrHigh = findings.filter((finding) =>
    ["CRITICAL", "HIGH"].includes(finding.severity),
  );
  const averageCoverage = completed.length
    ? Math.round(
        completed.reduce(
          (total, scan) => total + (scan.coverageScore ?? 0),
          0,
        ) / completed.length,
      )
    : null;
  const lastScan = scans[0];

  return (
    <>
      <section className="grid gap-4 xl:grid-cols-[1fr_360px]">
        <div className="panel p-6">
          <div className="flex flex-wrap items-start justify-between gap-5">
            <div>
              <p className="eyebrow">Security operations</p>
              <h1 className="mt-3 text-3xl font-semibold tracking-tight text-white">
                Admin console
              </h1>
              <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400">
                Review scan health, start approved website checks, manage
                findings and export evidence from one controlled workspace.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <Link className="button-secondary" href="/instructions">
                <BookOpenText size={16} />
                Instructions
              </Link>
              <Link className="button" href="/scans/new">
                <Plus size={16} />
                New scan
              </Link>
            </div>
          </div>

          <div className="mt-8 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {[
              ["Scans", scans.length, "Total records"],
              ["Active", active.length, "Queued or running"],
              ["High risk", criticalOrHigh.length, "Critical and high"],
              [
                "Coverage",
                averageCoverage === null ? "-" : `${averageCoverage}%`,
                "Average completed",
              ],
            ].map(([label, value, detail]) => (
              <div className="rounded-md border border-line p-4" key={label}>
                <p className="text-xs text-slate-500">{label}</p>
                <p className="mt-2 text-3xl font-semibold text-white">
                  {value}
                </p>
                <p className="mt-2 text-xs text-slate-600">{detail}</p>
              </div>
            ))}
          </div>
        </div>

        <aside className="panel p-6">
          <p className="eyebrow">Today</p>
          <div className="mt-5 space-y-5">
            <div>
              <p className="text-sm font-medium text-white">Current state</p>
              <p className="mt-2 text-sm leading-6 text-slate-500">
                {active.length
                  ? `${active.length} scan${active.length === 1 ? "" : "s"} currently in progress.`
                  : "No scans are running right now."}
              </p>
            </div>
            <div className="border-t border-line pt-5">
              <p className="text-sm font-medium text-white">Last scan</p>
              <p className="mt-2 truncate text-sm text-slate-500">
                {lastScan?.finalUrl ??
                  lastScan?.normalizedUrl ??
                  "No scans yet"}
              </p>
            </div>
            <div className="border-t border-line pt-5">
              <p className="text-sm font-medium text-white">Failed scans</p>
              <p className="mt-2 text-sm text-slate-500">
                {failed.length
                  ? `${failed.length} need review in recent history.`
                  : "No recent failures in the dashboard window."}
              </p>
            </div>
          </div>
        </aside>
      </section>

      <section className="mt-5 grid gap-4 lg:grid-cols-3">
        {[
          {
            href: "/issues",
            icon: CircleAlert,
            title: "Triage findings",
            body: "Confirm real issues, mark false positives, accept risk, or queue targeted retests.",
          },
          {
            href: "/reports",
            icon: FileText,
            title: "Export reports",
            body: "Generate technical, executive, compliance and evidence packages.",
          },
          {
            href: "/settings/safety",
            icon: ClipboardList,
            title: "Check safety controls",
            body: "Review ownership approval, rate limits, scan windows and dangerous payload settings.",
          },
        ].map(({ href, icon: Icon, title, body }) => (
          <Link
            className="panel block p-5 transition hover:border-slate-500"
            href={href}
            key={title}
          >
            <Icon className="text-signal" size={18} />
            <h2 className="mt-4 text-base font-semibold text-white">{title}</h2>
            <p className="mt-2 text-sm leading-6 text-slate-500">{body}</p>
          </Link>
        ))}
      </section>

      <section className="panel mt-5 overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-line p-5">
          <div>
            <h2 className="font-semibold text-white">Recent scans</h2>
            <p className="mt-1 text-xs text-slate-500">
              URL, status, score and coverage from the latest 30 scan records.
            </p>
          </div>
          <DeleteScanHistoryButton />
        </div>
        {scans.length === 0 ? (
          <div className="px-5 py-16 text-center">
            <p className="text-slate-300">No scans yet</p>
            <p className="muted mt-2">
              Start with a URL and Probeveil handles discovery, evidence and
              reporting.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-white/[.015] text-[10px] uppercase tracking-wider text-slate-600">
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
