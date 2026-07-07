import Link from "next/link";
import { ArrowUpRight, History } from "lucide-react";
import { db } from "@/lib/db";
import { StatusPill } from "@/components/status-pill";
import { requireRole } from "@/lib/auth";

export default async function IssuesPage() {
  await requireRole(["ADMIN", "AUDITOR"]);
  const issues = await db.findingIssue.findMany({
    include: {
      findings: {
        include: {
          scan: {
            select: {
              id: true,
              normalizedUrl: true,
              status: true,
            },
          },
        },
        orderBy: { detectedAt: "desc" },
        take: 1,
      },
      events: {
        orderBy: { createdAt: "desc" },
        take: 1,
      },
    },
    orderBy: [{ status: "asc" }, { severity: "asc" }, { lastSeenAt: "desc" }],
    take: 200,
  });
  const active = issues.filter((issue) =>
    ["ACTIVE", "REOPENED"].includes(issue.status),
  );
  const fixed = issues.filter((issue) => issue.status === "FIXED");
  const triaged = issues.filter((issue) =>
    ["ACCEPTED_RISK", "FALSE_POSITIVE"].includes(issue.status),
  );

  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Finding deduplication</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight">
            Issue lifecycle
          </h1>
          <p className="muted mt-2">
            Persistent vulnerability identities across repeated scans.
          </p>
        </div>
      </div>

      <div className="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ["Tracked issues", issues.length],
          ["Active or reopened", active.length],
          ["Fixed by later scans", fixed.length],
          ["Triaged", triaged.length],
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
            <h2 className="font-semibold">Persistent issues</h2>
            <p className="mt-1 text-xs text-slate-500">
              Same issue, repeated findings, one lifecycle record.
            </p>
          </div>
        </div>
        {issues.length === 0 ? (
          <div className="px-5 py-16 text-center">
            <p className="text-slate-300">No issue identities yet</p>
            <p className="muted mt-2">
              Completed scans will assign findings to persistent issues.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-white/[.02] text-[10px] uppercase tracking-wider text-slate-600">
                <tr>
                  <th className="px-5 py-3">Issue</th>
                  <th>Status</th>
                  <th>Severity</th>
                  <th>Occurrences</th>
                  <th>First seen</th>
                  <th>Last seen</th>
                  <th>Latest scan</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {issues.map((issue) => {
                  const latestFinding = issue.findings[0];
                  return (
                    <tr
                      className="border-t border-line/70 hover:bg-white/[.015]"
                      key={issue.id}
                    >
                      <td className="max-w-md px-5 py-4">
                        <p className="font-medium text-slate-200">
                          {issue.title}
                        </p>
                        <p className="mt-1 truncate text-xs text-slate-600">
                          {issue.affectedUrl ?? issue.scannerRuleId}
                        </p>
                      </td>
                      <td>
                        <StatusPill value={issue.status} />
                      </td>
                      <td>
                        <StatusPill value={issue.severity} />
                      </td>
                      <td>{issue.occurrenceCount}</td>
                      <td className="text-xs text-slate-500">
                        {issue.firstSeenAt.toLocaleString()}
                      </td>
                      <td className="text-xs text-slate-500">
                        {issue.lastSeenAt.toLocaleString()}
                      </td>
                      <td className="max-w-xs truncate text-xs text-slate-500">
                        {latestFinding?.scan.normalizedUrl ?? "—"}
                      </td>
                      <td>
                        {latestFinding ? (
                          <Link
                            aria-label="Open latest finding"
                            className="text-slate-500 hover:text-signal"
                            href={`/findings/${latestFinding.id}`}
                          >
                            <ArrowUpRight size={16} />
                          </Link>
                        ) : (
                          <History className="text-slate-700" size={16} />
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
