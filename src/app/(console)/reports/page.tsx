import { Download } from "lucide-react";
import { db } from "@/lib/db";

export default async function ReportsPage() {
  const scans = await db.scan.findMany({
    where: { status: "COMPLETED" },
    orderBy: { completedAt: "desc" },
    take: 100,
  });

  return (
    <>
      <p className="eyebrow">Exports</p>
      <h1 className="mt-2 text-3xl font-semibold">Reports</h1>
      <p className="muted mt-2">Portable evidence and scan summaries.</p>
      <section className="panel mt-8 divide-y divide-line">
        {scans.map((scan) => (
          <div className="flex flex-wrap items-center gap-4 p-5" key={scan.id}>
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium text-slate-200">
                {scan.finalUrl ?? scan.normalizedUrl}
              </p>
              <p className="mt-1 text-xs text-slate-600">
                Security {scan.securityScore}/100 · Coverage{" "}
                {scan.coverageScore}%
              </p>
            </div>
            <a
              className="button-secondary"
              href={`/api/scans/${scan.id}/report?format=json`}
            >
              <Download size={14} />
              JSON
            </a>
            <a
              className="button-secondary"
              href={`/api/scans/${scan.id}/report?format=html`}
            >
              <Download size={14} />
              HTML
            </a>
            <a
              className="button-secondary"
              href={`/api/scans/${scan.id}/report?format=pdf`}
            >
              <Download size={14} />
              PDF
            </a>
          </div>
        ))}
        {scans.length === 0 && (
          <div className="muted p-12 text-center">
            Reports appear after an scan completes.
          </div>
        )}
      </section>
    </>
  );
}
