import Link from "next/link";
import { db } from "@/lib/db";
export default async function AttackSurfacePage() {
  const scans = await db.scan.findMany({
    orderBy: { createdAt: "desc" },
    take: 50,
    include: {
      _count: {
        select: { endpoints: true, services: true, technologies: true },
      },
    },
  });
  return (
    <>
      <p className="eyebrow">Inventory</p>
      <h1 className="mt-2 text-3xl font-semibold">Attack surface</h1>
      <p className="muted mt-2">Discovered assets grouped by website scan.</p>
      <div className="mt-8 grid gap-4">
        {scans.map((scan) => (
          <Link
            href={`/scans/${scan.id}/attack-surface`}
            key={scan.id}
            className="panel flex items-center justify-between p-5 hover:border-slate-600"
          >
            <div>
              <p className="font-medium text-slate-200">
                {scan.finalUrl ?? scan.normalizedUrl}
              </p>
              <p className="mt-1 text-xs text-slate-600">
                {scan.mode} · {scan.createdAt.toLocaleString()}
              </p>
            </div>
            <div className="text-right text-sm text-slate-400">
              {scan._count.endpoints} routes
              <br />
              <span className="text-xs text-slate-600">
                {scan._count.services} services
              </span>
            </div>
          </Link>
        ))}
        {scans.length === 0 && (
          <div className="panel muted p-12 text-center">
            No attack surface has been discovered yet.
          </div>
        )}
      </div>
    </>
  );
}
