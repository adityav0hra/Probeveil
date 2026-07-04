import { db } from "@/lib/db";
import { StatusPill } from "@/components/status-pill";
export const dynamic = "force-dynamic";
export default async function HealthPage() {
  let database = true;
  try {
    await db.$queryRaw`SELECT 1`;
  } catch {
    database = false;
  }
  const [queued, running, failed] = await Promise.all([
    db.workerJob.count({ where: { status: "QUEUED" } }),
    db.scan.count({ where: { status: "RUNNING" } }),
    db.scan.count({ where: { status: "FAILED" } }),
  ]);
  const checks = [
    ["Control plane", true, "Next.js application"],
    ["PostgreSQL", database, "Durable scan state"],
    ["Passive queue", true, `${queued} jobs queued`],
    ["Worker activity", true, `${running} scans running`],
  ] as const;
  return (
    <>
      <p className="eyebrow">Operations</p>
      <h1 className="mt-2 text-3xl font-semibold">System health</h1>
      <p className="muted mt-2">Control-plane health and scan throughput.</p>
      <div className="mt-8 grid gap-4 lg:grid-cols-2">
        {checks.map(([name, ok, detail]) => (
          <div
            className="panel flex items-center justify-between p-5"
            key={name}
          >
            <div>
              <h2 className="font-medium">{name}</h2>
              <p className="mt-1 text-xs text-slate-600">{detail}</p>
            </div>
            <StatusPill value={ok ? "COMPLETED" : "FAILED"} />
          </div>
        ))}
      </div>
      <div className="panel mt-6 p-5">
        <p className="eyebrow">Historical failures</p>
        <p className="mt-3 text-3xl font-semibold">{failed}</p>
      </div>
    </>
  );
}
