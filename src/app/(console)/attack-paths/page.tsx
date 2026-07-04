import { GitFork } from "lucide-react";
import { db } from "@/lib/db";
import { StatusPill } from "@/components/status-pill";

export default async function AttackPathsPage() {
  const paths = await db.attackPath.findMany({
    include: { scan: true },
    orderBy: { createdAt: "desc" },
  });

  return (
    <>
      <p className="eyebrow">Correlation</p>
      <h1 className="mt-2 text-3xl font-semibold">Attack paths</h1>
      <p className="muted mt-2 max-w-3xl">
        Attack paths are evidence-backed chains that show how one weakness can
        connect to another and create a larger security impact. Probeveil only
        shows a path when stored findings support the relationship.
      </p>
      <div className="mt-8 space-y-4">
        {paths.map((path) => (
          <div className="panel p-5" key={path.id}>
            <div className="flex items-center gap-3">
              <GitFork className="text-signal" size={17} />
              <h2 className="font-semibold">{path.title}</h2>
              <StatusPill value={path.confidence} />
            </div>
            <p className="mt-3 text-sm leading-6 text-slate-400">
              {path.impact}
            </p>
            <p className="mt-3 text-xs text-slate-600">
              {path.scan.finalUrl ?? path.scan.normalizedUrl}
            </p>
          </div>
        ))}
        {paths.length === 0 && (
          <div className="panel p-12 text-center">
            <GitFork className="mx-auto text-slate-700" />
            <p className="mt-4 text-slate-300">
              No evidence-backed attack paths yet
            </p>
            <p className="muted mt-2">
              Probeveil leaves this empty when the evidence is not strong enough
              to connect multiple findings into a chain.
            </p>
          </div>
        )}
      </div>
    </>
  );
}
