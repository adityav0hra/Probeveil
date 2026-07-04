import { notFound } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, ExternalLink } from "lucide-react";
import { db } from "@/lib/db";

export default async function ScanSurfacePage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const scan = await db.scan.findUnique({
    include: {
      endpoints: { orderBy: { url: "asc" } },
      services: true,
      technologies: true,
    },
    where: { id },
  });
  if (!scan) notFound();

  return (
    <>
      <Link
        className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-white"
        href={`/scans/${id}`}
      >
        <ArrowLeft size={15} />
        Back to results
      </Link>
      <p className="eyebrow mt-6">Discovered inventory</p>
      <h1 className="mt-2 text-3xl font-semibold">Attack surface</h1>
      <p className="muted mt-2">
        {scan.endpoints.length} routes · {scan.services.length} services ·{" "}
        {scan.technologies.length} technologies
      </p>
      <section className="panel mt-8 overflow-hidden">
        <div className="border-b border-line p-5 font-semibold">Routes</div>
        <div className="divide-y divide-line/70">
          {scan.endpoints.map((endpoint) => (
            <div
              className="flex items-center gap-4 px-5 py-3 text-sm"
              key={endpoint.id}
            >
              <span
                className={`size-2 rounded-full ${
                  endpoint.tested ? "bg-signal" : "bg-amber-400"
                }`}
              />
              <span className="w-10 text-xs text-slate-600">
                {endpoint.statusCode ?? "-"}
              </span>
              <span className="min-w-0 flex-1 truncate text-slate-300">
                {endpoint.url}
              </span>
              {endpoint.external && (
                <span className="flex items-center gap-1 text-xs text-slate-500">
                  <ExternalLink size={12} />
                  External tested
                </span>
              )}
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
