import { notFound } from "next/navigation";
import { db } from "@/lib/db";
import { ScanView } from "@/components/scan-view";

export default async function ScanPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const scan = await db.scan.findUnique({
    where: { id },
    include: {
      stages: { orderBy: { order: "asc" } },
      findings: { orderBy: { detectedAt: "desc" } },
      endpoints: { take: 500, include: { parameters: true } },
      services: true,
      technologies: true,
    },
  });
  if (!scan) notFound();
  return <ScanView id={id} initial={JSON.parse(JSON.stringify(scan))} />;
}
