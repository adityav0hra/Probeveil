import type { Metadata } from "next";
import { isScanMode, NewScanForm } from "@/components/new-scan-form";

export const metadata: Metadata = { title: "New Security Scan" };

export default async function NewScanPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; mode?: string; url?: string }>;
}) {
  const params = await searchParams;
  const initialMode = isScanMode(params.mode) ? params.mode : "FULL";

  return (
    <div className="mx-auto max-w-3xl py-10 lg:py-20">
      <div className="text-center">
        <p className="eyebrow">New scan</p>
        <h1 className="mt-3 text-4xl font-semibold tracking-tight">
          New Security Scan
        </h1>
      </div>
      <section className="panel mt-10 p-6 sm:p-8">
        <NewScanForm
          error={params.error}
          initialMode={initialMode}
          initialUrl={params.url ?? ""}
        />
      </section>
    </div>
  );
}
