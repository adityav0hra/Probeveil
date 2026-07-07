import type { Metadata } from "next";
import { isScanMode, NewScanForm } from "@/components/new-scan-form";
import { db } from "@/lib/db";

export const metadata: Metadata = { title: "New Security Scan" };

export default async function NewScanPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; mode?: string; url?: string }>;
}) {
  const params = await searchParams;
  const initialMode = isScanMode(params.mode) ? params.mode : "FULL";
  const profiles = await db.scanProfile.findMany({
    orderBy: { name: "asc" },
    where: { enabled: true },
  });
  const credentialProfiles = await db.authCredentialProfile.findMany({
    orderBy: [{ targetHostname: "asc" }, { name: "asc" }],
    select: {
      expiresAt: true,
      id: true,
      lastValidatedAt: true,
      lastValidationStatus: true,
      name: true,
      role: true,
      targetHostname: true,
    },
    where: { enabled: true },
  });

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
          credentialProfiles={credentialProfiles.map((profile) => ({
            expiresAt: profile.expiresAt?.toISOString() ?? null,
            id: profile.id,
            lastValidatedAt: profile.lastValidatedAt?.toISOString() ?? null,
            lastValidationStatus: profile.lastValidationStatus,
            name: profile.name,
            role: profile.role,
            targetHostname: profile.targetHostname,
          }))}
          error={params.error}
          initialMode={initialMode}
          initialUrl={params.url ?? ""}
          profiles={profiles.map((profile) => ({
            alertThresholds: profile.alertThresholds,
            authConfig: profile.authConfig,
            cadence: profile.cadence,
            description: profile.description,
            engines: profile.engines,
            features: profile.features,
            id: profile.id,
            limits: profile.limits,
            mode: profile.mode,
            name: profile.name,
            slug: profile.slug,
            stageConfig: profile.stageConfig,
          }))}
        />
      </section>
    </div>
  );
}
