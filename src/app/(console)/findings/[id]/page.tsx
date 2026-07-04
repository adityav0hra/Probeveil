import { notFound } from "next/navigation";
import { revalidatePath } from "next/cache";
import { ArrowLeft, Download } from "lucide-react";
import Link from "next/link";
import { db } from "@/lib/db";
import { requireRole } from "@/lib/auth";
import { StatusPill } from "@/components/status-pill";
import { CopyButton } from "@/components/copy-button";

export default async function FindingPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const finding = await db.finding.findUnique({
    where: { id },
    include: {
      evidence: true,
      scan: true,
      reviews: { orderBy: { createdAt: "desc" }, include: { user: true } },
    },
  });
  if (!finding) notFound();
  async function review(formData: FormData) {
    "use server";
    const session = await requireRole(["ADMIN"]);
    const status = String(formData.get("status"));
    const note = String(formData.get("note") ?? "").trim();
    const allowed = [
      "CONFIRMED",
      "FALSE_POSITIVE",
      "ACCEPTED_RISK",
      "FIXED",
      "OPEN",
    ];
    if (!allowed.includes(status)) throw new Error("Invalid review state");
    const before = await db.finding.findUniqueOrThrow({ where: { id } });
    await db.$transaction([
      db.finding.update({
        where: { id },
        data: {
          status: status as typeof before.status,
          adminNotes: note || before.adminNotes,
        },
      }),
      db.findingReview.create({
        data: {
          findingId: id,
          userId: session.user.id,
          action: `MARK_${status}`,
          previousValue: { status: before.status },
          newValue: { status, note },
          explanation: note || undefined,
        },
      }),
      db.auditLog.create({
        data: {
          userId: session.user.id,
          action: "FINDING_REVIEWED",
          resourceType: "Finding",
          resourceId: id,
          metadata: { status },
        },
      }),
    ]);
    revalidatePath(`/findings/${id}`);
  }
  const evidenceText = finding.evidence
    .map((e) => e.content ?? "")
    .join("\n\n");
  return (
    <>
      <Link
        href={`/scans/${finding.scanId}`}
        className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-white"
      >
        <ArrowLeft size={15} />
        Back to results
      </Link>
      <div className="mt-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex gap-2">
            <StatusPill value={finding.severity} />
            <StatusPill value={finding.confidence} />
            <StatusPill value={finding.status} />
          </div>
          <h1 className="mt-4 text-3xl font-semibold tracking-tight">
            {finding.title}
          </h1>
          <p className="mt-2 text-sm text-slate-500">
            {finding.cwe ?? "Unclassified"} ·{" "}
            {finding.owaspCategory ?? finding.category} · {finding.scannerName}{" "}
            {finding.scannerVersion}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <CopyButton value={evidenceText} label="Copy evidence" />
          <a className="button-secondary" href={`/api/findings/${id}/evidence`}>
            <Download size={14} />
            Download evidence
          </a>
        </div>
      </div>
      <div className="mt-8 grid gap-6 xl:grid-cols-[1fr_360px]">
        <div className="space-y-6">
          <Section title="Description">
            <p>{finding.description}</p>
          </Section>
          <Section title="Impact">
            <p>{finding.impact}</p>
          </Section>
          <Section title="Affected location">
            <dl className="grid gap-4 sm:grid-cols-3">
              <Item label="URL" value={finding.affectedUrl ?? "—"} />
              <Item label="Method" value={finding.httpMethod ?? "—"} />
              <Item label="Parameter" value={finding.parameter ?? "—"} />
            </dl>
          </Section>
          <Section title="Evidence">
            {finding.evidence.length ? (
              <div className="space-y-3">
                {finding.evidence.map((e) => (
                  <details
                    key={e.id}
                    className="rounded-lg border border-line bg-black/20"
                    open
                  >
                    <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-slate-300">
                      {e.title}{" "}
                      <span className="ml-2 text-xs text-slate-600">
                        SHA-256 {e.sha256.slice(0, 12)}…
                      </span>
                    </summary>
                    <pre className="max-h-[480px] overflow-auto border-t border-line p-4 text-xs leading-5 text-slate-400">
                      {e.content}
                    </pre>
                  </details>
                ))}
              </div>
            ) : (
              <p className="muted">No inline evidence is available.</p>
            )}
          </Section>
          <Section title="Reproduction steps">
            <ol className="list-decimal space-y-2 pl-5 text-sm text-slate-400">
              {(finding.reproductionSteps as string[]).map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ol>
          </Section>
          <Section title="Remediation">
            <p>{finding.remediation}</p>
          </Section>
        </div>
        <aside className="space-y-5">
          <form action={review} className="panel p-5">
            <p className="eyebrow">Admin review</p>
            <label className="mt-4 block text-sm text-slate-300">
              Decision
              <select
                name="status"
                defaultValue={finding.status}
                className="input mt-2"
              >
                <option value="OPEN">Open</option>
                <option value="CONFIRMED">Mark confirmed</option>
                <option value="FALSE_POSITIVE">Mark false positive</option>
                <option value="ACCEPTED_RISK">Accept risk</option>
                <option value="FIXED">Mark fixed</option>
              </select>
            </label>
            <label className="mt-4 block text-sm text-slate-300">
              Private admin note
              <textarea
                name="note"
                defaultValue={finding.adminNotes ?? ""}
                rows={5}
                className="input mt-2 resize-none"
              />
            </label>
            <button className="button mt-4 w-full">Save review</button>
          </form>
          <div className="panel p-5">
            <p className="eyebrow">Detection</p>
            <dl className="mt-4 space-y-4">
              <Item label="Rule" value={finding.scannerRuleId} />
              <Item
                label="Detected"
                value={finding.detectedAt.toLocaleString()}
              />
              <Item
                label="Fingerprint"
                value={finding.fingerprint.slice(0, 18) + "…"}
              />
            </dl>
          </div>
        </aside>
      </div>
    </>
  );
}
function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="panel p-5 sm:p-6">
      <h2 className="font-semibold">{title}</h2>
      <div className="mt-4 text-sm leading-6 text-slate-400">{children}</div>
    </section>
  );
}
function Item({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="eyebrow">{label}</dt>
      <dd className="mt-1 break-all text-sm text-slate-300">{value}</dd>
    </div>
  );
}
