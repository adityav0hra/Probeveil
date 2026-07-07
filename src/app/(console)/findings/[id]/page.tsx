import { notFound } from "next/navigation";
import { revalidatePath } from "next/cache";
import type { FindingStatus } from "@prisma/client";
import { ArrowLeft, Download, RotateCcw } from "lucide-react";
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
      retests: { orderBy: { createdAt: "desc" } },
      scan: true,
      reviews: { orderBy: { createdAt: "desc" }, include: { user: true } },
    },
  });
  if (!finding) notFound();

  const workflowOptions = [
    ["OPEN", "Open", "Needs review or remediation work."],
    ["CONFIRMED", "Confirmed", "Validated and should be fixed or tracked."],
    [
      "FALSE_POSITIVE",
      "False positive",
      "Evidence does not represent a real issue.",
    ],
    [
      "ACCEPTED_RISK",
      "Accepted risk",
      "Known issue accepted with business context.",
    ],
    ["FIXED", "Fixed", "Fix has been implemented and awaits validation."],
    [
      "RETEST_PASSED",
      "Retest passed",
      "Retest evidence confirms the issue is resolved.",
    ],
    [
      "RETEST_FAILED",
      "Retest failed",
      "Retest evidence shows the issue remains.",
    ],
  ] as const satisfies Array<readonly [FindingStatus, string, string]>;

  async function review(formData: FormData) {
    "use server";
    const session = await requireRole(["ADMIN"]);
    const status = String(formData.get("status")) as FindingStatus;
    const note = String(formData.get("note") ?? "").trim();
    const allowed = workflowOptions.map(([value]) => value);
    if (!allowed.includes(status)) throw new Error("Invalid review state");
    const before = await db.finding.findUniqueOrThrow({ where: { id } });
    const noteChanged = (before.adminNotes ?? "") !== note;
    const statusChanged = before.status !== status;
    if (!noteChanged && !statusChanged) {
      revalidatePath(`/findings/${id}`);
      return;
    }
    await db.$transaction([
      db.finding.update({
        where: { id },
        data: {
          status,
          adminNotes: note || null,
        },
      }),
      db.findingReview.create({
        data: {
          findingId: id,
          userId: session.user.id,
          action: statusChanged ? `MARK_${status}` : "UPDATE_REVIEW_NOTE",
          previousValue: {
            adminNotes: before.adminNotes,
            status: before.status,
          },
          newValue: {
            adminNotes: note || null,
            status,
          },
          explanation: note || undefined,
        },
      }),
      db.auditLog.create({
        data: {
          userId: session.user.id,
          action: "FINDING_REVIEWED",
          resourceType: "Finding",
          resourceId: id,
          metadata: {
            noteChanged,
            previousStatus: before.status,
            status,
            statusChanged,
          },
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
          <form action={`/api/findings/${id}/retest`} method="post">
            <button className="button-secondary" type="submit">
              <RotateCcw size={14} />
              Targeted retest
            </button>
          </form>
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
          <Section title="Reviewer history">
            {finding.reviews.length ? (
              <div className="space-y-3">
                {finding.reviews.map((review) => (
                  <ReviewHistoryItem key={review.id} review={review} />
                ))}
              </div>
            ) : (
              <p className="muted">
                No reviewer decisions have been recorded yet.
              </p>
            )}
          </Section>
        </div>
        <aside className="space-y-5">
          <form action={review} className="panel p-5">
            <p className="eyebrow">False-positive workflow</p>
            <p className="mt-2 text-sm leading-6 text-slate-500">
              Set the decision state, leave context for future reviewers, and
              preserve an immutable review trail.
            </p>
            <label className="mt-4 block text-sm text-slate-300">
              Decision status
              <select
                name="status"
                defaultValue={finding.status}
                className="input mt-2"
              >
                {workflowOptions.map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <div className="mt-3 space-y-2 rounded-lg border border-line bg-black/20 p-3">
              {workflowOptions.map(([value, label, description]) => (
                <div
                  className="grid grid-cols-[110px_1fr] gap-3 text-xs leading-5"
                  key={value}
                >
                  <span className="font-medium text-slate-300">{label}</span>
                  <span className="text-slate-500">{description}</span>
                </div>
              ))}
            </div>
            <label className="mt-4 block text-sm text-slate-300">
              Reviewer note
              <textarea
                name="note"
                defaultValue={finding.adminNotes ?? ""}
                rows={5}
                className="input mt-2 resize-none"
                placeholder="Why this status was chosen, validation evidence, risk acceptance context, owner, ticket, or retest notes."
              />
            </label>
            <button className="button mt-4 w-full">Save decision</button>
          </form>
          <div className="panel p-5">
            <p className="eyebrow">Current decision</p>
            <div className="mt-4 space-y-4">
              <div>
                <StatusPill value={finding.status} />
              </div>
              <Item
                label="Last reviewed"
                value={
                  finding.reviews[0]?.createdAt.toLocaleString() ??
                  "No review yet"
                }
              />
              <Item
                label="Reviewer"
                value={
                  finding.reviews[0]?.user?.name ??
                  finding.reviews[0]?.user?.email ??
                  "—"
                }
              />
              <div>
                <p className="eyebrow">Notes</p>
                <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-400">
                  {finding.adminNotes || "No reviewer notes yet."}
                </p>
              </div>
            </div>
          </div>
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
          <div className="panel p-5">
            <p className="eyebrow">Retests</p>
            <div className="mt-4 space-y-3">
              {finding.retests.length ? (
                finding.retests.map((retest) => (
                  <RetestCard key={retest.id} retest={retest} />
                ))
              ) : (
                <p className="text-sm text-slate-500">
                  No targeted retests have been started.
                </p>
              )}
            </div>
          </div>
        </aside>
      </div>
    </>
  );
}
function ReviewHistoryItem({
  review,
}: {
  review: {
    action: string;
    createdAt: Date;
    explanation: string | null;
    newValue: unknown;
    previousValue: unknown;
    user: { email: string; name: string | null } | null;
  };
}) {
  const previous = reviewValue(review.previousValue);
  const next = reviewValue(review.newValue);
  return (
    <div className="rounded-lg border border-line bg-black/20 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-sm font-medium text-slate-200">
            {review.action.replaceAll("_", " ")}
          </p>
          <p className="mt-1 text-xs text-slate-600">
            {review.user?.name ?? review.user?.email ?? "Unknown reviewer"} ·{" "}
            {review.createdAt.toLocaleString()}
          </p>
        </div>
        {next.status ? <StatusPill value={next.status} /> : null}
      </div>
      <dl className="mt-4 grid gap-3 sm:grid-cols-2">
        <Item label="Previous status" value={previous.status ?? "—"} />
        <Item label="New status" value={next.status ?? "—"} />
      </dl>
      {review.explanation || next.adminNotes ? (
        <div className="mt-4 rounded-md border border-line bg-white/[.02] p-3">
          <p className="eyebrow">Reviewer note</p>
          <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-400">
            {review.explanation ?? next.adminNotes}
          </p>
        </div>
      ) : null}
    </div>
  );
}

function RetestCard({
  retest,
}: {
  retest: {
    completedAt: Date | null;
    createdAt: Date;
    id: string;
    newEvidence: unknown;
    previousEvidence: unknown;
    startedAt: Date | null;
    status: string;
  };
}) {
  const before = retestBefore(retest.previousEvidence);
  const after = retestAfter(retest.newEvidence);
  const newScanId = after.newScanId ?? before.newScanId;
  return (
    <div className="rounded-lg border border-line bg-black/20 p-4 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <StatusPill value={retest.status} />
          <p className="mt-2 text-xs text-slate-600">
            Started {(retest.startedAt ?? retest.createdAt).toLocaleString()}
            {retest.completedAt
              ? ` · Completed ${retest.completedAt.toLocaleString()}`
              : ""}
          </p>
        </div>
        {newScanId ? (
          <Link
            className="text-xs font-medium text-signal hover:text-white"
            href={`/scans/${newScanId}`}
          >
            Open retest scan
          </Link>
        ) : null}
      </div>
      <div className="mt-4 grid gap-3">
        <div className="rounded-md border border-line bg-white/[.02] p-3">
          <p className="eyebrow">Before</p>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            {before.title ?? "Original finding evidence captured."}
          </p>
          <p className="mt-2 break-all text-xs text-slate-600">
            {before.rule ?? "Rule not captured"}
          </p>
          {before.evidence.length ? (
            <ul className="mt-3 space-y-1 text-xs text-slate-500">
              {before.evidence.slice(0, 3).map((item, index) => (
                <li key={`${item.sha256}-${index}`}>
                  {item.title} · {item.sha256.slice(0, 12)}…
                </li>
              ))}
            </ul>
          ) : null}
        </div>
        <div className="rounded-md border border-line bg-white/[.02] p-3">
          <p className="eyebrow">After</p>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            {after.summary ??
              "Retest scan is still running or has not produced comparison evidence yet."}
          </p>
          {after.matchedFindings.length ? (
            <ul className="mt-3 space-y-2 text-xs text-slate-500">
              {after.matchedFindings.slice(0, 3).map((item) => (
                <li key={item.id}>
                  <span className="text-slate-300">{item.title}</span>
                  <br />
                  {item.severity} · {item.confidence} ·{" "}
                  {item.affectedUrl ?? "No affected URL"}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function retestBefore(value: unknown) {
  if (Array.isArray(value))
    return {
      evidence: value
        .map((item) => evidenceSummary(item))
        .filter((item): item is EvidenceSummary => Boolean(item)),
    };
  if (!value || typeof value !== "object") return { evidence: [] };
  const row = value as {
    evidence?: unknown;
    finding?: { scannerRuleId?: unknown; title?: unknown };
    newScanId?: unknown;
    targetUrl?: unknown;
  };
  return {
    evidence: Array.isArray(row.evidence)
      ? row.evidence
          .map((item) => evidenceSummary(item))
          .filter((item): item is EvidenceSummary => Boolean(item))
      : [],
    newScanId: typeof row.newScanId === "string" ? row.newScanId : undefined,
    rule:
      typeof row.finding?.scannerRuleId === "string"
        ? row.finding.scannerRuleId
        : undefined,
    targetUrl: typeof row.targetUrl === "string" ? row.targetUrl : undefined,
    title:
      typeof row.finding?.title === "string" ? row.finding.title : undefined,
  };
}

function retestAfter(value: unknown) {
  if (!value || typeof value !== "object")
    return { matchedFindings: [] as MatchedRetestFinding[] };
  const row = value as {
    matchedFindings?: unknown;
    newScanId?: unknown;
    outcome?: unknown;
    summary?: unknown;
  };
  return {
    matchedFindings: Array.isArray(row.matchedFindings)
      ? row.matchedFindings
          .map((item) => matchedRetestFinding(item))
          .filter((item): item is MatchedRetestFinding => Boolean(item))
      : [],
    newScanId: typeof row.newScanId === "string" ? row.newScanId : undefined,
    outcome: typeof row.outcome === "string" ? row.outcome : undefined,
    summary: typeof row.summary === "string" ? row.summary : undefined,
  };
}

type EvidenceSummary = {
  sha256: string;
  title: string;
};

type MatchedRetestFinding = {
  affectedUrl?: string;
  confidence: string;
  id: string;
  severity: string;
  title: string;
};

function evidenceSummary(value: unknown): EvidenceSummary | undefined {
  if (!value || typeof value !== "object") return undefined;
  const row = value as { sha256?: unknown; title?: unknown };
  if (typeof row.sha256 !== "string") return undefined;
  return {
    sha256: row.sha256,
    title: typeof row.title === "string" ? row.title : "Evidence",
  };
}

function matchedRetestFinding(
  value: unknown,
): MatchedRetestFinding | undefined {
  if (!value || typeof value !== "object") return undefined;
  const row = value as {
    affectedUrl?: unknown;
    confidence?: unknown;
    id?: unknown;
    severity?: unknown;
    title?: unknown;
  };
  if (
    typeof row.id !== "string" ||
    typeof row.title !== "string" ||
    typeof row.severity !== "string" ||
    typeof row.confidence !== "string"
  )
    return undefined;
  return {
    affectedUrl:
      typeof row.affectedUrl === "string" ? row.affectedUrl : undefined,
    confidence: row.confidence,
    id: row.id,
    severity: row.severity,
    title: row.title,
  };
}

function reviewValue(value: unknown) {
  if (!value || typeof value !== "object") return {};
  const row = value as {
    adminNotes?: unknown;
    note?: unknown;
    status?: unknown;
  };
  return {
    adminNotes:
      typeof row.adminNotes === "string"
        ? row.adminNotes
        : typeof row.note === "string"
          ? row.note
          : undefined,
    status: typeof row.status === "string" ? row.status : undefined,
  };
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
