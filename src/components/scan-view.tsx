"use client";
import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import Link from "next/link";
import {
  Check,
  Circle,
  Download,
  Gauge,
  Layers3,
  LoaderCircle,
  OctagonX,
  RefreshCw,
  Route,
  ShieldAlert,
  StopCircle,
} from "lucide-react";
import { ScoreRing } from "./score-ring";
import { StatusPill } from "./status-pill";

type Stage = {
  id: string;
  key: string;
  label: string;
  status: string;
  progress: number;
  message?: string;
};
type Finding = {
  id: string;
  title: string;
  description: string;
  severity: string;
  confidence: string;
  status: string;
  category: string;
  cwe?: string;
  owaspCategory?: string;
  affectedUrl?: string;
  httpMethod?: string;
  impact: string;
  remediation: string;
  scannerRuleId?: string;
};
type Endpoint = {
  id: string;
  url: string;
  statusCode?: number;
  external: boolean;
  tested?: boolean;
  discoveredBy?: string;
  parameters?: Array<{
    id: string;
    name: string;
    location: string;
    dataType?: string;
    tested?: boolean;
  }>;
};
type Technology = {
  id: string;
  name: string;
  version?: string;
  category?: string;
};
type Scan = {
  id: string;
  originalUrl: string;
  normalizedUrl: string;
  finalUrl?: string;
  mode: string;
  status: string;
  securityScore: number | null;
  coverageScore: number | null;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  error?: string;
  stages: Stage[];
  findings: Finding[];
  endpoints: Endpoint[];
  services: unknown[];
  technologies: Technology[];
};

const severityOrder: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

export function ScanView({ id, initial }: { id: string; initial: Scan }) {
  const [scan, setScan] = useState(initial);
  const [cancelError, setCancelError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const active = ["QUEUED", "RUNNING"].includes(scan.status);

  useEffect(() => {
    if (!active) return;
    const timer = setInterval(async () => {
      const response = await fetch(`/api/scans/${id}`, { cache: "no-store" });
      if (response.ok) setScan(await response.json());
    }, 1500);
    return () => clearInterval(timer);
  }, [id, active]);

  const counts = useMemo(
    () =>
      Object.fromEntries(
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((severity) => [
          severity,
          scan.findings.filter((f) => f.severity === severity).length,
        ]),
      ),
    [scan.findings],
  );
  const insight = useMemo(() => buildInsight(scan), [scan]);

  if (active) {
    return (
      <>
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <p className="eyebrow">Live scan progress</p>
              <StatusPill value={scan.status} />
            </div>
            <h1 className="mt-2 max-w-3xl truncate text-3xl font-semibold tracking-tight">
              {scan.finalUrl ?? scan.normalizedUrl}
            </h1>
            <p className="muted mt-2">
              {scan.mode} scan · started {formatTimestamp(scan.createdAt)}
            </p>
          </div>
          <form
            action={`/api/scans/${id}/cancel`}
            method="post"
            onSubmit={async (event) => {
              event.preventDefault();
              setCancelling(true);
              setCancelError(null);
              try {
                const cancelResponse = await fetch(`/api/scans/${id}/cancel`, {
                  method: "POST",
                });
                if (!cancelResponse.ok)
                  throw new Error("Cancel request failed.");
                const response = await fetch(`/api/scans/${id}`, {
                  cache: "no-store",
                });
                if (!response.ok) throw new Error("Could not refresh scan.");
                setScan(await response.json());
              } catch (error) {
                setCancelError(
                  error instanceof Error
                    ? error.message
                    : "Could not cancel scan.",
                );
              } finally {
                setCancelling(false);
              }
            }}
          >
            <button
              className="button-secondary text-red-300"
              disabled={cancelling}
              type="submit"
            >
              <StopCircle size={16} />
              {cancelling ? "Cancelling..." : "Cancel scan"}
            </button>
          </form>
        </div>
        {cancelError && (
          <div className="mt-6 rounded-lg border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-300">
            {cancelError}
          </div>
        )}
        <div className="mt-8 grid gap-6 xl:grid-cols-[1fr_340px]">
          <section className="panel overflow-hidden">
            <div className="border-b border-line p-5">
              <h2 className="font-semibold">Scan pipeline</h2>
              <p className="mt-1 text-xs text-slate-500">
                Stage state is persisted and survives page refreshes.
              </p>
            </div>
            <div className="divide-y divide-line/70">
              {scan.stages.map((stage) => (
                <div
                  key={stage.id}
                  className="flex items-center gap-4 px-5 py-4"
                >
                  <StageIcon status={stage.status} />
                  <div className="min-w-0 flex-1">
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-200">{stage.label}</span>
                      <span className="text-xs text-slate-600">
                        {stage.status}
                      </span>
                    </div>
                    {stage.status === "RUNNING" && (
                      <div className="mt-2 h-1 overflow-hidden rounded-full bg-line">
                        <div
                          className="h-full animate-pulse rounded-full bg-signal"
                          style={{ width: `${Math.max(8, stage.progress)}%` }}
                        />
                      </div>
                    )}
                    {stage.message && (
                      <p className="mt-1 truncate text-xs text-red-300">
                        {stage.message}
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </section>
          <aside className="space-y-4">
            <div className="panel p-5">
              <p className="eyebrow">Discovered so far</p>
              <div className="mt-5 grid grid-cols-2 gap-4">
                <Metric label="Routes" value={scan.endpoints.length} />
                <Metric label="Findings" value={scan.findings.length} />
                <Metric label="Services" value={scan.services.length} />
                <Metric label="Tech" value={scan.technologies.length} />
              </div>
            </div>
            <InsightNote text="The live view updates as worker events arrive. Findings may appear before endpoint correlation and scoring complete." />
          </aside>
        </div>
      </>
    );
  }

  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <p className="eyebrow">Scan results</p>
            <StatusPill value={scan.status} />
          </div>
          <h1 className="mt-2 max-w-3xl truncate text-3xl font-semibold tracking-tight">
            {scan.finalUrl ?? scan.normalizedUrl}
          </h1>
          <p className="muted mt-2">
            {scan.mode} scan · {scan.endpoints.length} routes tested · completed{" "}
            {scan.completedAt ? formatTimestamp(scan.completedAt) : "recently"}
          </p>
        </div>
        <div className="flex gap-2">
          <Link className="button" href="/scans/new">
            <RefreshCw size={15} />
            Run retest
          </Link>
        </div>
      </div>

      {scan.error && (
        <div className="mt-6 rounded-lg border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-300">
          {scan.error}
        </div>
      )}

      <div className="mt-8 grid gap-4 lg:grid-cols-[1.4fr_repeat(5,1fr)]">
        <div className="panel flex items-center justify-around p-5">
          <ScoreRing label="Security score" value={scan.securityScore} />
          <ScoreRing label="Coverage" value={scan.coverageScore} suffix="%" />
        </div>
        {Object.entries(counts).map(([severity, count]) => (
          <div className="panel p-5" key={severity}>
            <p className="eyebrow">{severity}</p>
            <p className="mt-4 text-3xl font-semibold">{count}</p>
          </div>
        ))}
      </div>

      <section className="mt-6 grid gap-4 lg:grid-cols-4">
        <InsightCard
          icon={<ShieldAlert size={18} />}
          title="Risk readout"
          value={insight.riskReadout}
          detail={insight.riskDetail}
        />
        <InsightCard
          icon={<Route size={18} />}
          title="Attack surface"
          value={insight.surfaceReadout}
          detail={insight.surfaceDetail}
        />
        <InsightCard
          icon={<Gauge size={18} />}
          title="Fix order"
          value={insight.fixReadout}
          detail={insight.fixDetail}
        />
        <InsightCard
          icon={<OctagonX size={18} />}
          title="Evasion signals"
          value={insight.evasionReadout}
          detail={insight.evasionDetail}
        />
      </section>

      <div className="mt-6 grid gap-6 xl:grid-cols-[1fr_360px]">
        <section className="panel overflow-hidden">
          <div className="border-b border-line p-5">
            <h2 className="font-semibold">Prioritized findings</h2>
            <p className="mt-1 text-xs text-slate-500">
              Each row includes the evidence category, affected location, likely
              impact and next action.
            </p>
          </div>
          {scan.findings.length === 0 ? (
            <div className="muted p-12 text-center">
              No findings were produced by completed Phase 1 checks.
            </div>
          ) : (
            <div className="divide-y divide-line/70">
              {insight.prioritizedFindings.map((finding) => (
                <FindingRow finding={finding} key={finding.id} />
              ))}
            </div>
          )}
        </section>
        <aside className="space-y-4">
          <ReportsPanel scanId={id} />
          <div className="panel p-5">
            <p className="eyebrow">Category distribution</p>
            <div className="mt-4 space-y-3">
              {insight.categories.length ? (
                insight.categories.map(([category, count]) => (
                  <Bar
                    key={category}
                    label={category}
                    value={count}
                    max={insight.maxCategory}
                  />
                ))
              ) : (
                <p className="text-sm text-slate-500">
                  No categories to summarize.
                </p>
              )}
            </div>
          </div>
          <div className="panel p-5">
            <p className="eyebrow">Coverage interpretation</p>
            <p className="mt-3 text-sm leading-6 text-slate-400">
              {insight.coverageInterpretation}
            </p>
          </div>
          <div className="panel p-5">
            <p className="eyebrow">Adversarial coverage</p>
            <div className="mt-4 space-y-3">
              {insight.coverageRows.map(([label, value]) => (
                <div
                  className="flex items-center justify-between gap-4 text-sm"
                  key={label}
                >
                  <span className="text-slate-400">{label}</span>
                  <span className="font-medium text-slate-200">{value}</span>
                </div>
              ))}
            </div>
          </div>
          {scan.technologies.length > 0 && (
            <div className="panel p-5">
              <p className="eyebrow">Detected stack</p>
              <div className="mt-4 flex flex-wrap gap-2">
                {scan.technologies.slice(0, 12).map((technology) => (
                  <span
                    className="rounded-full border border-line bg-white/[.03] px-3 py-1 text-xs text-slate-300"
                    key={technology.id}
                  >
                    {technology.name}
                  </span>
                ))}
              </div>
            </div>
          )}
          <Link
            className="button-secondary w-full"
            href={`/scans/${id}/attack-surface`}
          >
            <Layers3 size={15} />
            View attack surface
          </Link>
          <InsightNote text="Automated scanning cannot prove the absence of every vulnerability. Use this report to prioritize manual review and retesting." />
        </aside>
      </div>
    </>
  );
}

function ReportsPanel({ scanId }: { scanId: string }) {
  const reports = [
    {
      label: "Executive PDF",
      href: `/api/scans/${scanId}/report?format=pdf&type=executive`,
      action: "Download Executive PDF",
      detail: "Management summary, posture, top risks and remediation roadmap.",
    },
    {
      label: "Full Technical PDF",
      href: `/api/scans/${scanId}/report?format=pdf&type=technical`,
      action: "Download Full Technical PDF",
      detail:
        "Detailed vulnerabilities, evidence excerpts, routes and diagnostics.",
    },
    {
      label: "HTML Report",
      href: `/api/scans/${scanId}/report?format=html`,
      action: "Download HTML",
      detail: "Portable browser-readable report.",
    },
    {
      label: "JSON Export",
      href: `/api/scans/${scanId}/report?format=json`,
      action: "Download JSON",
      detail: "Complete structured scan data.",
    },
    {
      label: "CSV Export",
      href: `/api/scans/${scanId}/report?format=csv`,
      action: "Download CSV",
      detail: "Findings spreadsheet export.",
    },
    {
      label: "SARIF Export",
      href: `/api/scans/${scanId}/report?format=sarif`,
      action: "Download SARIF",
      detail: "Static-analysis compatible findings export.",
    },
  ];

  return (
    <div className="panel p-5">
      <p className="eyebrow">Reports</p>
      <div className="mt-4 space-y-3">
        {reports.map((report) => (
          <div
            className="rounded-lg border border-line bg-white/[.02] p-3"
            key={report.label}
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-sm font-medium text-slate-200">
                  {report.label}
                </p>
                <p className="mt-1 text-xs leading-5 text-slate-500">
                  {report.detail}
                </p>
              </div>
              <a
                className="button-secondary shrink-0 px-3 py-2 text-xs"
                href={report.href}
              >
                <Download size={13} />
                {report.action}
              </a>
            </div>
          </div>
        ))}
        <div className="rounded-lg border border-line bg-white/[.02] p-3">
          <p className="text-sm font-medium text-slate-200">
            Raw Evidence Archive
          </p>
          <p className="mt-1 text-xs leading-5 text-slate-500">
            Persisted findings, route inventory, evidence excerpts, stages,
            reports and integrity metadata.
          </p>
          <a
            className="button-secondary mt-3 px-3 py-2 text-xs"
            href={`/api/scans/${scanId}/evidence-archive`}
          >
            Download archive
          </a>
        </div>
      </div>
    </div>
  );
}

function buildInsight(scan: Scan) {
  const prioritizedFindings = [...scan.findings].sort(
    (a, b) =>
      (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9),
  );
  const highest = prioritizedFindings[0]?.severity ?? "NONE";
  const highOrWorse = scan.findings.filter((finding) =>
    ["CRITICAL", "HIGH"].includes(finding.severity),
  );
  const testedRoutes = scan.endpoints.filter(
    (endpoint) => endpoint.tested !== false,
  ).length;
  const externalRoutes = scan.endpoints.filter(
    (endpoint) => endpoint.external,
  ).length;
  const hiddenRoutes = scan.endpoints.filter((endpoint) =>
    endpoint.discoveredBy?.startsWith("hidden-surface"),
  ).length;
  const authenticatedRoutes = scan.endpoints.filter(
    (endpoint) => endpoint.discoveredBy === "authenticated-route-seed",
  ).length;
  const manualReview = scan.findings.filter(
    (finding) => finding.confidence === "MANUAL_REVIEW",
  ).length;
  const evasionSignals = scan.findings.filter(
    (finding) =>
      finding.category === "Evasion signal" ||
      finding.scannerRuleId?.startsWith("evasion/"),
  );
  const roleComparisonFindings = scan.findings.filter(
    (finding) =>
      finding.category === "Role comparison" ||
      finding.scannerRuleId?.startsWith("role-comparison/"),
  ).length;
  const parameters = scan.endpoints.flatMap(
    (endpoint) => endpoint.parameters ?? [],
  );
  const sensitiveParameters = parameters.filter((parameter) =>
    /role|admin|owner|tenant|price|amount|status|state|redirect|callback|return|url|file|path|template|query|filter|sort|token|secret/i.test(
      parameter.name,
    ),
  ).length;
  const differentialStages = scan.stages.filter((stage) =>
    ["hidden-surface", "adaptive-differential", "manual-review"].includes(
      stage.key,
    ),
  );
  const categories = Object.entries(
    scan.findings.reduce<Record<string, number>>(
      (acc, finding) => ({
        ...acc,
        [finding.category]: (acc[finding.category] ?? 0) + 1,
      }),
      {},
    ),
  ).sort((a, b) => b[1] - a[1]);
  const topCategory = categories[0]?.[0];
  const maxCategory = Math.max(1, ...categories.map(([, count]) => count));
  const score = scan.securityScore ?? 100;
  const coverage = scan.coverageScore ?? 0;

  return {
    prioritizedFindings,
    categories,
    maxCategory,
    riskReadout:
      highest === "NONE"
        ? "No automated findings"
        : `${highest} is the highest severity`,
    riskDetail: highOrWorse.length
      ? `${highOrWorse.length} high-priority issue${highOrWorse.length === 1 ? "" : "s"} should be reviewed before lower-severity hygiene work.`
      : `Security score is ${score}/100 with no high-severity passive findings.`,
    surfaceReadout: `${testedRoutes}/${scan.endpoints.length} routes tested`,
    surfaceDetail: externalRoutes
      ? `${externalRoutes} external route${externalRoutes === 1 ? " was" : "s were"} discovered and included in passive route testing.`
      : `${scan.services.length} service${scan.services.length === 1 ? "" : "s"}, ${testedRoutes} tested route${testedRoutes === 1 ? "" : "s"} and ${hiddenRoutes} hidden candidate${hiddenRoutes === 1 ? "" : "s"} were recorded.`,
    fixReadout: topCategory ? `Start with ${topCategory}` : "No fix queue yet",
    fixDetail: topCategory
      ? `${topCategory} has the largest cluster of findings, so one platform-level change may reduce several observations at once.`
      : "Keep the evidence export as a baseline for future comparison.",
    evasionReadout: evasionSignals.length
      ? `${evasionSignals.length} signal${evasionSignals.length === 1 ? "" : "s"} detected`
      : "No evasion signals",
    evasionDetail: evasionSignals.length
      ? "Review bot-management, crawl suppression and client-profile differences before treating scan coverage as complete."
      : "No bot challenge, cloaking or crawl-suppression signal was recorded by the automated checks.",
    coverageInterpretation:
      coverage >= 85
        ? "Coverage is strong for the configured passive scan mode. Remaining risk is mostly around authenticated flows, business logic and active exploit classes that Phase 1 does not attempt."
        : coverage >= 60
          ? "Coverage is moderate. Review crawl limits, blocked routes, redirects and response errors before treating the result as representative."
          : "Coverage is low. The scan may have been constrained by robots, response errors, private-network policy, redirects or crawl limits; prioritize expanding discovery before relying on severity totals.",
    coverageRows: [
      ["Routes discovered", scan.endpoints.length],
      ["Routes tested", testedRoutes],
      ["Parameters found", parameters.length],
      ["Sensitive fields", sensitiveParameters],
      ["Hidden candidates", hiddenRoutes],
      ["Authenticated routes", authenticatedRoutes],
      ["Technologies inferred", scan.technologies.length],
      ["Manual-review tasks", manualReview],
      ["Role findings", roleComparisonFindings],
      ["Evasion signals", evasionSignals.length],
      [
        "Adversarial stages",
        `${differentialStages.filter((stage) => stage.status === "COMPLETED").length}/${differentialStages.length}`,
      ],
      ["External routes tested", externalRoutes],
    ] as Array<[string, string | number]>,
  };
}

function FindingRow({ finding }: { finding: Finding }) {
  return (
    <Link
      href={`/findings/${finding.id}`}
      className="block p-5 transition hover:bg-white/[.02]"
    >
      <div className="flex flex-wrap items-start gap-4">
        <SeverityDot severity={finding.severity} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-sm font-medium text-slate-200">
              {finding.title}
            </p>
            <StatusPill value={finding.confidence} />
            <StatusPill value={finding.status} />
          </div>
          <p className="mt-2 line-clamp-2 text-sm leading-6 text-slate-400">
            {finding.impact}
          </p>
          <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-600">
            <span>{finding.category}</span>
            {finding.cwe && <span>{finding.cwe}</span>}
            {finding.httpMethod && <span>{finding.httpMethod}</span>}
            {finding.affectedUrl && (
              <span className="max-w-full truncate">{finding.affectedUrl}</span>
            )}
          </div>
        </div>
        <div className="w-full rounded-lg border border-line bg-black/20 p-3 text-xs leading-5 text-slate-500 lg:w-64">
          <span className="font-medium text-slate-300">Next action: </span>
          {firstSentence(finding.remediation)}
        </div>
      </div>
    </Link>
  );
}

function InsightCard({
  icon,
  title,
  value,
  detail,
}: {
  icon: ReactNode;
  title: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="panel p-5">
      <div className="flex items-center gap-2 text-signal">
        {icon}
        <p className="eyebrow">{title}</p>
      </div>
      <p className="mt-4 text-lg font-semibold text-slate-100">{value}</p>
      <p className="mt-2 text-sm leading-6 text-slate-400">{detail}</p>
    </div>
  );
}

function Bar({
  label,
  value,
  max,
}: {
  label: string;
  value: number;
  max: number;
}) {
  return (
    <div>
      <div className="flex justify-between gap-3 text-xs">
        <span className="truncate text-slate-400">{label}</span>
        <span className="text-slate-600">{value}</span>
      </div>
      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-line">
        <div
          className="h-full rounded-full bg-signal"
          style={{ width: `${Math.max(8, Math.round((value / max) * 100))}%` }}
        />
      </div>
    </div>
  );
}

function InsightNote({ text }: { text: string }) {
  return (
    <div className="rounded-lg border border-cyan/15 bg-cyan/[.04] p-5 text-xs leading-5 text-slate-400">
      {text}
    </div>
  );
}

function StageIcon({ status }: { status: string }) {
  if (status === "RUNNING")
    return <LoaderCircle size={17} className="animate-spin text-signal" />;
  if (status === "COMPLETED")
    return <Check size={17} className="text-signal" />;
  if (status === "FAILED")
    return <OctagonX size={17} className="text-red-400" />;
  return <Circle size={14} className="text-slate-700" />;
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <div className="text-2xl font-semibold text-white">{value}</div>
      <div className="mt-1 text-[10px] uppercase tracking-wider text-slate-600">
        {label}
      </div>
    </div>
  );
}

function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    CRITICAL: "bg-fuchsia-400",
    HIGH: "bg-red-400",
    MEDIUM: "bg-amber-400",
    LOW: "bg-cyan",
    INFO: "bg-slate-500",
  };
  return (
    <span
      className={`mt-1 size-2.5 shrink-0 rounded-full ${colors[severity]}`}
    />
  );
}

function firstSentence(value: string) {
  return value.split(/(?<=\.)\s+/)[0] ?? value;
}

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat("en-AU", {
    dateStyle: "short",
    hour12: false,
    timeStyle: "medium",
    timeZone: "Australia/Sydney",
  }).format(new Date(value));
}
