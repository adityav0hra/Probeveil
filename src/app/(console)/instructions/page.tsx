import Link from "next/link";
import {
  BellRing,
  Boxes,
  CircleAlert,
  FileArchive,
  FileText,
  GitFork,
  HeartPulse,
  Inbox,
  KeyRound,
  ListChecks,
  PlugZap,
  Radar,
  ScrollText,
  Settings2,
  ShieldAlert,
  ShieldPlus,
  SlidersHorizontal,
} from "lucide-react";

const guide = [
  {
    title: "Console overview",
    href: "/admin",
    icon: Radar,
    body: "Use the overview to see recent scan volume, active work, high-risk findings, coverage and failed scans. Start from here when you need the fastest picture of system state.",
    checks: [
      "Open the latest scan before trusting totals.",
      "Review failed scans before starting more work.",
      "Use the high-risk count as the triage starting point.",
    ],
  },
  {
    title: "New scan",
    href: "/scans/new",
    icon: ShieldPlus,
    body: "Create approved website scans. Enter the target URL, choose QUICK, FULL or MAXIMUM, select policy profiles and enable optional authenticated, role, browser-rendered and API coverage.",
    checks: [
      "Confirm you own or control the target.",
      "Use QUICK for smoke checks, FULL for normal coverage and MAXIMUM for deeper review.",
      "Attach credential profiles only when they belong to that target.",
    ],
  },
  {
    title: "Scan modes and profiles",
    href: "/settings/profiles",
    icon: SlidersHorizontal,
    body: "Profiles save repeatable scan settings: depth, engines, screenshots, browser rendering, auth, API checks, notifications and alert thresholds.",
    checks: [
      "Use Light weekly for frequent low-impact monitoring.",
      "Use Deep monthly for broader coverage.",
      "Use Authenticated app, API heavy or Compliance evidence when the target needs those controls.",
    ],
  },
  {
    title: "Authenticated scanning",
    href: "/settings/vault",
    icon: KeyRound,
    body: "Credential profiles let scans see signed-in pages such as dashboards, exports, settings, invoices and admin routes without re-entering cookies or headers each time.",
    checks: [
      "Store credentials in the vault, not in notes or contact messages.",
      "Set expiration reminders and validate profiles before scans.",
      "Use separate profiles for anonymous, normal user, admin and tenant-specific users.",
    ],
  },
  {
    title: "Role comparison",
    href: "/scans/new",
    icon: ListChecks,
    body: "Role comparison checks anonymous, standard user, admin and cross-account access patterns to find broken access control, IDOR, privilege issues and data leakage.",
    checks: [
      "Compare user A against user B when testing tenant boundaries.",
      "Review role-only findings even when severity is not critical.",
      "Retest after authorization fixes.",
    ],
  },
  {
    title: "Browser-rendered scanning",
    href: "/scans/new",
    icon: Radar,
    body: "Browser rendering uses a real page session to discover routes, buttons, forms, client-side navigation, fetch calls and JavaScript-only content.",
    checks: [
      "Enable it for modern React, Vue, Angular and single-page apps.",
      "Check discovered API calls after each browser scan.",
      "Use screenshots when the report needs visual proof.",
    ],
  },
  {
    title: "API testing",
    href: "/scans/new",
    icon: GitFork,
    body: "API coverage looks for OpenAPI or Swagger docs, GraphQL behavior, REST parameters, auth-header differences, mass assignment, pagination and export weaknesses.",
    checks: [
      "Provide known API entry points when discovery misses private docs.",
      "Compare authenticated and unauthenticated responses.",
      "Review schema coverage before judging API completeness.",
    ],
  },
  {
    title: "External scanner engines",
    href: "/settings/scanners",
    icon: Settings2,
    body: "Scanner settings show optional adapters such as Nuclei, ZAP baseline, SSLyze or testssl, Nikto-style checks, Semgrep hints and technology-specific checks.",
    checks: [
      "Install only the engines you can operate safely.",
      "Expect richer results when engines are installed on the worker environment.",
      "Check scanner health after dependency changes.",
    ],
  },
  {
    title: "Safety controls",
    href: "/settings/safety",
    icon: ShieldAlert,
    body: "Safety settings protect targets with ownership approvals, request limits, business-hour windows, allowed domains and blocked dangerous payload classes.",
    checks: [
      "Approve domains before deep scans.",
      "Lower rate limits for fragile production sites.",
      "Keep destructive payload classes excluded unless explicitly approved.",
    ],
  },
  {
    title: "Scan results",
    href: "/admin",
    icon: CircleAlert,
    body: "Open a scan to inspect status, coverage, route inventory, technologies, evasion signals, findings, evidence, report exports and downloadable archives.",
    checks: [
      "A low score means the scan observed high-risk findings or weak security signals.",
      "A failed scan means the scan record exists but the worker or control-plane step did not complete.",
      "Use the run retest control after remediation, not as a substitute for reviewing evidence.",
    ],
  },
  {
    title: "Evidence archive",
    href: "/reports",
    icon: FileArchive,
    body: "Archives package request and response pairs, headers, screenshots, route inventory, hashes, evidence excerpts and scanner logs for offline review.",
    checks: [
      "Download archives before deleting scan history.",
      "Use archives when a developer needs exact reproduction context.",
      "Keep audit logs separate from deletable scan records.",
    ],
  },
  {
    title: "Issues and deduplication",
    href: "/issues",
    icon: ListChecks,
    body: "Issues maintain persistent vulnerability identity across scans, so the same problem keeps lifecycle history instead of appearing as a brand-new item each time.",
    checks: [
      "Triage issues by identity, not just by scan.",
      "Watch first-seen, last-seen and occurrence count.",
      "Mark fixed only when retest evidence supports it.",
    ],
  },
  {
    title: "False-positive workflow",
    href: "/issues",
    icon: CircleAlert,
    body: "Findings can be confirmed, marked false positive, accepted as risk, fixed, retest passed or retest failed, with notes and reviewer history.",
    checks: [
      "Use false positive for incorrect detections.",
      "Use accepted risk for real issues the business knowingly accepts.",
      "Keep notes specific enough for future reviewers.",
    ],
  },
  {
    title: "Retesting",
    href: "/issues",
    icon: Radar,
    body: "Targeted retests focus on one finding and compare before and after evidence to show whether the issue disappeared.",
    checks: [
      "Retest the affected URL or parameter, not only the whole site.",
      "Review retest evidence before closing work.",
      "Use retest failed when the issue is still reproducible.",
    ],
  },
  {
    title: "Remediation assistant",
    href: "/issues",
    icon: FileText,
    body: "Each finding should provide affected code pattern, exact fix guidance, verification steps, retest control and a developer ticket generator.",
    checks: [
      "Read the impact before choosing priority.",
      "Use verification steps after the developer fix.",
      "Generate a ticket when work needs tracking outside Probeveil.",
    ],
  },
  {
    title: "Asset inventory",
    href: "/assets",
    icon: Boxes,
    body: "Assets track long-term domains, endpoints, APIs, exposed services, technologies, login pages, admin routes and changes over time.",
    checks: [
      "Review new assets after every deep scan.",
      "Treat unexpected admin routes as high-priority review items.",
      "Use missing assets to spot removed or unreachable surfaces.",
    ],
  },
  {
    title: "Attack surface and paths",
    href: "/attack-surface",
    icon: GitFork,
    body: "Attack surface views show discovered routes and services. Attack paths connect stored findings when the data supports a plausible chain.",
    checks: [
      "Use paths as prioritization hints, not automatic proof.",
      "Follow the linked findings for evidence.",
      "Fix shared root causes before isolated symptoms.",
    ],
  },
  {
    title: "Reports and PDFs",
    href: "/reports",
    icon: FileText,
    body: "Reports include executive, technical, OWASP Top 10, CWE, PCI-style controls, SOC 2 evidence, remediation tracking, JSON, CSV, SARIF and evidence archive exports.",
    checks: [
      "Use executive reports for business review.",
      "Use technical reports and archives for developers.",
      "Use compliance modes when evidence needs a recognizable framework.",
    ],
  },
  {
    title: "Contact enquiries",
    href: "/contact-enquiries",
    icon: Inbox,
    body: "The public contact form creates enquiries for product questions, review requests, demos, partnerships, support and general messages.",
    checks: [
      "Reply from the enquiry detail page or mailto link.",
      "Change status as work moves from new to closed.",
      "Never ask visitors to send secrets through the form.",
    ],
  },
  {
    title: "Integrations",
    href: "/settings/integrations",
    icon: PlugZap,
    body: "Integrations connect high-severity findings, scan summaries, failed scans and tickets to Slack, Discord, Teams, Jira, Linear, GitHub Issues and email.",
    checks: [
      "Configure webhooks or API tokens in environment variables.",
      "Test each provider before relying on alerts.",
      "Use ticket creation for work that needs ownership.",
    ],
  },
  {
    title: "Scheduling and notifications",
    href: "/settings/automation",
    icon: BellRing,
    body: "Automation runs weekly or monthly scans and sends summaries, failed-scan alerts, high-severity alerts and new-finding diffs when delivery is configured.",
    checks: [
      "Set the notification recipient before enabling schedules.",
      "Use failed-scan alerts for operational reliability.",
      "Use new-finding diffs to focus on what changed.",
    ],
  },
  {
    title: "Audit logs",
    href: "/audit",
    icon: ScrollText,
    body: "Audit logs preserve control-plane actions separately from scan history. Scan records can be deleted; audit logs are retained.",
    checks: [
      "Use audit logs to review who changed operational state.",
      "Do not treat scan history deletion as audit deletion.",
      "Keep audit review separate from normal finding triage.",
    ],
  },
  {
    title: "System health",
    href: "/health",
    icon: HeartPulse,
    body: "Health pages show scanner, worker and platform readiness so failed scans can be separated from target-specific findings.",
    checks: [
      "Check health before troubleshooting a failed scan.",
      "Review missing dependencies after deployment changes.",
      "Confirm email and scanner configuration before scheduled work.",
    ],
  },
];

export default function InstructionsPage() {
  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="eyebrow">Admin manual</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">
            Instructions
          </h1>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">
            Use this as the operating guide for Probeveil. It covers every
            console area, the expected workflow and what to verify before you
            trust results or send reports.
          </p>
        </div>
        <Link className="button" href="/scans/new">
          Start new scan
        </Link>
      </div>

      <section className="mt-8 grid gap-4 xl:grid-cols-[260px_1fr]">
        <aside className="panel h-fit p-4">
          <p className="eyebrow px-2">Contents</p>
          <div className="mt-3 max-h-[70vh] space-y-1 overflow-auto pr-1">
            {guide.map((item) => (
              <a
                className="block rounded-md px-2 py-2 text-xs text-slate-500 transition hover:bg-white/[.03] hover:text-white"
                href={`#${slug(item.title)}`}
                key={item.title}
              >
                {item.title}
              </a>
            ))}
          </div>
        </aside>

        <div className="space-y-4">
          {guide.map(({ title, href, icon: Icon, body, checks }) => (
            <article
              className="panel scroll-mt-6 p-5"
              id={slug(title)}
              key={title}
            >
              <div className="flex flex-wrap items-start justify-between gap-4 lg:flex-nowrap">
                <div className="flex min-w-0 flex-1 gap-4">
                  <span className="grid size-10 shrink-0 place-items-center rounded-md border border-line text-signal">
                    <Icon size={18} />
                  </span>
                  <div>
                    <h2 className="text-lg font-semibold text-white">
                      {title}
                    </h2>
                    <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
                      {body}
                    </p>
                  </div>
                </div>
                <Link
                  className="button-secondary shrink-0 px-3 py-2 text-xs"
                  href={href}
                >
                  Open
                </Link>
              </div>
              <div className="mt-5 grid gap-2 md:grid-cols-3">
                {checks.map((check) => (
                  <p
                    className="rounded-md border border-line bg-black/10 p-3 text-xs leading-5 text-slate-500"
                    key={check}
                  >
                    {check}
                  </p>
                ))}
              </div>
            </article>
          ))}
        </div>
      </section>
    </>
  );
}

function slug(value: string) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}
