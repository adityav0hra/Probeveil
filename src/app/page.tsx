import Image from "next/image";
import Link from "next/link";
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  FileText,
  Gauge,
  Globe2,
  LockKeyhole,
  Mail,
  Radar,
  ShieldCheck,
  TerminalSquare,
} from "lucide-react";
import { auth } from "@/lib/auth";

const capabilityCards = [
  {
    title: "Full website discovery",
    body: "Crawls internal and external routes, follows redirects, records forms, scripts, security headers, exposed services and reachable application paths.",
    icon: Globe2,
    accent: "text-sky-300",
  },
  {
    title: "Evidence-backed findings",
    body: "Every issue is tied to request data, response signals, confidence, affected URLs and remediation notes so reports feel usable instead of vague.",
    icon: ShieldCheck,
    accent: "text-emerald-300",
  },
  {
    title: "Evasion-aware coverage",
    body: "Flags bot challenges, crawl suppression, throttling, hidden traps and client-profile differences that can make scans miss reachable application behavior.",
    icon: TerminalSquare,
    accent: "text-amber-300",
  },
  {
    title: "Professional PDF reports",
    body: "Generates polished reports with security scores, severity breakdowns, validated evidence, route coverage and clear remediation priorities.",
    icon: FileText,
    accent: "text-rose-300",
  },
];

const flow = [
  "Submit a website",
  "Discover reachable routes",
  "Run layered checks",
  "Review evidence",
  "Export the report",
];

const metrics = [
  ["Coverage", "Route depth, assets, forms and external links"],
  ["Confidence", "Signal strength behind every finding"],
  ["Evasion", "Bot-management and crawl-control signals"],
  ["Impact", "Severity, exploitability and business context"],
];

export default async function HomePage() {
  const session = await auth();
  const adminHref = session ? "/admin" : "/login";
  const adminLabel = session ? "Open admin console" : "Admin login";

  return (
    <main className="min-h-screen overflow-hidden">
      <header className="mx-auto flex max-w-7xl items-center justify-between px-5 py-5 lg:px-8">
        <Link href="/" className="flex items-center gap-3">
          <Image
            alt="Probeveil"
            className="size-10 rounded-lg border border-signal/25 bg-signal/10"
            height={40}
            src="/probeveil-icon.png"
            width={40}
          />
          <div>
            <div className="font-semibold tracking-tight text-white">
              Probeveil
            </div>
            <div className="text-[10px] uppercase tracking-[.18em] text-slate-600">
              Website security
            </div>
          </div>
        </Link>
        <nav className="flex items-center gap-2">
          <Link
            className="button-secondary hidden sm:inline-flex"
            href="/contact"
          >
            <Mail size={15} />
            Contact
          </Link>
          <Link className="button" href={adminHref}>
            {adminLabel}
            {session ? <ArrowRight size={15} /> : <LockKeyhole size={15} />}
          </Link>
        </nav>
      </header>

      <section className="relative mx-auto max-w-7xl px-5 pb-12 pt-10 lg:px-8 lg:pb-16 lg:pt-16">
        <div className="pointer-events-none absolute inset-x-5 top-8 -z-10 h-[620px] rounded-[2rem] border border-white/[.04] bg-[linear-gradient(135deg,rgba(124,248,196,.08),rgba(56,189,248,.06)_35%,rgba(251,113,133,.05)_70%,transparent)]" />
        <div className="pointer-events-none absolute right-[-70px] top-14 -z-10 hidden opacity-[.18] md:block">
          <Image
            alt=""
            className="size-[460px]"
            height={460}
            src="/probeveil-icon.png"
            width={460}
          />
        </div>

        <div className="max-w-4xl">
          <p className="eyebrow">Probeveil security platform</p>
          <h1 className="mt-5 max-w-3xl text-5xl font-semibold leading-[1.03] tracking-tight text-white sm:text-6xl lg:text-7xl">
            Probeveil
          </h1>
          <p className="mt-6 max-w-2xl text-lg leading-8 text-slate-300">
            Website security scanning with deep route discovery, evidence-rich
            vulnerability analysis, operational dashboards and professional PDF
            reporting for administrators.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link className="button" href="/contact">
              Contact us
              <Mail size={16} />
            </Link>
            <Link className="button-secondary" href={adminHref}>
              {adminLabel}
              {session ? <ArrowRight size={16} /> : <LockKeyhole size={16} />}
            </Link>
          </div>
        </div>

        <div className="mt-12 grid gap-4 lg:grid-cols-[1.2fr_.8fr]">
          <section className="panel overflow-hidden">
            <div className="flex items-center justify-between border-b border-line px-5 py-4">
              <div>
                <p className="eyebrow">Live scan cockpit</p>
                <h2 className="mt-1 font-semibold">Admin dashboard preview</h2>
              </div>
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <Activity size={14} className="text-signal" />
                Online
              </div>
            </div>
            <div className="grid gap-4 p-5 md:grid-cols-4">
              {metrics.map(([label, body]) => (
                <div
                  className="rounded-lg border border-line bg-white/[.025] p-4"
                  key={label}
                >
                  <p className="text-sm font-medium text-white">{label}</p>
                  <p className="mt-2 text-xs leading-5 text-slate-500">
                    {body}
                  </p>
                </div>
              ))}
            </div>
            <div className="border-t border-line p-5">
              <div className="grid gap-3 md:grid-cols-5">
                {flow.map((item, index) => (
                  <div className="flex items-center gap-3 md:block" key={item}>
                    <div className="grid size-8 shrink-0 place-items-center rounded-lg border border-signal/20 bg-signal/10 text-xs font-semibold text-signal">
                      {index + 1}
                    </div>
                    <p className="mt-0 text-sm text-slate-300 md:mt-3">
                      {item}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </section>

          <section className="panel p-5">
            <p className="eyebrow">Operational signal</p>
            <div className="mt-5 space-y-4">
              {[
                ["0", "Critical blind spots tolerated"],
                ["24/7", "Worker-ready scan queue"],
                ["PDF", "Executive and technical reports"],
              ].map(([value, label]) => (
                <div
                  className="flex items-center justify-between gap-4 border-b border-line pb-4 last:border-0 last:pb-0"
                  key={label}
                >
                  <span className="text-3xl font-semibold text-white">
                    {value}
                  </span>
                  <span className="max-w-40 text-right text-sm text-slate-500">
                    {label}
                  </span>
                </div>
              ))}
            </div>
          </section>
        </div>
      </section>

      <section className="border-y border-line bg-[#090c11]/70">
        <div className="mx-auto grid max-w-7xl gap-4 px-5 py-12 lg:grid-cols-4 lg:px-8">
          {capabilityCards.map(({ title, body, icon: Icon, accent }) => (
            <article className="panel p-5" key={title}>
              <Icon className={accent} size={22} />
              <h2 className="mt-5 text-lg font-semibold text-white">{title}</h2>
              <p className="mt-3 text-sm leading-6 text-slate-400">{body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="mx-auto grid max-w-7xl gap-8 px-5 py-14 lg:grid-cols-[.85fr_1.15fr] lg:px-8">
        <div>
          <p className="eyebrow">Built for administrators</p>
          <h2 className="mt-3 text-3xl font-semibold tracking-tight text-white">
            The public site is simple. The admin console is where the depth
            lives.
          </h2>
          <p className="mt-4 text-sm leading-7 text-slate-400">
            Probeveil keeps scanning, evidence, reports, scanner health and audit
            logs inside the signed-in dashboard while this landing page gives
            the product a clean front door.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <Link className="button" href="/contact">
              Contact us
              <Mail size={16} />
            </Link>
            <Link className="button-secondary" href={adminHref}>
              {adminLabel}
              {session ? <ArrowRight size={16} /> : <LockKeyhole size={16} />}
            </Link>
          </div>
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          {[
            "Authenticated dashboard access",
            "Scan mode selection and queued workers",
            "Route coverage and finding detail",
            "Report PDF generation",
            "Scanner health visibility",
            "Audit logs retained separately",
          ].map((item) => (
            <div
              className="flex items-center gap-3 rounded-lg border border-line bg-white/[.025] px-4 py-3 text-sm text-slate-300"
              key={item}
            >
              <CheckCircle2 className="text-signal" size={17} />
              {item}
            </div>
          ))}
        </div>
      </section>

      <footer className="border-t border-line px-5 py-8 lg:px-8">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3 text-sm text-slate-500">
            <Radar size={16} className="text-signal" />
            Probeveil website security scanning
          </div>
          <div className="flex flex-wrap gap-2">
            <Link className="button-secondary" href="/contact">
              Contact us
              <Mail size={16} />
            </Link>
            <Link className="button-secondary" href="/admin">
              Admin dashboard
              <Gauge size={16} />
            </Link>
          </div>
        </div>
      </footer>
    </main>
  );
}
