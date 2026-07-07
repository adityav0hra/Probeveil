import Image from "next/image";
import Link from "next/link";
import {
  Activity,
  ArrowRight,
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
    title: "Surface discovery",
    body: "Crawls internal and external routes, follows redirects, records forms, scripts, security headers, exposed services and reachable application paths.",
    icon: Globe2,
    accent: "text-red-300",
  },
  {
    title: "Evidence-backed findings",
    body: "Every issue is tied to request data, response signals, confidence, affected URLs and remediation notes so reports feel usable instead of vague.",
    icon: ShieldCheck,
    accent: "text-red-300",
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
      <header className="mx-auto flex max-w-7xl items-center justify-between border-b border-line px-5 py-5 lg:px-8">
        <Link href="/" className="flex items-center gap-3">
          <Image
            alt="Probeveil"
            className="size-10 rounded-md border border-signal/30 bg-signal/10"
            height={40}
            src="/probeveil-icon-red.png"
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

      <section className="relative mx-auto max-w-7xl px-5 pb-12 pt-10 lg:px-8 lg:pb-14 lg:pt-14">
        <div className="max-w-3xl">
          <p className="eyebrow">Website security operations</p>
          <h1 className="mt-5 max-w-3xl text-4xl font-semibold leading-tight tracking-tight text-white sm:text-5xl">
            Probeveil
          </h1>
          <p className="mt-5 max-w-2xl text-base leading-7 text-slate-300">
            A control console for approved website scanning, evidence review,
            issue tracking, scheduling and report delivery.
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

        <div className="mt-10 grid gap-4 lg:grid-cols-[1.25fr_.75fr]">
          <section className="panel overflow-hidden">
            <div className="flex items-center justify-between border-b border-line px-5 py-4">
              <div>
                <p className="eyebrow">Operations snapshot</p>
                <h2 className="mt-1 font-semibold">
                  Coverage and evidence flow
                </h2>
              </div>
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <Activity size={14} className="text-signal" />
                Active
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
                    <div className="grid size-8 shrink-0 place-items-center rounded-md border border-signal/25 bg-signal/10 text-xs font-semibold text-signal">
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
                ["0", "Unreviewed criticals tolerated"],
                ["24/7", "Scheduled scan queue"],
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

      <section className="border-y border-line bg-[#0b0c0f]">
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
