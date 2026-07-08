import Image from "next/image";
import Link from "next/link";
import { ArrowRight, LockKeyhole, Mail } from "lucide-react";
import { auth } from "@/lib/auth";

const signals = [
  ["Discovery", "Routes, services, forms and APIs"],
  ["Evidence", "Findings with proof and exports"],
  ["Workflow", "Review, retest, notify, report"],
];

export default async function HomePage() {
  const session = await auth();
  const adminHref = session ? "/admin" : "/login";
  const adminLabel = session ? "Open admin console" : "Admin login";

  return (
    <main className="flex h-[100svh] overflow-hidden">
      <div className="flex min-h-0 w-full flex-col">
        <header className="shrink-0 border-b border-line">
          <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4 lg:px-8">
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
                className="button hidden px-5 sm:inline-flex"
                href="/contact"
              >
                <Mail size={15} />
                Contact
              </Link>
              <Link className="button-secondary" href={adminHref}>
                {adminLabel}
                {session ? <ArrowRight size={15} /> : <LockKeyhole size={15} />}
              </Link>
            </nav>
          </div>
        </header>

        <section className="mx-auto grid min-h-0 w-full max-w-7xl flex-1 items-center gap-6 px-5 py-6 lg:grid-cols-[minmax(0,1fr)_360px] lg:px-8">
          <div className="max-w-4xl">
            <p className="eyebrow">Website security operations</p>
            <h1 className="mt-4 max-w-4xl text-5xl font-semibold leading-[1.02] tracking-tight text-white sm:text-6xl lg:text-7xl">
              Probeveil security operations
            </h1>
            <p className="mt-5 max-w-2xl text-base leading-7 text-slate-300">
              A clean control console for approved website scanning, evidence
              review, issue tracking, scheduling and report delivery.
            </p>
            <div className="mt-7 flex flex-wrap gap-3">
              <Link className="button px-6 py-3 text-base" href="/contact">
                Contact Probeveil
                <Mail size={17} />
              </Link>
              <Link className="button-secondary px-5 py-3" href={adminHref}>
                {adminLabel}
                {session ? <ArrowRight size={16} /> : <LockKeyhole size={16} />}
              </Link>
            </div>
          </div>

          <aside className="panel hidden p-5 lg:block">
            <p className="eyebrow">Operating model</p>
            <div className="mt-5 divide-y divide-line">
              {signals.map(([label, detail]) => (
                <div
                  className="grid grid-cols-[96px_1fr] gap-4 py-4 first:pt-0 last:pb-0"
                  key={label}
                >
                  <span className="text-sm font-semibold text-white">
                    {label}
                  </span>
                  <span className="text-sm leading-6 text-slate-500">
                    {detail}
                  </span>
                </div>
              ))}
            </div>
          </aside>
        </section>
      </div>
    </main>
  );
}
