import Image from "next/image";
import Link from "next/link";
import { ArrowLeft, LockKeyhole, Mail } from "lucide-react";

const sections = [
  {
    title: "1. Open the admin console",
    body: "Sign in from the home page. Public visitors can read this page or send a contact enquiry, but scan controls stay inside the admin console.",
  },
  {
    title: "2. Prepare the target",
    body: "Add only websites you own or control. Configure domain approval, safety limits, allowed scan windows and optional authenticated profiles before deeper scans.",
  },
  {
    title: "3. Start a scan",
    body: "Choose a scan mode or saved policy, add the target URL, select optional browser rendering, API discovery, screenshots and credential profiles, then start the scan.",
  },
  {
    title: "4. Review findings",
    body: "Open each finding for evidence, affected location, remediation guidance, verification steps, lifecycle status and targeted retest controls.",
  },
  {
    title: "5. Export and follow up",
    body: "Download reports or evidence archives, generate developer tickets, schedule recurring scans and send notifications when email or webhook delivery is configured.",
  },
];

export default function InstructionsPage() {
  return (
    <main className="min-h-screen">
      <header className="border-b border-line">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-5 lg:px-8">
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
                Instructions
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
            <Link className="button" href="/login">
              Admin login
              <LockKeyhole size={15} />
            </Link>
          </nav>
        </div>
      </header>

      <section className="mx-auto max-w-5xl px-5 py-10 lg:px-8 lg:py-14">
        <Link
          className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-white"
          href="/"
        >
          <ArrowLeft size={15} />
          Back to home
        </Link>
        <div className="mt-10 max-w-3xl">
          <p className="eyebrow">Instructions</p>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight text-white">
            How to use Probeveil
          </h1>
          <p className="mt-4 text-sm leading-7 text-slate-400">
            Keep public navigation simple. Use the admin console for scan setup,
            evidence review, report generation and operational follow-up.
          </p>
        </div>

        <div className="panel mt-8 divide-y divide-line">
          {sections.map((section) => (
            <article
              className="grid gap-3 p-5 md:grid-cols-[240px_1fr]"
              key={section.title}
            >
              <h2 className="text-sm font-semibold text-slate-100">
                {section.title}
              </h2>
              <p className="text-sm leading-7 text-slate-500">{section.body}</p>
            </article>
          ))}
        </div>
      </section>
    </main>
  );
}
