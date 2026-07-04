import Image from "next/image";
import Link from "next/link";
import { ArrowLeft, LockKeyhole } from "lucide-react";
import { ContactForm } from "@/components/contact-form";

export default function ContactPage() {
  return (
    <main className="min-h-screen">
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
        <Link className="button-secondary" href="/login">
          <LockKeyhole size={15} />
          Admin login
        </Link>
      </header>

      <section className="mx-auto grid max-w-7xl gap-8 px-5 py-10 lg:grid-cols-[.8fr_1.2fr] lg:px-8 lg:py-16">
        <aside>
          <Link
            className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-white"
            href="/"
          >
            <ArrowLeft size={15} />
            Back to home
          </Link>
          <p className="eyebrow mt-10">Public contact</p>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight text-white">
            Contact Probeveil
          </h1>
          <p className="mt-4 max-w-md text-sm leading-7 text-slate-400">
            Use this form for product enquiries, security review requests, demo
            requests, partnerships, technical questions or general contact. It
            does not provide scanner access.
          </p>
          <div className="panel mt-8 p-5">
            <p className="text-sm font-medium text-white">
              Keep credentials out of messages
            </p>
            <p className="mt-2 text-sm leading-6 text-slate-500">
              Do not send passwords, API keys, private keys, authentication
              tokens, payment details, source-code archives or sensitive
              vulnerability evidence through this form.
            </p>
          </div>
        </aside>
        <ContactForm />
      </section>
    </main>
  );
}
