import Link from "next/link";
import {
  Activity,
  ArrowLeft,
  BellRing,
  Boxes,
  FileText,
  GitFork,
  Inbox,
  HeartPulse,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  PlugZap,
  Radar,
  ScrollText,
  Settings2,
  ShieldPlus,
  SlidersHorizontal,
} from "lucide-react";
import { auth, signOut } from "@/lib/auth";
import { Logo } from "./logo";

const nav = [
  ["/admin", "Overview", LayoutDashboard],
  ["/scans/new", "New scan", ShieldPlus],
  ["/issues", "Issues", ListChecks],
  ["/assets", "Assets", Boxes],
  ["/attack-surface", "Attack surface", Radar],
  ["/attack-paths", "Attack paths", GitFork],
  ["/reports", "Reports", FileText],
  ["/contact-enquiries", "Enquiries", Inbox],
  ["/settings/profiles", "Profiles", SlidersHorizontal],
  ["/settings/vault", "Secrets vault", KeyRound],
  ["/settings/scanners", "Scanners", Settings2],
  ["/settings/integrations", "Integrations", PlugZap],
  ["/settings/automation", "Automation", BellRing],
  ["/audit", "Audit logs", ScrollText],
  ["/health", "System health", HeartPulse],
] as const;

export async function AppShell({ children }: { children: React.ReactNode }) {
  const session = await auth();
  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[240px_1fr]">
      <aside className="hidden border-r border-line bg-[#090c11]/95 p-5 lg:flex lg:flex-col">
        <Logo />
        <Link
          href="/"
          className="mt-5 flex items-center gap-2 rounded-lg border border-line bg-white/[.025] px-3 py-2 text-xs font-medium text-slate-400 transition hover:border-slate-600 hover:bg-white/[.05] hover:text-white"
        >
          <ArrowLeft size={14} />
          Back to home
        </Link>
        <nav className="mt-9 space-y-1">
          {nav.map(([href, label, Icon]) => (
            <Link
              key={href}
              href={href}
              className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-slate-400 transition hover:bg-white/[.04] hover:text-white"
            >
              <Icon size={16} />
              {label}
            </Link>
          ))}
        </nav>
        <div className="mt-auto border-t border-line pt-4">
          <div className="text-sm text-slate-300">
            {session?.user.name ?? session?.user.email}
          </div>
          <div className="mt-1 text-xs text-slate-600">
            {session?.user.role}
          </div>
          <form
            action={async () => {
              "use server";
              await signOut({ redirectTo: "/login" });
            }}
          >
            <button className="mt-3 text-xs text-slate-500 hover:text-white">
              Sign out
            </button>
          </form>
        </div>
      </aside>
      <main>
        <header className="flex h-16 items-center justify-between border-b border-line px-5 lg:px-8">
          <div className="lg:hidden">
            <Logo />
          </div>
          <div className="ml-auto flex items-center gap-2 text-xs text-slate-500">
            <Activity size={14} className="text-signal" />
            Control plane online
          </div>
        </header>
        <div className="mx-auto max-w-[1440px] p-5 lg:p-8">{children}</div>
      </main>
    </div>
  );
}
