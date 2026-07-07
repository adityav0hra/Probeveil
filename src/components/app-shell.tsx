import Link from "next/link";
import { Activity, ArrowLeft, BookOpenText, Plus } from "lucide-react";
import { auth, signOut } from "@/lib/auth";
import { ConsoleNav } from "./console-nav";
import { Logo } from "./logo";

export async function AppShell({ children }: { children: React.ReactNode }) {
  const session = await auth();
  return (
    <div className="min-h-screen bg-ink lg:grid lg:grid-cols-[260px_1fr]">
      <aside className="hidden h-screen border-r border-line bg-panel p-5 lg:flex lg:flex-col">
        <Logo />
        <Link
          href="/"
          className="mt-5 flex items-center gap-2 rounded-md border border-line px-3 py-2 text-xs font-medium text-slate-400 transition hover:border-slate-500 hover:text-white"
        >
          <ArrowLeft size={14} />
          Back to home
        </Link>
        <ConsoleNav />
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
        <header className="flex h-16 items-center justify-between border-b border-line bg-panel px-5 lg:px-8">
          <div className="lg:hidden">
            <Logo />
          </div>
          <div className="hidden items-center gap-3 text-xs text-slate-500 lg:flex">
            <span className="rounded-full border border-line px-3 py-1">
              Admin console
            </span>
            <span>Operational workspace</span>
          </div>
          <div className="ml-auto flex items-center gap-2 rounded-full border border-line px-3 py-1 text-xs text-slate-500">
            <Activity size={13} className="text-signal" />
            Online
          </div>
        </header>
        <div className="flex gap-2 border-b border-line bg-panel px-5 py-3 lg:hidden">
          <Link
            className="button-secondary flex-1 px-3 py-2 text-xs"
            href="/instructions"
          >
            <BookOpenText size={14} />
            Instructions
          </Link>
          <Link className="button flex-1 px-3 py-2 text-xs" href="/scans/new">
            <Plus size={14} />
            New scan
          </Link>
        </div>
        <div className="mx-auto max-w-[1440px] p-5 lg:p-8">{children}</div>
      </main>
    </div>
  );
}
