"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  BellRing,
  BookOpenText,
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
  ShieldAlert,
  ShieldPlus,
  SlidersHorizontal,
} from "lucide-react";

const navGroups = [
  {
    label: "Core",
    items: [
      ["/admin", "Overview", LayoutDashboard],
      ["/instructions", "Instructions", BookOpenText],
      ["/scans/new", "New scan", ShieldPlus],
      ["/issues", "Issues", ListChecks],
      ["/reports", "Reports", FileText],
    ],
  },
  {
    label: "Coverage",
    items: [
      ["/assets", "Assets", Boxes],
      ["/attack-surface", "Attack surface", Radar],
      ["/attack-paths", "Attack paths", GitFork],
    ],
  },
  {
    label: "Operations",
    items: [
      ["/contact-enquiries", "Enquiries", Inbox],
      ["/settings/profiles", "Profiles", SlidersHorizontal],
      ["/settings/vault", "Secrets vault", KeyRound],
      ["/settings/safety", "Safety", ShieldAlert],
      ["/settings/scanners", "Scanners", Settings2],
      ["/settings/integrations", "Integrations", PlugZap],
      ["/settings/automation", "Automation", BellRing],
      ["/audit", "Audit logs", ScrollText],
      ["/health", "System health", HeartPulse],
    ],
  },
] as const;

export function ConsoleNav() {
  const pathname = usePathname();

  return (
    <nav className="mt-7 min-h-0 flex-1 space-y-6 overflow-auto pr-1">
      {navGroups.map((group) => (
        <div key={group.label}>
          <p className="px-3 text-[10px] font-semibold uppercase tracking-[.16em] text-slate-600">
            {group.label}
          </p>
          <div className="mt-2 space-y-1">
            {group.items.map(([href, label, Icon]) => {
              const active =
                pathname === href ||
                (href !== "/admin" && pathname.startsWith(`${href}/`));

              return (
                <Link
                  aria-current={active ? "page" : undefined}
                  className={
                    active
                      ? "flex items-center gap-3 rounded-md border border-line bg-white/[.04] px-3 py-2.5 text-sm text-white"
                      : "flex items-center gap-3 rounded-md border border-transparent px-3 py-2.5 text-sm text-slate-400 transition hover:bg-white/[.03] hover:text-white"
                  }
                  href={href}
                  key={href}
                >
                  <Icon className={active ? "text-signal" : ""} size={16} />
                  {label}
                </Link>
              );
            })}
          </div>
        </div>
      ))}
    </nav>
  );
}
