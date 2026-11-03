"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Upload,
  History,
  Database,
  Settings,
  ShieldCheck,
} from "lucide-react";
import ThemeToggle from "@/components/ThemeToggle";

const links = [
  { href: "/", label: "New Scan", icon: Upload },
  { href: "/history", label: "Scan History", icon: History },
  { href: "/remediation", label: "Remediation Database", icon: Database },
  { href: "/settings", label: "Settings", icon: Settings },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="flex w-64 shrink-0 flex-col border-r border-ink bg-surface">
      <div className="flex items-center gap-2 px-6 py-6">
        <ShieldCheck className="h-7 w-7 text-emerald-600 dark:text-emerald-400" />
        <div>
          <h1 className="text-lg font-semibold leading-tight">SAST Scanner</h1>
          <p className="text-xs text-muted">OWASP Top 10 · Semgrep</p>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-3">
        {links.map(({ href, label, icon: Icon }) => {
          const active = pathname === href;
          return (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
                active
                  ? "bg-ink text-bg"
                  : "text-ink hover:bg-faint"
              }`}
            >
              <Icon className="h-5 w-5" />
              {label}
            </Link>
          );
        })}
      </nav>

      <div className="flex items-center justify-between border-t border-ink/15 px-6 py-4 text-xs text-muted">
        <span>Engine: Semgrep CLI</span>
        <ThemeToggle />
      </div>
    </aside>
  );
}
