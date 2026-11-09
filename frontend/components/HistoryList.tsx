"use client";

import Link from "next/link";
import { ArrowRight, History } from "lucide-react";
import { useScanSession } from "@/lib/scanSession";

const SEVERITIES = ["Critical", "High", "Medium", "Low"] as const;

const SEVERITY_DOT: Record<(typeof SEVERITIES)[number], string> = {
  Critical: "bg-red-500",
  High: "bg-orange-500",
  Medium: "bg-yellow-500",
  Low: "bg-blue-500",
};

export default function HistoryList() {
  const { session, hydrated } = useScanSession();

  // Storage is read after mount, so hold the layout until we know.
  if (!hydrated) {
    return (
      <div
        className="mt-8 h-48 animate-pulse rounded-2xl bg-faint motion-reduce:animate-none"
        aria-hidden="true"
      />
    );
  }

  if (!session) {
    return (
      <div className="mt-8 flex flex-col items-center justify-center rounded-2xl border-2 border-dashed border-ink/30 p-12 text-center">
        <History className="h-10 w-10 text-muted" />
        <p className="mt-3 font-medium">No saved scans yet</p>
        <p className="mt-1 max-w-sm text-sm text-muted">
          Run a scan and it will stay here for this browser session, with its
          severity breakdown, so you can come back to the report.
        </p>
        <Link
          href="/"
          className="mt-4 inline-flex items-center gap-2 rounded-lg bg-ink px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-85"
        >
          Start a scan <ArrowRight className="h-4 w-4" />
        </Link>
      </div>
    );
  }

  const counts = session.payload.severity_counts;
  return (
    <div className="mt-8 space-y-3">
      <Link
        href="/"
        className="block rounded-2xl border border-ink bg-surface p-5 transition-colors hover:bg-faint/60"
      >
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="truncate font-semibold">{session.label}</p>
            <p className="mt-0.5 text-xs text-muted">
              {new Date(session.finishedAt).toLocaleString()} ·{" "}
              {session.payload.total_findings} finding
              {session.payload.total_findings === 1 ? "" : "s"}
            </p>
          </div>
          <span className="inline-flex items-center gap-1 text-sm font-medium text-ink">
            View results <ArrowRight className="h-4 w-4" />
          </span>
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-4">
          {SEVERITIES.map((sev) => (
            <span key={sev} className="inline-flex items-center gap-1.5 text-sm">
              <span className={`h-2 w-2 rounded-full ${SEVERITY_DOT[sev]}`} />
              <span className="text-muted">{sev}</span>
              <span className="font-semibold tabular-nums">
                {counts[sev] ?? 0}
              </span>
            </span>
          ))}
        </div>
      </Link>
      <p className="text-xs text-muted">
        Only the most recent scan is kept, in this browser session only. Nothing
        is written to a database.
      </p>
    </div>
  );
}
