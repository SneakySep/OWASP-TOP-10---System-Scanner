"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ArrowRight,
  History,
  Loader2,
  RefreshCw,
} from "lucide-react";
import { fetchScans, type ScanSummary } from "@/lib/api";

const SEVERITIES = ["Critical", "High", "Medium", "Low"] as const;

const SEVERITY_DOT: Record<(typeof SEVERITIES)[number], string> = {
  Critical: "bg-red-500",
  High: "bg-orange-500",
  Medium: "bg-yellow-500",
  Low: "bg-blue-500",
};

export default function HistoryList() {
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setScans(null);
    setError(null);
    fetchScans(controller.signal)
      .then(setScans)
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === "AbortError") return;
        if (e instanceof Error && e.name === "AbortError") return;
        setError(
          e instanceof Error ? e.message : "Could not load scan history."
        );
        setScans([]);
      });
    return () => controller.abort();
  }, [attempt]);

  const retry = useCallback(() => setAttempt((value) => value + 1), []);

  if (scans === null) {
    return (
      <div
        role="status"
        className="mt-8 flex items-center gap-2 text-sm text-muted"
      >
        <Loader2 className="h-4 w-4 animate-spin motion-reduce:animate-none" />
        Loading scan history…
      </div>
    );
  }

  if (error) {
    return (
      <div className="mt-8 rounded-2xl border border-red-700 bg-red-50 p-6 text-sm text-red-800 dark:border-red-800 dark:bg-red-950/50 dark:text-red-300">
        <div className="flex items-start gap-2">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <div>
            <p className="font-semibold">Could not reach the backend.</p>
            <p className="mt-1">{error}</p>
            <p className="mt-1 text-xs">
              Check the API base URL on the Settings page, then try again.
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={retry}
          className="mt-3 inline-flex items-center gap-2 rounded-lg border border-red-700 px-3 py-1.5 text-xs font-medium transition-colors hover:bg-red-100 dark:border-red-700 dark:hover:bg-red-900/40"
        >
          <RefreshCw className="h-3.5 w-3.5" /> Try again
        </button>
      </div>
    );
  }

  if (scans.length === 0) {
    return (
      <div className="mt-8 flex flex-col items-center justify-center rounded-2xl border-2 border-dashed border-ink/30 p-12 text-center">
        <History className="h-10 w-10 text-muted" />
        <p className="mt-3 font-medium">No scans recorded yet</p>
        <p className="mt-1 max-w-sm text-sm text-muted">
          Every scan is stored on the backend with its findings and severity
          breakdown, so you can come back to the report later or compare the
          next run against it.
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

  return (
    <div className="mt-8 space-y-3">
      {scans.map((scan) => (
        <Link
          key={scan.scan_id}
          href={`/scan/${scan.scan_id}`}
          className="block rounded-2xl border border-ink bg-surface p-5 transition-colors hover:bg-faint/60"
        >
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="truncate font-semibold">{scan.label}</p>
              <p className="mt-0.5 text-xs text-muted">
                {new Date(scan.created_at * 1000).toLocaleString()} ·{" "}
                {scan.ruleset} · {scan.total_findings} finding
                {scan.total_findings === 1 ? "" : "s"}
              </p>
            </div>
            <span className="inline-flex items-center gap-1 text-sm font-medium text-ink">
              View report <ArrowRight className="h-4 w-4" />
            </span>
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-4">
            {SEVERITIES.map((sev) => (
              <span key={sev} className="inline-flex items-center gap-1.5 text-sm">
                <span className={`h-2 w-2 rounded-full ${SEVERITY_DOT[sev]}`} />
                <span className="text-muted">{sev}</span>
                <span className="font-semibold tabular-nums">
                  {scan.severity_counts?.[sev] ?? 0}
                </span>
              </span>
            ))}
            {(scan.new_findings > 0 || scan.fixed_findings > 0) && (
              <span className="ml-auto text-xs text-muted">
                {scan.new_findings > 0 && (
                  <span className="font-semibold text-ink">
                    {scan.new_findings} new
                  </span>
                )}
                {scan.new_findings > 0 && scan.fixed_findings > 0 && " · "}
                {scan.fixed_findings > 0 && (
                  <span className="font-semibold text-emerald-700 dark:text-emerald-400">
                    {scan.fixed_findings} fixed
                  </span>
                )}
              </span>
            )}
          </div>
        </Link>
      ))}
    </div>
  );
}
