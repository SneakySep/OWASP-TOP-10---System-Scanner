"use client";

import { AlertTriangle, ArrowRight, Loader2, RefreshCw } from "lucide-react";
import type { ScanFlow } from "@/lib/useScanFlow";

/** Error, cancellation notice, fix summary and before→after severity bar. */
export default function ScanAlerts({ flow }: { flow: ScanFlow }) {
  return (
    <>
      {flow.error && (
        <div
          role="alert"
          className="rounded-lg border border-red-700 bg-red-50 px-4 py-3 text-sm text-red-800 dark:border-red-800 dark:bg-red-950/50 dark:text-red-300"
        >
          {flow.error}
        </div>
      )}

      {flow.notice && (
        <div
          role="status"
          className="rounded-lg border border-ink/25 bg-faint px-4 py-3 text-sm text-ink"
        >
          {flow.notice}
        </div>
      )}

      {flow.fixSummary && (
        <div className="rounded-lg border border-emerald-600 bg-emerald-50 px-4 py-3 text-sm text-emerald-800 dark:border-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <span>{flow.fixSummary}</span>
            {flow.hasFixedZip && (
              <button
                type="button"
                onClick={() => void flow.verifyFixed()}
                disabled={flow.verifyBusy}
                className="inline-flex items-center gap-2 rounded-lg bg-ink px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-85 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {flow.verifyBusy ? (
                  <Loader2 className="h-4 w-4 animate-spin motion-reduce:animate-none" />
                ) : (
                  <RefreshCw className="h-4 w-4" />
                )}
                {flow.verifyBusy ? "Re-scanning…" : "Verify fixed code"}
              </button>
            )}
          </div>
          {flow.fixWarning && (
            <p className="mt-2 flex items-start gap-2 border-t border-emerald-600/40 pt-2 text-xs text-amber-800 dark:text-amber-300">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              {flow.fixWarning}
            </p>
          )}
        </div>
      )}

      {flow.beforeCounts && flow.result && (
        <div className="flex flex-wrap items-center gap-4 rounded-lg border border-ink bg-surface px-4 py-3 text-sm">
          <span className="font-semibold">Fix verification:</span>
          {(["Critical", "High", "Medium", "Low"] as const).map((sev) => {
            const before = flow.beforeCounts?.[sev] ?? 0;
            const after = flow.result?.severity_counts[sev] ?? 0;
            if (before === 0 && after === 0) return null;
            const improved = after < before;
            const worsened = after > before;
            return (
              <span key={sev} className="inline-flex items-center gap-1.5">
                <span className="text-muted">{sev}</span>
                <span className="font-semibold tabular-nums">{before}</span>
                <ArrowRight className="h-3.5 w-3.5 text-muted" />
                <span
                  className={`font-semibold tabular-nums ${
                    improved
                      ? "text-emerald-600 dark:text-emerald-400"
                      : worsened
                        ? "text-red-600 dark:text-red-400"
                        : ""
                  }`}
                >
                  {after}
                </span>
              </span>
            );
          })}
        </div>
      )}
    </>
  );
}
