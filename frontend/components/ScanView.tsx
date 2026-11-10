"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AlertTriangle, ArrowLeft, Loader2 } from "lucide-react";
import ScanResults from "@/components/ScanResults";
import { apiUrl, fetchScan, type ScanDetail } from "@/lib/api";

/** A stored report rendered from `GET /api/scans/{id}` (permalink target). */
export default function ScanView({ scanId }: { scanId: string }) {
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setScan(null);
    setError(null);
    fetchScan(scanId, controller.signal)
      .then(setScan)
      .catch((e: unknown) => {
        if (e instanceof DOMException && e.name === "AbortError") return;
        if (e instanceof Error && e.name === "AbortError") return;
        setError(e instanceof Error ? e.message : "Could not load this report.");
      });
    return () => controller.abort();
  }, [scanId]);

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <Link
        href="/history"
        className="inline-flex items-center gap-1.5 text-sm text-muted transition-colors hover:text-ink"
      >
        <ArrowLeft className="h-4 w-4" /> Scan history
      </Link>

      {error && (
        <div
          role="alert"
          className="rounded-lg border border-red-700 bg-red-50 px-4 py-3 text-sm text-red-800 dark:border-red-800 dark:bg-red-950/50 dark:text-red-300"
        >
          <div className="flex items-start gap-2">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <div>
              <p className="font-semibold">Could not load this report.</p>
              <p className="mt-1">{error}</p>
              <p className="mt-1 text-xs">
                History keeps the newest 200 scans, so old reports are pruned.
                The raw record is at{" "}
                <code className="rounded bg-red-100 px-1 dark:bg-red-900/40">
                  {apiUrl(`/api/scans/${scanId}`)}
                </code>
                .
              </p>
            </div>
          </div>
        </div>
      )}

      {!scan && !error && (
        <div
          role="status"
          className="flex items-center gap-2 text-sm text-muted"
        >
          <Loader2 className="h-4 w-4 animate-spin motion-reduce:animate-none" />
          Loading report…
        </div>
      )}

      {scan && (
        <>
          <header>
            <h2 className="text-2xl font-bold">{scan.label}</h2>
            <p className="mt-1 text-sm text-muted">
              Saved report · {new Date(scan.created_at * 1000).toLocaleString()}{" "}
              · {scan.ruleset}
            </p>
            <p className="mt-2 text-xs text-muted">
              This report is stored on the backend. Run a new scan to download
              patched code.
            </p>
          </header>
          <ScanResults payload={scan.payload} />
        </>
      )}
    </div>
  );
}
