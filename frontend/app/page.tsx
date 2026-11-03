"use client";

import { useCallback, useRef, useState } from "react";
import JSZip from "jszip";
import {
  ArrowRight,
  Loader2,
  FileArchive,
  FolderOpen,
  Files,
  RefreshCw,
  UploadCloud,
} from "lucide-react";
import ScanResults, { type ScanPayload } from "@/components/ScanResults";
import {
  collectFromDataTransfer,
  collectFromInput,
  CollectionError,
  MAX_FILES,
  type PickedFile,
} from "@/lib/collectFiles";

const MAX_TOTAL_BYTES = 100 * 1024 * 1024; // must match the backend limit

// React's input types don't know the non-standard folder-picker attributes.
const folderInputProps = {
  webkitdirectory: "",
  directory: "",
} as unknown as React.InputHTMLAttributes<HTMLInputElement>;

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${bytes} B`;
}

export default function Home() {
  const [dragActive, setDragActive] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanPayload | null>(null);
  const [fixBusy, setFixBusy] = useState(false);
  const [fixSummary, setFixSummary] = useState<string | null>(null);
  const [verifyBusy, setVerifyBusy] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  // Severity counts from the original scan, captured before a verify re-scan.
  const [beforeCounts, setBeforeCounts] = useState<
    ScanPayload["severity_counts"] | null
  >(null);
  const filesInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  // The last uploaded archive is re-posted to /api/fix by "Download fixed code".
  const lastZipRef = useRef<File | null>(null);
  // The patched archive produced by /api/fix, kept for "Verify fixed code".
  const fixedBlobRef = useRef<Blob | null>(null);
  // Nesting counter that kills the dragleave flicker across child elements.
  const dragDepthRef = useRef(0);

  const scanZip = useCallback(async (file: File, label: string) => {
    setError(null);
    setResult(null);
    setFixSummary(null);
    lastZipRef.current = file;
    setStatus(`Scanning ${label}…`);
    const startedAt = Date.now();
    setElapsed(0);
    const timer = window.setInterval(
      () => setElapsed(Math.round((Date.now() - startedAt) / 1000)),
      1000
    );
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/scan`,
        {
          method: "POST",
          body: form,
        }
      );
      if (!res.ok) {
        const detail = await res.json().catch(() => ({}));
        throw new Error(
          detail.detail || `Scan failed with status ${res.status}`
        );
      }
      setResult(await res.json());
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Unexpected error during scan."
      );
    } finally {
      window.clearInterval(timer);
      setStatus(null);
    }
  }, []);

  const downloadFixed = useCallback(async () => {
    const zip = lastZipRef.current;
    if (!zip || fixBusy) return;
    setFixBusy(true);
    setError(null);
    setFixSummary(null);
    setStatus("Applying suggested fixes…");
    try {
      const form = new FormData();
      form.append("file", zip);
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/fix`,
        {
          method: "POST",
          body: form,
        }
      );
      if (!res.ok) {
        const detail = await res.json().catch(() => ({}));
        throw new Error(
          detail.detail || `Fix request failed with status ${res.status}`
        );
      }
      const blob = await res.blob();
      // Keep the patched archive around for "Verify fixed code".
      fixedBlobRef.current = blob;
      // Best-effort: read the fix report from the archive for a summary.
      let summary = "Downloaded fixed-source.zip — review before committing.";
      try {
        const reportRaw = await (
          await JSZip.loadAsync(blob)
        ).file("_FIX_REPORT.json")?.async("string");
        if (reportRaw) {
          const report = JSON.parse(reportRaw);
          const applied = report.applied?.length ?? 0;
          const unfixed = report.unfixed?.length ?? 0;
          const total = report.total_findings ?? applied + unfixed;
          summary = applied
            ? `Applied ${applied} of ${total} suggested fixes — review the changes before committing.`
            : `No fixes could be applied automatically (${total} findings) — follow the remediation guidance on each card.`;
        }
      } catch {
        // Report parsing is optional; the download itself is the point.
      }
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "fixed-source.zip";
      link.click();
      URL.revokeObjectURL(url);
      setFixSummary(summary);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Unexpected error while fixing."
      );
    } finally {
      setFixBusy(false);
      setStatus(null);
    }
  }, [fixBusy]);

  // Verify-fixes loop: re-scan the patched archive and compare severity
  // counts before → after. Uses only the existing /api/scan endpoint.
  const verifyFixed = useCallback(async () => {
    const blob = fixedBlobRef.current;
    if (!blob || verifyBusy || !result) return;
    setVerifyBusy(true);
    setError(null);
    setBeforeCounts(result.severity_counts);
    setStatus("Re-scanning fixed code…");
    try {
      const form = new FormData();
      form.append(
        "file",
        new File([blob], "fixed-source.zip", { type: "application/zip" })
      );
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/scan`,
        { method: "POST", body: form }
      );
      if (!res.ok) {
        const detail = await res.json().catch(() => ({}));
        throw new Error(
          detail.detail || `Re-scan failed with status ${res.status}`
        );
      }
      setResult(await res.json());
      setFixSummary(null);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Unexpected error during re-scan."
      );
    } finally {
      setVerifyBusy(false);
      setStatus(null);
    }
  }, [result, verifyBusy]);

  const handlePicked = useCallback(
    async (picked: PickedFile[]) => {
      setError(null);
      setResult(null);
      setBeforeCounts(null);
      fixedBlobRef.current = null;
      try {
        if (picked.length === 0) {
          setError("Nothing to scan — drop some files or a folder first.");
          return;
        }
        if (picked.length >= MAX_FILES) {
          setError(
            `That selection contains ${picked.length}+ files — please upload a .zip archive instead.`
          );
          return;
        }

        // A single .zip goes to the API untouched, as before.
        if (
          picked.length === 1 &&
          picked[0].path.toLowerCase().endsWith(".zip")
        ) {
          await scanZip(picked[0].file, picked[0].path);
          return;
        }

        const total = picked.reduce((sum, p) => sum + p.file.size, 0);
        if (total > MAX_TOTAL_BYTES) {
          setError(
            `Selection is ${formatBytes(total)} — the limit is ${formatBytes(
              MAX_TOTAL_BYTES
            )}. Please upload a .zip instead.`
          );
          return;
        }

        // Pack everything (relative paths preserved) into a zip client-side.
        setStatus(
          picked.length === 1
            ? "Preparing file…"
            : `Packing ${picked.length} files…`
        );
        const zip = new JSZip();
        const used = new Set<string>();
        for (const { file, path } of picked) {
          let p = path;
          let i = 1;
          while (used.has(p)) p = `${i++}-${path}`;
          used.add(p);
          zip.file(p, file);
        }
        const blob = await zip.generateAsync({
          type: "blob",
          compression: "DEFLATE",
        });
        await scanZip(
          new File([blob], "upload.zip", { type: "application/zip" }),
          picked.length === 1 ? picked[0].path : `${picked.length} files`
        );
      } catch (e) {
        setError(
          e instanceof CollectionError
            ? e.message
            : e instanceof Error
              ? e.message
              : "Unexpected error while preparing the upload."
        );
        setStatus(null);
      }
    },
    [scanZip]
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      dragDepthRef.current = 0;
      setDragActive(false);
      if (status) return;
      collectFromDataTransfer(e.dataTransfer)
        .then(handlePicked)
        .catch((err: unknown) =>
          setError(
            err instanceof Error
              ? err.message
              : "Could not read the dropped items."
          )
        );
    },
    [handlePicked, status]
  );

  return (
    <div className="mx-auto max-w-5xl space-y-8">
      <header>
        <h2 className="text-2xl font-bold">New Scan</h2>
        <p className="mt-1 text-sm text-muted">
          Drop files, a whole folder, or a .zip of your source code. It is
          scanned with Semgrep against the OWASP Top 10 ruleset and enriched
          with remediation guidance.
        </p>
      </header>

      <div
        role="button"
        tabIndex={0}
        aria-label="Upload files or a folder to scan"
        onDragOver={(e) => {
          e.preventDefault();
          setDragActive(true);
        }}
        onDragEnter={() => {
          dragDepthRef.current += 1;
        }}
        onDragLeave={() => {
          dragDepthRef.current = Math.max(0, dragDepthRef.current - 1);
          if (dragDepthRef.current === 0) setDragActive(false);
        }}
        onDrop={onDrop}
        onClick={() => {
          if (!status) filesInputRef.current?.click();
        }}
        onKeyDown={(e) => {
          if (status) return;
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            filesInputRef.current?.click();
          }
        }}
        className={`flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed p-14 text-center transition-colors ${
          dragActive
            ? "border-ink bg-faint"
            : "border-ink/40 bg-surface hover:border-ink"
        }`}
      >
        <input
          ref={filesInputRef}
          type="file"
          multiple
          className="hidden"
          onChange={(e) => {
            void handlePicked(collectFromInput(e.target.files));
            e.target.value = "";
          }}
        />
        <input
          ref={folderInputRef}
          type="file"
          multiple
          className="hidden"
          {...folderInputProps}
          onChange={(e) => {
            void handlePicked(collectFromInput(e.target.files));
            e.target.value = "";
          }}
        />
        {status ? (
          <>
            <Loader2 className="h-12 w-12 animate-spin text-emerald-600 dark:text-emerald-400" />
            <p className="mt-4 font-medium" aria-live="polite">
              {status}
              {elapsed >= 1 ? ` · ${elapsed}s` : ""}
            </p>
            <p className="mt-1 text-sm text-muted">
              Running Semgrep against the OWASP Top 10 ruleset. This can take a
              minute on first run while rules download.
            </p>
          </>
        ) : (
          <>
            <FileArchive className="h-12 w-12 text-muted" />
            <p className="mt-4 font-medium">
              Drag &amp; drop files or a folder here
            </p>
            <p className="mt-1 text-sm text-muted">
              Any mix of files and folders (or a single .zip), up to 100 MB —
              junk folders like node_modules and .git are skipped
            </p>
            <div className="mt-5 flex flex-wrap items-center justify-center gap-3">
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  filesInputRef.current?.click();
                }}
                className="inline-flex items-center gap-2 rounded-lg bg-ink px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-85"
              >
                <Files className="h-4 w-4" /> Browse files
              </button>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  folderInputRef.current?.click();
                }}
                className="inline-flex items-center gap-2 rounded-lg bg-surface px-4 py-2 text-sm font-medium text-ink ring-1 ring-ink/40 transition-colors hover:bg-faint"
              >
                <FolderOpen className="h-4 w-4" /> Browse folder
              </button>
              <span className="inline-flex items-center gap-1 text-xs text-muted">
                <UploadCloud className="h-3.5 w-3.5" /> or drop them anywhere in
                this box
              </span>
            </div>
          </>
        )}
      </div>

      {error && (
        <div
          role="alert"
          className="rounded-lg border border-red-700 bg-red-50 px-4 py-3 text-sm text-red-800 dark:border-red-800 dark:bg-red-950/50 dark:text-red-300"
        >
          {error}
        </div>
      )}

      {fixSummary && (
        <div className="rounded-lg border border-emerald-600 bg-emerald-50 px-4 py-3 text-sm text-emerald-800 dark:border-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <span>{fixSummary}</span>
            {fixedBlobRef.current && (
              <button
                type="button"
                onClick={() => void verifyFixed()}
                disabled={verifyBusy}
                className="inline-flex items-center gap-2 rounded-lg bg-ink px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-85 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {verifyBusy ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <RefreshCw className="h-4 w-4" />
                )}
                {verifyBusy ? "Re-scanning…" : "Verify fixed code"}
              </button>
            )}
          </div>
        </div>
      )}

      {beforeCounts && result && (
        <div className="flex flex-wrap items-center gap-4 rounded-lg border border-ink bg-surface px-4 py-3 text-sm">
          <span className="font-semibold">Fix verification:</span>
          {(["Critical", "High", "Medium", "Low"] as const).map((sev) => {
            const before = beforeCounts[sev] ?? 0;
            const after = result.severity_counts[sev] ?? 0;
            if (before === 0 && after === 0) return null;
            const improved = after < before;
            const worsened = after > before;
            return (
              <span key={sev} className="inline-flex items-center gap-1.5">
                <span className="text-muted">{sev}</span>
                <span className="font-semibold">{before}</span>
                <ArrowRight className="h-3.5 w-3.5 text-muted" />
                <span
                  className={`font-semibold ${
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

      {result && (
        <ScanResults
          key={result.scan_id}
          payload={result}
          onDownloadFixed={() => void downloadFixed()}
          fixBusy={fixBusy}
        />
      )}
    </div>
  );
}
