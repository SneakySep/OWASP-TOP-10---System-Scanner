"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import JSZip from "jszip";
import {
  AlertTriangle,
  ArrowRight,
  Ban,
  FileArchive,
  Files,
  FolderOpen,
  Loader2,
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
import { scanArtifacts, useScanSession } from "@/lib/scanSession";
import { apiUrl, getRuleset } from "@/lib/api";

const MAX_TOTAL_BYTES = 100 * 1024 * 1024; // must match the backend limit

// React's input types don't know the non-standard folder-picker attributes.
const folderInputProps = {
  webkitdirectory: "",
  directory: "",
} as unknown as React.InputHTMLAttributes<HTMLInputElement>;

type Phase = "idle" | "packing" | "scanning" | "fixing" | "verifying";

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${bytes} B`;
}

function wasAborted(e: unknown): boolean {
  return (
    (e instanceof DOMException && e.name === "AbortError") ||
    (e instanceof Error && e.name === "AbortError")
  );
}

export default function Home() {
  const { session, setSession } = useScanSession();
  const result = session?.payload ?? null;
  const beforeCounts = session?.beforeCounts ?? null;
  const fixSummary = session?.fixSummary ?? null;
  const fixWarning = session?.fixWarning ?? null;

  const [dragActive, setDragActive] = useState(false);
  const [phase, setPhase] = useState<Phase>("idle");
  const [status, setStatus] = useState<string | null>(null);
  // 0–100 while packing the upload; null means "indeterminate".
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // Short text for screen readers — never contains the ticking timer.
  const [announcement, setAnnouncement] = useState("");
  const [fixBusy, setFixBusy] = useState(false);
  const [verifyBusy, setVerifyBusy] = useState(false);
  const [elapsed, setElapsed] = useState(0);

  const filesInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  const cancelledRef = useRef(false);
  // Nesting counter that kills the dragleave flicker across child elements.
  const dragDepthRef = useRef(0);

  // Dropping anywhere outside the dropzone must not navigate the browser to
  // the file — without this the whole app is lost on a slightly-off drop.
  useEffect(() => {
    const prevent = (e: DragEvent) => e.preventDefault();
    window.addEventListener("dragover", prevent);
    window.addEventListener("drop", prevent);
    return () => {
      window.removeEventListener("dragover", prevent);
      window.removeEventListener("drop", prevent);
    };
  }, []);

  const cancel = useCallback(() => {
    cancelledRef.current = true;
    if (abortRef.current) {
      abortRef.current.abort();
    } else {
      // Packing has no abort hook; bail as soon as JSZip yields.
      setStatus("Cancelling…");
    }
  }, []);

  const scanZip = useCallback(
    async (file: File, label: string) => {
      setError(null);
      setNotice(null);
      setAnnouncement(`Scanning ${label}.`);
      scanArtifacts.lastZip = file;
      const startedAt = Date.now();
      setElapsed(0);
      setPhase("scanning");
      setStatus(`Scanning ${label}…`);
      setProgress(null);
      const timer = window.setInterval(
        () => setElapsed(Math.round((Date.now() - startedAt) / 1000)),
        1000
      );
      const controller = new AbortController();
      abortRef.current = controller;
      try {
        const form = new FormData();
        form.append("file", file);
        form.append("ruleset", getRuleset());
        const res = await fetch(apiUrl("/api/scan"), {
          method: "POST",
          body: form,
          signal: controller.signal,
        });
        if (!res.ok) {
          const detail = await res.json().catch(() => ({}));
          throw new Error(
            detail.detail || `Scan failed with status ${res.status}`
          );
        }
        const payload = (await res.json()) as ScanPayload;
        scanArtifacts.fixedZip = null;
        setSession({
          payload,
          beforeCounts: null,
          fixSummary: null,
          fixWarning: null,
          label,
          finishedAt: Date.now(),
          hasFixedZip: false,
        });
        setAnnouncement(
          `Scan complete. ${payload.total_findings} finding${
            payload.total_findings === 1 ? "" : "s"
          }, ${payload.severity_counts.Critical ?? 0} critical.`
        );
      } catch (e) {
        if (controller.signal.aborted || wasAborted(e)) {
          setNotice("Scan cancelled — previous results kept.");
          setAnnouncement("Scan cancelled.");
        } else {
          setError(
            e instanceof Error ? e.message : "Unexpected error during scan."
          );
        }
      } finally {
        window.clearInterval(timer);
        abortRef.current = null;
        setStatus(null);
        setPhase("idle");
        setProgress(null);
      }
    },
    [setSession]
  );

  const downloadFixed = useCallback(async () => {
    const zip = scanArtifacts.lastZip;
    if (fixBusy) return;
    if (!zip) {
      setError(
        "The uploaded archive is no longer in memory — run a new scan to apply fixes."
      );
      return;
    }
    setFixBusy(true);
    setError(null);
    setNotice(null);
    setAnnouncement("");
    setElapsed(0);
    setPhase("fixing");
    setStatus("Applying suggested fixes…");
    try {
      const form = new FormData();
      form.append("file", zip);
      form.append("ruleset", getRuleset());
      const res = await fetch(apiUrl("/api/fix"), {
        method: "POST",
        body: form,
      });
      if (!res.ok) {
        const detail = await res.json().catch(() => ({}));
        throw new Error(
          detail.detail || `Fix request failed with status ${res.status}`
        );
      }
      const blob = await res.blob();
      // Keep the patched archive around for "Verify fixed code".
      scanArtifacts.fixedZip = blob;
      // Best-effort: read the fix report from the archive for a summary.
      let summary = "Downloaded fixed-source.zip — review before committing.";
      let warning: string | null = null;
      try {
        const reportRaw = await (
          await JSZip.loadAsync(blob)
        ).file("_FIX_REPORT.json")?.async("string");
        if (reportRaw) {
          const report = JSON.parse(reportRaw);
          const applied: { confidence?: string }[] = report.applied ?? [];
          const unfixed = report.unfixed?.length ?? 0;
          const total = report.total_findings ?? applied.length + unfixed;
          const high = applied.filter(
            (entry) => entry.confidence === "high"
          ).length;
          const medium = applied.length - high;
          summary = applied.length
            ? `Applied ${applied.length} of ${total} suggested fixes — ${high} high confidence, ${medium} need review.`
            : `No fixes could be applied automatically (${total} findings) — follow the remediation guidance on each card.`;
          if (medium > 0) {
            warning = `${medium} applied fix${
              medium === 1 ? " is" : "es are"
            } medium confidence: they change runtime behaviour, add salt storage your schema must handle, or ship placeholder allow-lists (example.com, api.example.com). Review the diff before committing.`;
          }
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
      setSession((prev) =>
        prev
          ? { ...prev, fixSummary: summary, fixWarning: warning, hasFixedZip: true }
          : prev
      );
      setAnnouncement("Fixed code downloaded.");
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Unexpected error while fixing."
      );
    } finally {
      setFixBusy(false);
      setStatus(null);
      setPhase("idle");
    }
  }, [fixBusy, setSession]);

  // Verify-fixes loop: re-scan the patched archive and compare severity
  // counts before → after. Uses only the existing /api/scan endpoint.
  const verifyFixed = useCallback(async () => {
    const blob = scanArtifacts.fixedZip;
    if (!blob || verifyBusy || !session) return;
    setVerifyBusy(true);
    setError(null);
    setNotice(null);
    setAnnouncement("");
    setElapsed(0);
    setPhase("verifying");
    setStatus("Re-scanning fixed code…");
    try {
      const form = new FormData();
      form.append(
        "file",
        new File([blob], "fixed-source.zip", { type: "application/zip" })
      );
      form.append("ruleset", getRuleset());
      const res = await fetch(apiUrl("/api/scan"), {
        method: "POST",
        body: form,
      });
      if (!res.ok) {
        const detail = await res.json().catch(() => ({}));
        throw new Error(
          detail.detail || `Re-scan failed with status ${res.status}`
        );
      }
      const payload = (await res.json()) as ScanPayload;
      setSession((prev) =>
        prev
          ? {
              ...prev,
              payload,
              beforeCounts: prev.payload.severity_counts,
              fixSummary: null,
              fixWarning: null,
            }
          : prev
      );
      setAnnouncement(
        `Re-scan complete. ${payload.total_findings} finding${
          payload.total_findings === 1 ? "" : "s"
        } remain.`
      );
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Unexpected error during re-scan."
      );
    } finally {
      setVerifyBusy(false);
      setStatus(null);
      setPhase("idle");
    }
  }, [session, verifyBusy, setSession]);

  const handlePicked = useCallback(
    async (picked: PickedFile[]) => {
      setError(null);
      setNotice(null);
      setAnnouncement("");
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

      cancelledRef.current = false;

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
      setPhase("packing");
      setProgress(0);
      setStatus(
        picked.length === 1
          ? "Preparing file…"
          : `Packing ${picked.length} files…`
      );
      try {
        const zip = new JSZip();
        const used = new Set<string>();
        for (const { file, path } of picked) {
          let p = path;
          let i = 1;
          while (used.has(p)) p = `${i++}-${path}`;
          used.add(p);
          zip.file(p, file);
        }
        const blob = await zip.generateAsync(
          {
            type: "blob",
            compression: "DEFLATE",
          },
          (meta) => {
            if (!cancelledRef.current) setProgress(Math.round(meta.percent));
          }
        );
        if (cancelledRef.current) {
          setNotice("Scan cancelled — nothing was uploaded.");
          setAnnouncement("Scan cancelled.");
          return;
        }
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
      } finally {
        setProgress(null);
        setStatus(null);
        setPhase((p) => (p === "packing" ? "idle" : p));
      }
    },
    [scanZip]
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      dragDepthRef.current = 0;
      setDragActive(false);
      if (phase !== "idle") return;
      // Ignore drops that carry no files (e.g. dragged text or a link).
      if (!e.dataTransfer.files || e.dataTransfer.files.length === 0) return;
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
    [handlePicked, phase]
  );

  const busy = phase !== "idle";

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
        onDragOver={(e) => {
          if (!Array.from(e.dataTransfer.types).includes("Files")) return;
          e.preventDefault();
          setDragActive(true);
        }}
        onDragEnter={(e) => {
          if (!Array.from(e.dataTransfer.types).includes("Files")) return;
          dragDepthRef.current += 1;
          setDragActive(true);
        }}
        onDragLeave={() => {
          dragDepthRef.current = Math.max(0, dragDepthRef.current - 1);
          if (dragDepthRef.current === 0) setDragActive(false);
        }}
        onDrop={onDrop}
        className={`flex flex-col items-center justify-center rounded-2xl border-2 border-dashed p-8 text-center transition-colors sm:p-14 ${
          dragActive
            ? "border-ink bg-faint"
            : "border-ink/40 bg-surface md:hover:border-ink"
        }`}
      >
        <input
          ref={filesInputRef}
          id="scan-files"
          type="file"
          multiple
          className="sr-only"
          disabled={busy}
          onChange={(e) => {
            void handlePicked(collectFromInput(e.target.files));
            e.target.value = "";
          }}
        />
        <input
          ref={folderInputRef}
          id="scan-folder"
          type="file"
          multiple
          className="sr-only"
          disabled={busy}
          {...folderInputProps}
          onChange={(e) => {
            void handlePicked(collectFromInput(e.target.files));
            e.target.value = "";
          }}
        />
        {status ? (
          <div className="flex w-full flex-col items-center">
            <Loader2
              aria-hidden="true"
              className="h-12 w-12 animate-spin text-emerald-600 motion-reduce:animate-none dark:text-emerald-400"
            />
            <p className="mt-4 font-medium">
              {status}
              {elapsed >= 1 && (
                <span className="ml-1 tabular-nums">· {elapsed}s</span>
              )}
            </p>
            <div
              role="progressbar"
              aria-label="Upload progress"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={progress ?? undefined}
              className="mt-4 h-1.5 w-56 overflow-hidden rounded-full bg-faint"
            >
              {progress === null ? (
                <div className="h-full w-1/3 rounded-full bg-emerald-600 animate-indeterminate motion-reduce:animate-none dark:bg-emerald-400" />
              ) : (
                <div
                  className="h-full rounded-full bg-emerald-600 transition-[width] duration-200 dark:bg-emerald-400"
                  style={{ width: `${progress}%` }}
                />
              )}
            </div>
            <p className="mt-3 text-sm text-muted">
              {phase === "packing"
                ? "Compressing the selection in your browser — nothing has been uploaded yet."
                : phase === "verifying"
                  ? "Re-running Semgrep on the patched copy to compare results."
                  : phase === "fixing"
                    ? "Generating a patched archive — review it before committing."
                    : "Running Semgrep against the OWASP Top 10 ruleset. This can take a minute on first run while rules download."}
            </p>
            {(phase === "packing" || phase === "scanning") && (
              <button
                type="button"
                onClick={cancel}
                className="mt-4 inline-flex items-center gap-2 rounded-lg border border-ink/40 bg-surface px-4 py-2 text-sm font-medium text-ink transition-colors hover:bg-faint"
              >
                <Ban className="h-4 w-4" /> Cancel scan
              </button>
            )}
          </div>
        ) : (
          <>
            <label
              htmlFor="scan-files"
              className="flex cursor-pointer flex-col items-center"
            >
              <FileArchive className="h-12 w-12 text-muted" />
              <p className="mt-4 font-medium">
                Drag &amp; drop files or a folder here
              </p>
              <p className="mt-1 text-sm text-muted">
                Any mix of files and folders (or a single .zip), up to 100 MB —
                junk folders like node_modules and .git are skipped
              </p>
            </label>
            <div className="mt-5 flex flex-wrap items-center justify-center gap-3">
              <button
                type="button"
                onClick={() => filesInputRef.current?.click()}
                className="inline-flex items-center gap-2 rounded-lg bg-ink px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-85"
              >
                <Files className="h-4 w-4" /> Browse files
              </button>
              <button
                type="button"
                onClick={() => folderInputRef.current?.click()}
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

      {/* One live region for the whole flow; the ticking timer stays out of it. */}
      <p className="sr-only" role="status">
        {announcement || status || ""}
      </p>

      {error && (
        <div
          role="alert"
          className="rounded-lg border border-red-700 bg-red-50 px-4 py-3 text-sm text-red-800 dark:border-red-800 dark:bg-red-950/50 dark:text-red-300"
        >
          {error}
        </div>
      )}

      {notice && (
        <div
          role="status"
          className="rounded-lg border border-ink/25 bg-faint px-4 py-3 text-sm text-ink"
        >
          {notice}
        </div>
      )}

      {fixSummary && (
        <div className="rounded-lg border border-emerald-600 bg-emerald-50 px-4 py-3 text-sm text-emerald-800 dark:border-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <span>{fixSummary}</span>
            {session?.hasFixedZip && (
              <button
                type="button"
                onClick={() => void verifyFixed()}
                disabled={verifyBusy}
                className="inline-flex items-center gap-2 rounded-lg bg-ink px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-85 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {verifyBusy ? (
                  <Loader2 className="h-4 w-4 animate-spin motion-reduce:animate-none" />
                ) : (
                  <RefreshCw className="h-4 w-4" />
                )}
                {verifyBusy ? "Re-scanning…" : "Verify fixed code"}
              </button>
            )}
          </div>
          {fixWarning && (
            <p className="mt-2 flex items-start gap-2 border-t border-emerald-600/40 pt-2 text-xs text-amber-800 dark:text-amber-300">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              {fixWarning}
            </p>
          )}
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
