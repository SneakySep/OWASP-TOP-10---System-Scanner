"use client";

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type DragEvent as ReactDragEvent,
} from "react";
import JSZip from "jszip";
import {
  CollectionError,
  MAX_FILES,
  collectFromDataTransfer,
  collectFromInput,
  type PickedFile,
} from "@/lib/collectFiles";
import { apiUrl, getRuleset } from "@/lib/api";
import { scanArtifacts, useScanSession } from "@/lib/scanSession";
import type { ScanPayload } from "@/components/ScanResults";

/** Must match MAX_UPLOAD_BYTES in backend/main.py. */
export const MAX_TOTAL_BYTES = 100 * 1024 * 1024;

export type ScanPhase = "idle" | "packing" | "scanning" | "fixing" | "verifying";

export function formatBytes(bytes: number): string {
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

/**
 * Drives one scan lifecycle: collect/pack a selection, POST /api/scan, then
 * download or verify the patched archive. All UI state for the flow lives
 * here so the page is just composition and markup.
 */
export function useScanFlow() {
  const { session, setSession } = useScanSession();
  const result = session?.payload ?? null;
  const beforeCounts = session?.beforeCounts ?? null;
  const fixSummary = session?.fixSummary ?? null;
  const fixWarning = session?.fixWarning ?? null;
  const hasFixedZip = session?.hasFixedZip ?? false;

  const [dragActive, setDragActive] = useState(false);
  const [phase, setPhase] = useState<ScanPhase>("idle");
  const [status, setStatus] = useState<string | null>(null);
  // 0–100 while packing the upload; null means "indeterminate".
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // Short text for screen readers — never contains the ticking timer.
  const [announcement, setAnnouncement] = useState("");
  const [fixBusy, setFixBusy] = useState(false);
  const [patchBusy, setPatchBusy] = useState(false);
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
    const prevent = (e: globalThis.DragEvent) => e.preventDefault();
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

  // Patch download: the same fixes as /api/fix, but as a diff the user can
  // `git apply` to their own checkout instead of replacing the tree.
  const downloadPatch = useCallback(async () => {
    const zip = scanArtifacts.lastZip;
    if (patchBusy) return;
    if (!zip) {
      setError(
        "The uploaded archive is no longer in memory — run a new scan to generate a patch."
      );
      return;
    }
    setPatchBusy(true);
    setError(null);
    setNotice(null);
    setAnnouncement("");
    setElapsed(0);
    setPhase("fixing");
    setStatus("Building patch…");
    try {
      const form = new FormData();
      form.append("file", zip);
      form.append("ruleset", getRuleset());
      form.append("format", "patch");
      const res = await fetch(apiUrl("/api/fix"), {
        method: "POST",
        body: form,
      });
      if (!res.ok) {
        const detail = await res.json().catch(() => ({}));
        throw new Error(
          detail.detail || `Patch request failed with status ${res.status}`
        );
      }
      const blob = await res.blob();
      const applied = Number(res.headers.get("X-Fixes-Applied") ?? 0);
      const unfixed = Number(res.headers.get("X-Fixes-Unfixed") ?? 0);
      const total = applied + unfixed;
      if (blob.size === 0) {
        setNotice(
          `No fixes could be applied automatically (${total} finding${
            total === 1 ? "" : "s"
          }) — follow the remediation guidance on each card.`
        );
        setAnnouncement("No patch was produced.");
        return;
      }
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "sast-fixes.patch";
      link.click();
      URL.revokeObjectURL(url);
      setSession((prev) =>
        prev
          ? {
              ...prev,
              fixSummary: `Patch ready — ${applied} of ${total} fixes. Apply from your repo root with git apply sast-fixes.patch.`,
              fixWarning:
                unfixed > 0
                  ? `${unfixed} finding${
                      unfixed === 1 ? " has" : "s have"
                    } no automatic fix — follow the remediation guidance on those cards.`
                  : null,
            }
          : prev
      );
      setAnnouncement("Patch downloaded.");
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Unexpected error while building the patch."
      );
    } finally {
      setPatchBusy(false);
      setStatus(null);
      setPhase("idle");
    }
  }, [patchBusy, setSession]);

  // Verify-fixes loop: re-scan the patched archive and compare severity
  // counts before → after. Uses only the existing /api/scan endpoint.
  const verifyFixed = useCallback(async () => {
    const blob = scanArtifacts.fixedZip;
    if (!blob) {
      setError(
        "The patched archive is no longer in memory — download the fixed code again to verify it."
      );
      return;
    }
    if (verifyBusy || !session) return;
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
    (e: ReactDragEvent<HTMLDivElement>) => {
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

  const onDragOver = useCallback((e: ReactDragEvent<HTMLDivElement>) => {
    if (!Array.from(e.dataTransfer.types).includes("Files")) return;
    e.preventDefault();
    setDragActive(true);
  }, []);

  const onDragEnter = useCallback((e: ReactDragEvent<HTMLDivElement>) => {
    if (!Array.from(e.dataTransfer.types).includes("Files")) return;
    e.preventDefault();
    dragDepthRef.current += 1;
    setDragActive(true);
  }, []);

  const onDragLeave = useCallback(() => {
    dragDepthRef.current = Math.max(0, dragDepthRef.current - 1);
    if (dragDepthRef.current === 0) setDragActive(false);
  }, []);

  const handleInputChange = useCallback(
    (event: ChangeEvent<HTMLInputElement>) => {
      void handlePicked(collectFromInput(event.target.files));
      event.target.value = "";
    },
    [handlePicked]
  );

  return {
    result,
    beforeCounts,
    fixSummary,
    fixWarning,
    hasFixedZip,
    phase,
    busy: phase !== "idle",
    status,
    progress,
    error,
    notice,
    announcement,
    dragActive,
    fixBusy,
    patchBusy,
    verifyBusy,
    elapsed,
    filesInputRef,
    folderInputRef,
    cancel,
    downloadFixed,
    downloadPatch,
    verifyFixed,
    handlePicked,
    handleInputChange,
    onDrop,
    onDragOver,
    onDragEnter,
    onDragLeave,
  };
}

export type ScanFlow = ReturnType<typeof useScanFlow>;
