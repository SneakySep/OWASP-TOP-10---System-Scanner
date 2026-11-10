"use client";

import {
  Ban,
  FileArchive,
  Files,
  FolderOpen,
  Loader2,
  UploadCloud,
} from "lucide-react";
import { MAX_TOTAL_BYTES, formatBytes, type ScanFlow } from "@/lib/useScanFlow";

// React's input types don't know the non-standard folder-picker attributes.
const folderInputProps = {
  webkitdirectory: "",
  directory: "",
} as unknown as React.InputHTMLAttributes<HTMLInputElement>;

export default function UploadDropzone({ flow }: { flow: ScanFlow }) {
  return (
    <div
      onDragOver={flow.onDragOver}
      onDragEnter={flow.onDragEnter}
      onDragLeave={flow.onDragLeave}
      onDrop={flow.onDrop}
      className={`flex flex-col items-center justify-center rounded-2xl border-2 border-dashed p-8 text-center transition-colors sm:p-14 ${
        flow.dragActive
          ? "border-ink bg-faint"
          : "border-ink/40 bg-surface md:hover:border-ink"
      }`}
    >
      <input
        ref={flow.filesInputRef}
        id="scan-files"
        type="file"
        multiple
        className="sr-only"
        disabled={flow.busy}
        onChange={flow.handleInputChange}
      />
      <input
        ref={flow.folderInputRef}
        id="scan-folder"
        type="file"
        multiple
        className="sr-only"
        disabled={flow.busy}
        {...folderInputProps}
        onChange={flow.handleInputChange}
      />
      {flow.status ? (
        <div className="flex w-full flex-col items-center">
          <Loader2
            aria-hidden="true"
            className="h-12 w-12 animate-spin text-emerald-600 motion-reduce:animate-none dark:text-emerald-400"
          />
          <p className="mt-4 font-medium">
            {flow.status}
            {flow.elapsed >= 1 && (
              <span className="ml-1 tabular-nums">· {flow.elapsed}s</span>
            )}
          </p>
          <div
            role="progressbar"
            aria-label="Upload progress"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={flow.progress ?? undefined}
            className="mt-4 h-1.5 w-56 overflow-hidden rounded-full bg-faint"
          >
            {flow.progress === null ? (
              <div className="h-full w-1/3 rounded-full bg-emerald-600 animate-indeterminate motion-reduce:animate-none dark:bg-emerald-400" />
            ) : (
              <div
                className="h-full rounded-full bg-emerald-600 transition-[width] duration-200 dark:bg-emerald-400"
                style={{ width: `${flow.progress}%` }}
              />
            )}
          </div>
          <p className="mt-3 text-sm text-muted">
            {flow.phase === "packing"
              ? "Compressing the selection in your browser — nothing has been uploaded yet."
              : flow.phase === "verifying"
                ? "Re-running Semgrep on the patched copy to compare results."
                : flow.phase === "fixing"
                  ? "Generating a patched archive — review it before committing."
                  : "Running Semgrep against the OWASP Top 10 ruleset. This can take a minute on first run while rules download."}
          </p>
          {(flow.phase === "packing" || flow.phase === "scanning") && (
            <button
              type="button"
              onClick={flow.cancel}
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
              Any mix of files and folders (or a single .zip), up to{" "}
              {formatBytes(MAX_TOTAL_BYTES)} — junk folders like node_modules
              and .git are skipped
            </p>
          </label>
          <div className="mt-5 flex flex-wrap items-center justify-center gap-3">
            <button
              type="button"
              onClick={() => flow.filesInputRef.current?.click()}
              className="inline-flex items-center gap-2 rounded-lg bg-ink px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-85"
            >
              <Files className="h-4 w-4" /> Browse files
            </button>
            <button
              type="button"
              onClick={() => flow.folderInputRef.current?.click()}
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
  );
}
