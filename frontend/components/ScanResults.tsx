"use client";

import { useCallback, useMemo, useState } from "react";
import {
  AlertTriangle,
  BookOpen,
  Check,
  ChevronDown,
  Copy,
  Download,
  FileJson,
  Loader2,
  Search,
  Wand2,
  X,
} from "lucide-react";

export type Remediation = {
  title: string;
  summary: string;
  steps: string[];
  references: string[];
};

export type SuggestedFix = {
  patched_code: string;
  explanation: string;
  confidence: "high" | "medium";
};

export type Finding = {
  id: string;
  rule_id: string;
  message: string;
  file: string;
  start_line: number;
  end_line: number;
  code_snippet: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  owasp_category: string;
  related_rules: string[];
  remediation: Remediation;
  suggested_fix: SuggestedFix | null;
};

export type ScanPayload = {
  scan_id: string;
  total_findings: number;
  severity_counts: Record<"Critical" | "High" | "Medium" | "Low", number>;
  groups: { category: string; title: string; findings: Finding[] }[];
  errors: unknown[];
};

// Traffic-light severity system — solid badges on milk white, tinted on dark.
const SEVERITY_STYLES: Record<Finding["severity"], string> = {
  Critical:
    "bg-red-600 text-white border-red-700 dark:bg-red-500/15 dark:text-red-400 dark:border-red-500/40",
  High: "bg-orange-500 text-white border-orange-600 dark:bg-orange-500/15 dark:text-orange-400 dark:border-orange-500/40",
  Medium:
    "bg-yellow-400 text-yellow-950 border-yellow-500 dark:bg-yellow-500/15 dark:text-yellow-400 dark:border-yellow-500/40",
  Low: "bg-blue-500 text-white border-blue-600 dark:bg-blue-500/15 dark:text-blue-400 dark:border-blue-500/40",
};

// Text color only — used for the big numbers on the stat cards.
const SEVERITY_TEXT: Record<Finding["severity"], string> = {
  Critical: "text-red-600 dark:text-red-400",
  High: "text-orange-600 dark:text-orange-400",
  Medium: "text-yellow-600 dark:text-yellow-400",
  Low: "text-blue-600 dark:text-blue-400",
};

const SEVERITY_DOT: Record<Finding["severity"], string> = {
  Critical: "bg-red-500",
  High: "bg-orange-500",
  Medium: "bg-yellow-500",
  Low: "bg-blue-500",
};

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(() => {
    navigator.clipboard
      ?.writeText(text)
      .then(() => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 2000);
      })
      .catch(() => undefined);
  }, [text]);
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        copy();
      }}
      aria-label={label}
      title={label}
      className="inline-flex h-7 items-center gap-1.5 rounded-md border border-zinc-700 px-2 text-[11px] text-zinc-400 transition-colors hover:border-zinc-500 hover:text-zinc-200"
    >
      {copied ? (
        <Check className="h-3.5 w-3.5 text-emerald-400" />
      ) : (
        <Copy className="h-3.5 w-3.5" />
      )}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function CodeViewer({ finding }: { finding: Finding }) {
  const lines = finding.code_snippet
    ? finding.code_snippet.split("\n")
    : ["// snippet unavailable"];
  const firstLine = finding.start_line || 1;

  return (
    // Signature look: the code plate stays black in both themes.
    <div className="overflow-hidden rounded-lg border border-zinc-800 bg-[#111110] font-mono text-xs">
      <div className="flex items-center justify-between gap-2 border-b border-zinc-800 pl-3 pr-2 py-1.5 text-zinc-400">
        <span className="truncate font-mono">{finding.file}</span>
        <CopyButton
          text={finding.code_snippet}
          label="Copy flagged code snippet"
        />
      </div>
      <pre className="overflow-x-auto p-0 leading-5">
        {lines.map((line, i) => {
          const lineNo = firstLine + i;
          const highlighted = lineNo === finding.start_line;
          return (
            <div
              key={lineNo}
              className={`flex ${
                highlighted ? "border-l-2 border-red-500 bg-red-500/20" : ""
              }`}
            >
              <span className="w-12 shrink-0 select-none px-2 text-right text-zinc-600">
                {lineNo}
              </span>
              <code className={`whitespace-pre px-3 ${highlighted ? "text-red-200" : "text-zinc-300"}`}>
                {line || " "}
              </code>
            </div>
          );
        })}
      </pre>
    </div>
  );
}

function RemediationNote({ remediation }: { remediation: Remediation }) {
  return (
    <div className="rounded-lg border border-emerald-600 bg-emerald-50 p-4 dark:border-emerald-700/40 dark:bg-emerald-950/30">
      <div className="flex items-center gap-2 font-semibold text-emerald-800 dark:text-emerald-300">
        <BookOpen className="h-4 w-4" />
        {remediation.title}
      </div>
      <p className="mt-2 text-sm text-ink/80 dark:text-slate-300">{remediation.summary}</p>
      <ol className="mt-3 list-decimal space-y-1.5 pl-5 text-sm text-ink/80 dark:text-slate-300">
        {remediation.steps.map((step, i) => (
          <li key={i}>{step}</li>
        ))}
      </ol>
      {remediation.references.length > 0 && (
        <div className="mt-3 text-xs text-muted">
          References: {remediation.references.join(" · ")}
        </div>
      )}
    </div>
  );
}

function SuggestedFixBlock({ fix }: { fix: NonNullable<Finding["suggested_fix"]> }) {
  return (
    <div className="mt-4 rounded-lg border border-emerald-600 bg-emerald-50 p-4 dark:border-emerald-700/40 dark:bg-emerald-950/30">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-2 font-semibold text-emerald-800 dark:text-emerald-300">
          <Wand2 className="h-4 w-4" />
          Suggested fix — review before applying
        </div>
        <span className="rounded-full border border-emerald-600 bg-white px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:border-emerald-500/40 dark:bg-emerald-500/10 dark:text-emerald-300">
          {fix.confidence} confidence
        </span>
      </div>
      <p className="mt-2 text-sm text-ink/80 dark:text-slate-300">{fix.explanation}</p>
      <div className="relative mt-3">
        <div className="absolute right-2 top-2 z-10">
          <CopyButton text={fix.patched_code} label="Copy patched code" />
        </div>
        {/* Patched code keeps the black plate look in both themes. */}
        <pre className="overflow-x-auto rounded-lg border border-zinc-800 bg-[#111110] p-3 pr-20 font-mono text-xs leading-5 text-emerald-200">
          {fix.patched_code}
        </pre>
      </div>
    </div>
  );
}

function FindingCard({
  finding,
  defaultOpen = false,
}: {
  finding: Finding;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const shortFile = finding.file.split("/").pop() ?? finding.file;
  return (
    <div className="rounded-xl border border-ink bg-surface">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full flex-wrap items-center gap-3 rounded-t-xl px-5 py-4 text-left transition-colors hover:bg-faint/60"
      >
        <span
          className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${
            SEVERITY_STYLES[finding.severity]
          }`}
        >
          <span className={`h-2 w-2 rounded-full ${SEVERITY_DOT[finding.severity]}`} />
          {finding.severity}
        </span>
        <code className="text-xs text-muted">{finding.rule_id}</code>
        <span className="text-xs text-muted">
          {shortFile} · lines {finding.start_line}
          {finding.end_line > finding.start_line ? `–${finding.end_line}` : ""}
        </span>
        <span className="min-w-0 flex-1 truncate text-sm text-ink/80">
          {finding.message}
        </span>
        <ChevronDown
          className={`h-4 w-4 shrink-0 text-muted transition-transform ${open ? "rotate-180" : ""}`}
        />
      </button>
      {open && (
        <div className="border-t border-ink/10 p-5 pt-4">
          {finding.related_rules.length > 0 && (
            <div className="mb-2 flex flex-wrap items-center gap-1.5 text-xs text-muted">
              <span>Also flagged by:</span>
              {finding.related_rules.map((rule) => (
                <code
                  key={rule}
                  className="rounded bg-faint px-1.5 py-0.5 text-[11px] text-ink/80 ring-1 ring-ink/15"
                >
                  {rule}
                </code>
              ))}
            </div>
          )}
          <p className="mb-4 text-sm text-ink">{finding.message}</p>
          <div className="grid gap-4 lg:grid-cols-2">
            <CodeViewer finding={finding} />
            <RemediationNote remediation={finding.remediation} />
          </div>
          {finding.suggested_fix && <SuggestedFixBlock fix={finding.suggested_fix} />}
        </div>
      )}
    </div>
  );
}

const SEVERITIES = ["Critical", "High", "Medium"] as const;
type Sev = (typeof SEVERITIES)[number];

export default function ScanResults({
  payload,
  onDownloadFixed,
  fixBusy = false,
}: {
  payload: ScanPayload;
  onDownloadFixed?: () => void;
  fixBusy?: boolean;
}) {
  const counts = payload.severity_counts;
  const fixableCount = payload.groups.reduce(
    (sum, g) => sum + g.findings.filter((f) => f.suggested_fix).length,
    0
  );
  const [severityFilter, setSeverityFilter] = useState<Set<Sev>>(new Set());
  const [query, setQuery] = useState("");
  const [errorsDismissed, setErrorsDismissed] = useState(false);

  const toggleSeverity = useCallback((sev: Sev) => {
    setSeverityFilter((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);
      return next;
    });
  }, []);

  const q = query.trim().toLowerCase();
  const filtersActive = severityFilter.size > 0 || q.length > 0;

  const filteredGroups = useMemo(() => {
    if (!filtersActive) return payload.groups;
    return payload.groups
      .map((group) => ({
        ...group,
        findings: group.findings.filter((f) => {
          if (severityFilter.size > 0 && !severityFilter.has(f.severity as Sev))
            return false;
          if (!q) return true;
          return (
            f.file.toLowerCase().includes(q) ||
            f.rule_id.toLowerCase().includes(q) ||
            f.message.toLowerCase().includes(q) ||
            f.owasp_category.toLowerCase().includes(q)
          );
        }),
      }))
      .filter((g) => g.findings.length > 0);
  }, [payload.groups, severityFilter, q, filtersActive]);

  const shownCount = filtersActive
    ? filteredGroups.reduce((sum, g) => sum + g.findings.length, 0)
    : payload.total_findings;

  const downloadJson = useCallback(() => {
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "scan-report.json";
    link.click();
    URL.revokeObjectURL(url);
  }, [payload]);

  return (
    <section className="space-y-6">
      {/* Stat cards double as severity filters */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <div className="rounded-xl border border-ink bg-surface p-4">
          <div className="text-3xl font-bold">{payload.total_findings}</div>
          <div className="text-xs text-muted">Total findings</div>
        </div>
        {SEVERITIES.map((sev) => {
          const active = severityFilter.has(sev);
          return (
            <button
              key={sev}
              type="button"
              onClick={() => toggleSeverity(sev)}
              aria-pressed={active}
              title={`Show only ${sev} findings`}
              className={`rounded-xl border border-ink p-4 text-left transition-colors ${
                active ? "bg-faint" : "bg-surface hover:bg-faint/60"
              }`}
            >
              <div className={`flex items-center gap-2 text-3xl font-bold ${SEVERITY_TEXT[sev]}`}>
                <span className={`h-3 w-3 rounded-full ${SEVERITY_DOT[sev]}`} />
                {counts[sev] ?? 0}
              </div>
              <div className="text-xs text-muted">{sev}</div>
            </button>
          );
        })}
      </div>

      {/* Triage toolbar: search + severity chips + JSON export */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[220px] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search file, rule, message, OWASP category…"
            className="w-full rounded-lg border border-ink/40 bg-surface py-2 pl-9 pr-3 text-sm text-ink placeholder:text-muted/70 focus:border-ink focus:outline-none"
          />
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {SEVERITIES.map((sev) => {
            const active = severityFilter.has(sev);
            return (
              <button
                key={sev}
                type="button"
                onClick={() => toggleSeverity(sev)}
                aria-pressed={active}
                className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                  active
                    ? "border-ink bg-ink text-bg"
                    : "border-ink/40 bg-surface text-ink hover:border-ink"
                }`}
              >
                <span className={`h-2 w-2 rounded-full ${SEVERITY_DOT[sev]}`} />
                {sev}
              </button>
            );
          })}
          <button
            type="button"
            onClick={downloadJson}
            title="Download the full report as JSON"
            className="inline-flex items-center gap-1.5 rounded-full border border-ink/40 bg-surface px-3 py-1 text-xs font-medium text-ink transition-colors hover:border-ink"
          >
            <FileJson className="h-3.5 w-3.5" /> JSON
          </button>
          {filtersActive && (
            <button
              type="button"
              onClick={() => {
                setSeverityFilter(new Set());
                setQuery("");
              }}
              className="inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs text-muted transition-colors hover:text-ink"
            >
              <X className="h-3.5 w-3.5" /> Clear
            </button>
          )}
        </div>
      </div>

      {filtersActive && (
        <p className="text-sm text-muted" aria-live="polite">
          Showing {shownCount} of {payload.total_findings} findings.
        </p>
      )}

      {/* Backend scan warnings (rules that failed, files skipped) */}
      {payload.errors.length > 0 && !errorsDismissed && (
        <div className="rounded-lg border border-amber-600 bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:border-amber-500/50 dark:bg-amber-950/30 dark:text-amber-300">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <div>
                <div className="font-semibold">
                  {payload.errors.length} warning
                  {payload.errors.length !== 1 ? "s" : ""} during this scan
                </div>
                <ul className="mt-1 list-disc space-y-0.5 pl-5 text-xs">
                  {payload.errors.map((err, i) => (
                    <li key={i}>{String(err)}</li>
                  ))}
                </ul>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setErrorsDismissed(true)}
              aria-label="Dismiss scan warnings"
              className="rounded p-1 hover:bg-amber-100 dark:hover:bg-amber-900/40"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}

      {fixableCount > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-emerald-600 bg-emerald-50 px-4 py-3 dark:border-emerald-800/60 dark:bg-emerald-950/20">
          <div className="text-sm text-ink/80 dark:text-slate-300">
            <span className="font-semibold text-emerald-700 dark:text-emerald-300">
              {fixableCount} finding{fixableCount !== 1 ? "s" : ""}
            </span>{" "}
            {fixableCount === 1 ? "has" : "have"} an auto-generated suggested
            fix. Download a patched copy of your source to review.
          </div>
          {onDownloadFixed && (
            <button
              type="button"
              onClick={onDownloadFixed}
              disabled={fixBusy}
              className="inline-flex items-center gap-2 rounded-lg bg-ink px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-85 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {fixBusy ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Download className="h-4 w-4" />
              )}
              {fixBusy ? "Preparing fixes…" : "Download fixed code"}
            </button>
          )}
        </div>
      )}

      {payload.total_findings === 0 && (
        <div className="rounded-xl border border-emerald-600 bg-emerald-50 p-6 text-center text-emerald-800 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300">
          No OWASP Top 10 findings detected. Nice codebase.
        </div>
      )}

      {filtersActive && filteredGroups.length === 0 && (
        <div className="rounded-xl border border-dashed border-ink/40 p-6 text-center text-sm text-muted">
          No findings match your filters.
        </div>
      )}

      {filteredGroups.map((group) => (
        <div key={group.category} className="space-y-3">
          <h3 className="flex items-center gap-2 text-lg font-semibold text-ink">
            <AlertTriangle className="h-5 w-5 text-amber-600 dark:text-amber-400" />
            {group.title}
            <span className="text-sm font-normal text-muted">
              ({group.findings.length} finding{group.findings.length !== 1 ? "s" : ""})
            </span>
          </h3>
          {group.findings.map((f) => (
            <FindingCard
              key={f.id}
              finding={f}
              defaultOpen={
                f.severity === "Critical" ||
                (q.length > 0 && group.findings.length <= 5)
              }
            />
          ))}
        </div>
      ))}
    </section>
  );
}
