"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { BookOpen, ChevronDown, ExternalLink, RefreshCw, Search, X } from "lucide-react";
import { apiUrl } from "@/lib/api";

type Reference = { title: string; url: string };

type RemediationEntry = {
  category: string;
  title: string;
  summary: string;
  steps: string[];
  references: Reference[];
};

export default function RemediationCatalog() {
  const [entries, setEntries] = useState<RemediationEntry[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(apiUrl("/api/remediation"));
      if (!res.ok) {
        throw new Error(
          res.status === 404
            ? "The backend does not expose the catalog yet (404) — restart it on the current version."
            : `The backend returned ${res.status}.`
        );
      }
      const data = await res.json();
      setEntries(Array.isArray(data.categories) ? data.categories : []);
    } catch (e) {
      const message = e instanceof Error ? e.message : "";
      setError(
        message.startsWith("The backend")
          ? message
          : "Could not reach the scanner API. Check that the backend is running at the configured URL and try again."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const q = query.trim().toLowerCase();
  const filtered = useMemo(() => {
    if (!entries) return [];
    if (!q) return entries;
    return entries.filter((entry) =>
      [
        entry.category,
        entry.title,
        entry.summary,
        ...entry.steps,
        ...entry.references.map((reference) => reference.title),
      ]
        .join(" ")
        .toLowerCase()
        .includes(q)
    );
  }, [entries, q]);

  if (loading) {
    return (
      <div className="mt-8 space-y-3" aria-busy="true" aria-live="polite">
        <p className="sr-only">Loading the remediation catalog…</p>
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            className="h-20 animate-pulse rounded-xl bg-faint motion-reduce:animate-none"
            aria-hidden="true"
          />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div
        role="alert"
        className="mt-8 rounded-xl border border-red-700 bg-red-50 px-4 py-4 text-sm text-red-800 dark:border-red-800 dark:bg-red-950/50 dark:text-red-300"
      >
        <p className="font-semibold">The catalog could not be loaded.</p>
        <p className="mt-1">{error}</p>
        <button
          type="button"
          onClick={() => void load()}
          className="mt-3 inline-flex items-center gap-2 rounded-lg border border-red-700/50 px-3 py-1.5 font-medium transition-colors hover:bg-red-100 dark:border-red-700 dark:hover:bg-red-950"
        >
          <RefreshCw className="h-4 w-4" /> Try again
        </button>
      </div>
    );
  }

  return (
    <div className="mt-6 space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[220px] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search categories, guidance, keywords…"
            aria-label="Search the remediation catalog"
            className="w-full rounded-lg border border-ink/40 bg-surface py-2 pl-9 pr-3 text-sm text-ink placeholder:text-muted focus:border-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-ink focus-visible:ring-offset-2 focus-visible:ring-offset-bg"
          />
        </div>
        {q && (
          <button
            type="button"
            onClick={() => setQuery("")}
            className="inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs text-muted transition-colors hover:text-ink"
          >
            <X className="h-3.5 w-3.5" /> Clear
          </button>
        )}
        <p className="text-sm text-muted" aria-live="polite">
          {filtered.length} of {entries?.length ?? 0} categories
        </p>
      </div>

      {filtered.length === 0 && (
        <div className="rounded-xl border border-dashed border-ink/40 p-6 text-center text-sm text-muted">
          No categories match &ldquo;{query.trim()}&rdquo;.
        </div>
      )}

      <div className="space-y-3">
        {filtered.map((entry) => (
          // Native <details> keeps the accordion keyboard- and screen-reader
          // friendly without extra state; search results open themselves.
          <details
            key={entry.category}
            open={q ? true : undefined}
            className="group rounded-xl border border-ink bg-surface"
          >
            <summary className="flex cursor-pointer list-none items-start gap-3 px-5 py-4 [&::-webkit-details-marker]:hidden">
              <BookOpen className="mt-0.5 h-5 w-5 shrink-0 text-emerald-600 dark:text-emerald-400" />
              <div className="min-w-0 flex-1">
                <h3 className="text-base font-semibold text-ink">{entry.title}</h3>
                <p className="mt-0.5 font-mono text-xs text-muted">{entry.category}</p>
              </div>
              <span className="shrink-0 text-xs text-muted">
                {entry.steps.length} step{entry.steps.length === 1 ? "" : "s"}
              </span>
              <ChevronDown className="mt-0.5 h-4 w-4 shrink-0 text-muted transition-transform group-open:rotate-180" />
            </summary>
            <div className="border-t border-ink/10 px-5 py-4">
              <p className="text-sm text-ink/80">{entry.summary}</p>
              <h4 className="mt-4 text-xs font-semibold uppercase tracking-wide text-muted">
                Fix checklist
              </h4>
              <ol className="mt-2 list-decimal space-y-1.5 pl-5 text-sm text-ink/80">
                {entry.steps.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ol>
              {entry.references.length > 0 && (
                <>
                  <h4 className="mt-4 text-xs font-semibold uppercase tracking-wide text-muted">
                    References
                  </h4>
                  <ul className="mt-1 space-y-1 text-xs">
                    {entry.references.map((reference) => (
                      <li key={reference.url}>
                        <a
                          href={reference.url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 text-muted underline decoration-ink/30 underline-offset-2 transition-colors hover:text-ink hover:decoration-ink"
                        >
                          {reference.title}
                          <ExternalLink className="h-3 w-3 shrink-0" />
                        </a>
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          </details>
        ))}
      </div>
    </div>
  );
}
