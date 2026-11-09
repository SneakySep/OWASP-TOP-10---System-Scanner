"use client";

import { useEffect, useState } from "react";
import {
  CheckCircle2,
  Loader2,
  PlugZap,
  RotateCcw,
  Save,
  XCircle,
} from "lucide-react";
import {
  DEFAULT_API_BASE,
  DEFAULT_RULESET,
  RULESETS,
  getApiBase,
  getRuleset,
  isValidApiBase,
  normalizeApiBase,
  setApiBase,
  setRuleset,
} from "@/lib/api";

type TestState =
  | { status: "idle" }
  | { status: "testing" }
  | { status: "ok"; message: string }
  | { status: "error"; message: string };

export default function SettingsPanel() {
  const [apiBase, setApiBaseInput] = useState(DEFAULT_API_BASE);
  const [ruleset, setRulesetInput] = useState<string>(DEFAULT_RULESET);
  const [hydrated, setHydrated] = useState(false);
  const [test, setTest] = useState<TestState>({ status: "idle" });
  const [error, setError] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  // Settings live in localStorage, so read them after mount.
  useEffect(() => {
    setApiBaseInput(getApiBase());
    setRulesetInput(getRuleset());
    setHydrated(true);
  }, []);

  useEffect(() => {
    if (savedAt === null) return;
    const timer = window.setTimeout(() => setSavedAt(null), 3000);
    return () => window.clearTimeout(timer);
  }, [savedAt]);

  const testConnection = async () => {
    const base = normalizeApiBase(apiBase);
    if (!isValidApiBase(base)) {
      setTest({ status: "error", message: "Enter a valid http(s) URL first." });
      return;
    }
    setTest({ status: "testing" });
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 5000);
    try {
      const res = await fetch(`${base}/api/health`, {
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json().catch(() => ({}));
      if (data?.status !== "ok") throw new Error("Unexpected response");
      setTest({
        status: "ok",
        message: "Connected — /api/health returned ok.",
      });
    } catch {
      setTest({
        status: "error",
        message: `Could not reach ${base}. Is the backend running, and does it allow this origin?`,
      });
    } finally {
      window.clearTimeout(timer);
    }
  };

  const save = () => {
    const base = normalizeApiBase(apiBase);
    if (!isValidApiBase(base)) {
      setError("Enter a valid http(s) backend URL before saving.");
      return;
    }
    setError(null);
    setApiBase(base);
    setRuleset(ruleset);
    setSavedAt(Date.now());
  };

  const reset = () => {
    setApiBase(null);
    setRuleset(null);
    setApiBaseInput(DEFAULT_API_BASE);
    setRulesetInput(DEFAULT_RULESET);
    setTest({ status: "idle" });
    setError(null);
    setSavedAt(Date.now());
  };

  return (
    <div className="mt-6 space-y-5">
      <section className="rounded-xl border border-ink bg-surface p-5">
        <h3 className="flex items-center gap-2 text-base font-semibold">
          <PlugZap className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
          Backend connection
        </h3>
        <p className="mt-1 text-sm text-muted">
          Where scan requests are sent. The build default is{" "}
          <code className="rounded bg-faint px-1.5 py-0.5 text-xs ring-1 ring-ink/15">
            {DEFAULT_API_BASE}
          </code>
          ; an override is stored in this browser only.
        </p>

        <div className="mt-4">
          <label
            htmlFor="api-base"
            className="block text-sm font-medium text-ink"
          >
            API base URL
          </label>
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <input
              id="api-base"
              type="url"
              value={apiBase}
              disabled={!hydrated}
              onChange={(e) => {
                setApiBaseInput(e.target.value);
                setTest({ status: "idle" });
              }}
              aria-invalid={error ? true : undefined}
              aria-describedby="api-base-help"
              placeholder="http://localhost:8000"
              className="min-w-[260px] flex-1 rounded-lg border border-ink/40 bg-surface px-3 py-2 font-mono text-sm text-ink placeholder:text-muted focus:border-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-ink focus-visible:ring-offset-2 focus-visible:ring-offset-bg"
            />
            <button
              type="button"
              onClick={() => void testConnection()}
              disabled={!hydrated || test.status === "testing"}
              className="inline-flex items-center gap-2 rounded-lg border border-ink/40 bg-surface px-3 py-2 text-sm font-medium text-ink transition-colors hover:border-ink hover:bg-faint disabled:cursor-not-allowed disabled:opacity-50"
            >
              {test.status === "testing" ? (
                <Loader2 className="h-4 w-4 animate-spin motion-reduce:animate-none" />
              ) : (
                <PlugZap className="h-4 w-4" />
              )}
              {test.status === "testing" ? "Testing…" : "Test connection"}
            </button>
          </div>
          <p id="api-base-help" className="mt-1.5 text-xs text-muted">
            Absolute http(s) URL, no trailing slash. Use{" "}
            <code className="rounded bg-faint px-1 py-0.5 ring-1 ring-ink/15">
              http://backend:8000
            </code>{" "}
            from inside the container network.
          </p>
          {error && (
            <p role="alert" className="mt-2 text-sm text-red-700 dark:text-red-400">
              {error}
            </p>
          )}
          <div aria-live="polite">
            {test.status === "ok" && (
              <p className="mt-2 flex items-center gap-1.5 text-sm text-emerald-700 dark:text-emerald-400">
                <CheckCircle2 className="h-4 w-4" /> {test.message}
              </p>
            )}
            {test.status === "error" && (
              <p className="mt-2 flex items-start gap-1.5 text-sm text-red-700 dark:text-red-400">
                <XCircle className="mt-0.5 h-4 w-4 shrink-0" /> {test.message}
              </p>
            )}
          </div>
        </div>
      </section>

      <section className="rounded-xl border border-ink bg-surface p-5">
        <h3 className="text-base font-semibold">Scan ruleset</h3>
        <p className="mt-1 text-sm text-muted">
          Sent with every scan and fix request. The backend only accepts the
          rulesets listed here.
        </p>
        <fieldset className="mt-4">
          <legend className="sr-only">Ruleset</legend>
          <div className="space-y-2">
            {RULESETS.map((option) => {
              const active = ruleset === option.id;
              return (
                <label
                  key={option.id}
                  className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 transition-colors ${
                    active
                      ? "border-ink bg-faint"
                      : "border-ink/30 bg-surface hover:bg-faint/50"
                  }`}
                >
                  <input
                    type="radio"
                    name="ruleset"
                    value={option.id}
                    checked={active}
                    disabled={!hydrated}
                    onChange={() => setRulesetInput(option.id)}
                    className="mt-1 accent-ink"
                  />
                  <span className="min-w-0">
                    <span className="block text-sm font-medium text-ink">
                      {option.label}
                    </span>
                    <span className="mt-0.5 block text-xs text-muted">
                      {option.description}
                    </span>
                    <code className="mt-1 block text-[11px] text-muted">
                      {option.id}
                    </code>
                  </span>
                </label>
              );
            })}
          </div>
        </fieldset>
      </section>

      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={save}
          disabled={!hydrated}
          className="inline-flex items-center gap-2 rounded-lg bg-ink px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-85 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <Save className="h-4 w-4" /> Save changes
        </button>
        <button
          type="button"
          onClick={reset}
          className="inline-flex items-center gap-2 rounded-lg border border-ink/40 bg-surface px-4 py-2 text-sm font-medium text-ink transition-colors hover:bg-faint"
        >
          <RotateCcw className="h-4 w-4" /> Reset to defaults
        </button>
        <p role="status" className="text-sm text-emerald-700 dark:text-emerald-400">
          {savedAt ? "Saved — applies to new scans." : ""}
        </p>
      </div>

      <p className="text-xs text-muted">
        These preferences are stored in this browser, not on the server. Already
        open pages that fetched data (such as the remediation catalog) need a
        reload to pick up a new URL.
      </p>
    </div>
  );
}
