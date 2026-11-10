"use client";

/**
 * Runtime settings. `NEXT_PUBLIC_API_URL` is only the build-time default; the
 * Settings page can override the backend URL and the Semgrep ruleset per
 * browser. Everything is read at request time so changes apply immediately.
 */

import type { ScanPayload } from "@/components/ScanResults";

export const DEFAULT_API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const API_BASE_KEY = "sast:api-base";
const RULESET_KEY = "sast:ruleset";

/** Keep in sync with ALLOWED_RULESETS in backend/main.py. */
export const RULESETS = [
  {
    id: "p/owasp-top-ten",
    label: "OWASP Top 10",
    description: "The default pack — one rule set per OWASP Top 10 category.",
  },
  {
    id: "p/security-audit",
    label: "Semgrep security-audit",
    description: "Broader security pack: more checks, and more noise to triage.",
  },
] as const;

export const DEFAULT_RULESET: string = RULESETS[0].id;

function read(key: string): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key: string, value: string | null): void {
  if (typeof window === "undefined") return;
  try {
    if (value) window.localStorage.setItem(key, value);
    else window.localStorage.removeItem(key);
  } catch {
    // Private mode or a full quota — the default still applies.
  }
}

export function normalizeApiBase(value: string): string {
  return value.trim().replace(/\/+$/, "");
}

export function isValidApiBase(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

export function getApiBase(): string {
  const stored = read(API_BASE_KEY);
  return stored ? normalizeApiBase(stored) : DEFAULT_API_BASE;
}

export function setApiBase(value: string | null): void {
  write(API_BASE_KEY, value ? normalizeApiBase(value) : null);
}

/** Absolute URL for an API path on the configured backend. */
export function apiUrl(path: string): string {
  return `${getApiBase()}${path.startsWith("/") ? path : `/${path}`}`;
}

export function isKnownRuleset(value: string): boolean {
  return RULESETS.some((ruleset) => ruleset.id === value);
}

export function getRuleset(): string {
  const stored = read(RULESET_KEY);
  return stored && isKnownRuleset(stored) ? stored : DEFAULT_RULESET;
}

export function setRuleset(value: string | null): void {
  write(RULESET_KEY, value && isKnownRuleset(value) ? value : null);
}

/** Metadata for one stored scan, as returned by `GET /api/scans`. */
export type ScanSummary = {
  scan_id: string;
  label: string;
  ruleset: string;
  /** Unix seconds. */
  created_at: number;
  total_findings: number;
  severity_counts: ScanPayload["severity_counts"];
  /** Findings that were not in the previous scan of the same target. */
  new_findings: number;
  fixed_findings: number;
};

/** One stored scan plus its full report payload (the permalink shape). */
export type ScanDetail = ScanSummary & {
  fingerprint: string;
  payload: ScanPayload;
};

/** Server-side scan history, newest first. */
export async function fetchScans(signal?: AbortSignal): Promise<ScanSummary[]> {
  const res = await fetch(apiUrl("/api/scans"), { signal });
  if (!res.ok) throw new Error(`History request failed (HTTP ${res.status}).`);
  const data = (await res.json()) as { scans?: ScanSummary[] };
  return data.scans ?? [];
}

/** One stored report, in the same shape a live scan returns. */
export async function fetchScan(
  id: string,
  signal?: AbortSignal
): Promise<ScanDetail> {
  const res = await fetch(apiUrl(`/api/scans/${encodeURIComponent(id)}`), {
    signal,
  });
  if (res.status === 404) throw new Error("That report is no longer stored.");
  if (!res.ok) throw new Error(`Report request failed (HTTP ${res.status}).`);
  return (await res.json()) as ScanDetail;
}
