"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import type { ScanPayload } from "@/components/ScanResults";

const STORAGE_KEY = "sast:last-scan";

export type ScanSession = {
  payload: ScanPayload;
  /** Severity counts captured before a verify re-scan, for the before → after bar. */
  beforeCounts: ScanPayload["severity_counts"] | null;
  fixSummary: string | null;
  /** Caveat shown under the fix summary when medium-confidence fixes landed. */
  fixWarning: string | null;
  /** Human label for what was scanned, e.g. "src/app.py" or "24 files". */
  label: string;
  finishedAt: number;
  /** True when a patched archive is available in memory to re-scan. */
  hasFixedZip: boolean;
};

/**
 * Upload artifacts are too large for sessionStorage, so they live here:
 * module scope survives client-side navigation (the layout stays mounted) but
 * not a full reload. `hasFixedZip` mirrors the blob for rendering.
 */
export const scanArtifacts: {
  lastZip: File | null;
  fixedZip: Blob | null;
} = { lastZip: null, fixedZip: null };

type SetSessionInput =
  | ScanSession
  | null
  | ((prev: ScanSession | null) => ScanSession | null);

type ScanSessionContextValue = {
  session: ScanSession | null;
  /** False during SSR and the first client render, before storage is read. */
  hydrated: boolean;
  setSession: (next: SetSessionInput) => void;
};

const ScanSessionContext = createContext<ScanSessionContextValue | null>(null);

export function ScanSessionProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  const [session, setSessionState] = useState<ScanSession | null>(null);
  const [hydrated, setHydrated] = useState(false);

  // Restore after mount so the server-rendered markup and hydration agree.
  useEffect(() => {
    try {
      const raw = window.sessionStorage.getItem(STORAGE_KEY);
      if (raw) {
        // The patched archive itself lives in memory only, so a restored
        // session must never claim one is available to verify.
        setSessionState({ ...(JSON.parse(raw) as ScanSession), hasFixedZip: false });
      }
    } catch {
      // Corrupt or unavailable storage — start fresh.
    }
    setHydrated(true);
  }, []);

  // Mirror to sessionStorage so a refresh keeps the report on screen.
  useEffect(() => {
    if (!hydrated) return;
    try {
      if (session) {
        // Upload artifacts are memory-only; do not persist the flag that
        // advertises them, or a reload would render a dead Verify button.
        window.sessionStorage.setItem(
          STORAGE_KEY,
          JSON.stringify({ ...session, hasFixedZip: false })
        );
      } else {
        window.sessionStorage.removeItem(STORAGE_KEY);
      }
    } catch {
      // Storage full or disabled — the report still renders from state.
    }
  }, [session, hydrated]);

  const setSession = useCallback((next: SetSessionInput) => {
    setSessionState((prev) => (typeof next === "function" ? next(prev) : next));
  }, []);

  const value = useMemo(
    () => ({ session, hydrated, setSession }),
    [session, hydrated, setSession]
  );

  return (
    <ScanSessionContext.Provider value={value}>
      {children}
    </ScanSessionContext.Provider>
  );
}

export function useScanSession() {
  const ctx = useContext(ScanSessionContext);
  if (!ctx) {
    throw new Error("useScanSession must be used inside <ScanSessionProvider>");
  }
  return ctx;
}
