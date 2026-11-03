import type { Metadata } from "next";
import { History } from "lucide-react";

export const metadata: Metadata = {
  title: "Scan History — SAST Scanner",
};

export default function HistoryPage() {
  return (
    <div className="mx-auto max-w-5xl">
      <h2 className="flex items-center gap-2 text-2xl font-bold">
        <History className="h-6 w-6" /> Scan History
      </h2>
      <p className="mt-2 text-sm text-muted">
        Scan results are not persisted in this build — each scan runs in an
        isolated temporary directory that is destroyed afterward. Wire this page
        to a database to retain history.
      </p>
      <div className="mt-8 flex flex-col items-center justify-center rounded-2xl border-2 border-dashed border-ink/30 p-12 text-center">
        <History className="h-10 w-10 text-muted" />
        <p className="mt-3 font-medium">No saved scans yet</p>
        <p className="mt-1 max-w-sm text-sm text-muted">
          Once scan persistence is wired up, every run will be listed here with
          its severity breakdown, so you can track fixes over time.
        </p>
      </div>
    </div>
  );
}
