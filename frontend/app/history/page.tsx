import type { Metadata } from "next";
import { History } from "lucide-react";
import HistoryList from "@/components/HistoryList";

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
        Every scan is stored on the backend with its findings and severity
        breakdown. The newest scan of the same target is used as the baseline,
        so each report shows what is new and what was fixed since last time.
      </p>
      <HistoryList />
    </div>
  );
}
