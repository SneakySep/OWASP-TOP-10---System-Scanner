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
        Scans are not persisted in a database — each one runs in an isolated
        temporary directory. The most recent report is kept in this browser
        session so you can navigate away and come back to it.
      </p>
      <HistoryList />
    </div>
  );
}
