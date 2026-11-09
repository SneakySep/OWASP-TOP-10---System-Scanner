import type { Metadata } from "next";
import { Settings } from "lucide-react";
import SettingsPanel from "@/components/SettingsPanel";

export const metadata: Metadata = {
  title: "Settings — SAST Scanner",
};

export default function SettingsPage() {
  return (
    <div className="mx-auto max-w-5xl">
      <h2 className="flex items-center gap-2 text-2xl font-bold">
        <Settings className="h-6 w-6" /> Settings
      </h2>
      <p className="mt-2 text-sm text-muted">
        Point the dashboard at a different backend and choose which Semgrep
        ruleset scans use.
      </p>
      <SettingsPanel />
    </div>
  );
}
