import type { Metadata } from "next";
import { Settings } from "lucide-react";

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
        Backend endpoint: <code className="rounded bg-faint px-1.5 py-0.5 text-xs ring-1 ring-ink/15">http://backend:8000/api/scan</code>{" "}
        (container network) · <code className="rounded bg-faint px-1.5 py-0.5 text-xs ring-1 ring-ink/15">http://localhost:8000/api/scan</code>{" "}
        (local dev).
      </p>
      <div className="mt-8 flex flex-col items-center justify-center rounded-2xl border-2 border-dashed border-ink/30 p-12 text-center">
        <Settings className="h-10 w-10 text-muted" />
        <p className="mt-3 font-medium">No configurable options yet</p>
        <p className="mt-1 max-w-sm text-sm text-muted">
          Ruleset selection, default theme, and API URL overrides will live here.
          For now the scanner always uses the OWASP Top 10 ruleset.
        </p>
      </div>
    </div>
  );
}
