import type { Metadata } from "next";
import { Database } from "lucide-react";

export const metadata: Metadata = {
  title: "Remediation Database — SAST Scanner",
};

export default function RemediationPage() {
  return (
    <div className="mx-auto max-w-5xl">
      <h2 className="flex items-center gap-2 text-2xl font-bold">
        <Database className="h-6 w-6" /> Remediation Database
      </h2>
      <p className="mt-2 text-sm text-muted">
        The full remediation knowledge base lives in
        <code className="mx-1 rounded bg-faint px-1.5 py-0.5 text-xs ring-1 ring-ink/15">backend/remediation.py</code>
        and is attached to every matching finding in scan results.
      </p>
      <div className="mt-8 flex flex-col items-center justify-center rounded-2xl border-2 border-dashed border-ink/30 p-12 text-center">
        <Database className="h-10 w-10 text-muted" />
        <p className="mt-3 font-medium">Knowledge base lives inside the engine</p>
        <p className="mt-1 max-w-sm text-sm text-muted">
          Remediation guidance is delivered on each finding card — run a scan to
          see it. A browsable catalog will appear here in a future release.
        </p>
      </div>
    </div>
  );
}
