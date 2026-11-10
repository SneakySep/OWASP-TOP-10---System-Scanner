"use client";

import ScanResults from "@/components/ScanResults";
import ScanAlerts from "@/components/ScanAlerts";
import UploadDropzone from "@/components/UploadDropzone";
import { useScanFlow } from "@/lib/useScanFlow";

export default function Home() {
  const flow = useScanFlow();

  return (
    <div className="mx-auto max-w-5xl space-y-8">
      <header>
        <h2 className="text-2xl font-bold">New Scan</h2>
        <p className="mt-1 text-sm text-muted">
          Drop files, a whole folder, or a .zip of your source code. It is
          scanned with Semgrep against the OWASP Top 10 ruleset and enriched
          with remediation guidance.
        </p>
      </header>

      <UploadDropzone flow={flow} />

      {/* One live region for the whole flow; the ticking timer stays out of it. */}
      <p className="sr-only" role="status">
        {flow.announcement || flow.status || ""}
      </p>

      <ScanAlerts flow={flow} />

      {flow.result && (
        <ScanResults
          key={flow.result.scan_id}
          payload={flow.result}
          onDownloadFixed={() => void flow.downloadFixed()}
          onDownloadPatch={() => void flow.downloadPatch()}
          fixBusy={flow.fixBusy}
          patchBusy={flow.patchBusy}
        />
      )}
    </div>
  );
}
