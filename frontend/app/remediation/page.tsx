import type { Metadata } from "next";
import { Database } from "lucide-react";
import RemediationCatalog from "@/components/RemediationCatalog";

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
        Fix checklists for every OWASP Top 10 category, served from the scanner&apos;s
        own knowledge base. The same guidance is attached to each matching
        finding in a scan report.
      </p>
      <RemediationCatalog />
    </div>
  );
}
