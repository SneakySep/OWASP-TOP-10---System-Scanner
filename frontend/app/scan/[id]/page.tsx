import type { Metadata } from "next";
import ScanView from "@/components/ScanView";

export const metadata: Metadata = {
  title: "Scan report — SAST Scanner",
};

export default function ScanReportPage({
  params,
}: {
  params: { id: string };
}) {
  return <ScanView scanId={params.id} />;
}
