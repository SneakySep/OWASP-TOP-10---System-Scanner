import type { Metadata } from "next";
import "./globals.css";
import AppShell from "@/components/AppShell";
import { ScanSessionProvider } from "@/lib/scanSession";

export const metadata: Metadata = {
  title: "SAST Scanner",
  description: "Static Application Security Testing with Semgrep and OWASP Top 10 remediation",
};

// Runs before first paint so the saved (or OS) theme is applied without a
// flash of the wrong colors. Kept tiny and inline on purpose.
const themeInitScript = `(function(){try{var t=localStorage.getItem("theme");var d=t?t==="dark":window.matchMedia("(prefers-color-scheme: dark)").matches;if(d)document.documentElement.classList.add("dark");}catch(e){}})();`;

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body className="min-h-screen bg-bg text-ink antialiased">
        <AppShell>
          <ScanSessionProvider>{children}</ScanSessionProvider>
        </AppShell>
      </body>
    </html>
  );
}
