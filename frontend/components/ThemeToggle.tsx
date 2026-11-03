"use client";

import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";

// Persists the choice in localStorage["theme"] and toggles the .dark class
// on <html>, which the CSS variables in globals.css respond to. The inline
// script in layout.tsx applies the saved theme before first paint.
export default function ThemeToggle() {
  const [mounted, setMounted] = useState(false);
  const [dark, setDark] = useState(false);

  useEffect(() => {
    setDark(document.documentElement.classList.contains("dark"));
    setMounted(true);
  }, []);

  const toggle = () => {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    try {
      localStorage.setItem("theme", next ? "dark" : "light");
    } catch {
      // Private mode etc. — theme still applies for this session.
    }
  };

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={dark ? "Switch to light mode" : "Switch to dark mode"}
      aria-pressed={mounted && dark}
      title={dark ? "Switch to light mode" : "Switch to dark mode"}
      className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-ink/25 bg-surface text-ink transition-colors hover:bg-faint"
    >
      {/* Render a fixed icon until mounted to avoid a hydration mismatch. */}
      {mounted && dark ? (
        <Sun className="h-4 w-4" />
      ) : (
        <Moon className="h-4 w-4" />
      )}
    </button>
  );
}