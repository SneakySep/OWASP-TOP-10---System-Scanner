/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // "Milk Ink" theme — semantic tokens backed by CSS variables so the
        // .dark class on <html> can swap every value without touching JSX.
        bg: "rgb(var(--bg) / <alpha-value>)", // page background (milk white / near-black)
        surface: "rgb(var(--surface) / <alpha-value>)", // cards, sidebar, inputs
        ink: "rgb(var(--ink) / <alpha-value>)", // text, borders, solid fills
        muted: "rgb(var(--muted) / <alpha-value>)", // secondary text
        faint: "rgb(var(--faint) / <alpha-value>)", // hover fills, code chips, gutters
      },
      keyframes: {
        // Sliding bar for work with unknown duration (scan, fix, re-scan).
        indeterminate: {
          "0%": { transform: "translateX(-100%)" },
          "100%": { transform: "translateX(400%)" },
        },
      },
      animation: {
        indeterminate: "indeterminate 1.4s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
