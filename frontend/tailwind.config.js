/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        // SOC/ASM dark console palette (raised near-black avoids halation).
        bg: "#0a0f1c",
        surface: "#111a2e",
        "surface-2": "#16213a",
        "surface-3": "#1c2842",
        border: "#243250",
        "border-strong": "#33456b",
        primary: "#22d3ee",
        "primary-dim": "#0e7490",
        text: "#e5e7eb",
        muted: "#94a3b8",
        faint: "#64748b",
        // Severity — always paired with a text label/shape, never color alone.
        critical: "#f87171",
        high: "#fb923c",
        medium: "#fbbf24",
        low: "#60a5fa",
        info: "#94a3b8",
        ok: "#34d399",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(0,0,0,0.3), 0 1px 3px rgba(0,0,0,0.2)",
      },
    },
  },
  plugins: [],
};
