// Severity metadata — color plus a non-color signal (label + shape), per SOC a11y rules.
export const SEVERITY = {
  critical: { label: "Critical", color: "#f87171", rank: 4, glyph: "▲▲" },
  high: { label: "High", color: "#fb923c", rank: 3, glyph: "▲" },
  medium: { label: "Medium", color: "#fbbf24", rank: 2, glyph: "●" },
  low: { label: "Low", color: "#60a5fa", rank: 1, glyph: "▬" },
  info: { label: "Info", color: "#94a3b8", rank: 0, glyph: "·" },
};

export const STATE_LABEL = {
  detected: "Detected",
  potentially_affected: "Potentially affected",
  needs_verification: "Needs verification",
  confirmed: "Confirmed",
};

export const STATUS_LABEL = {
  new: "New",
  triaged: "Triaged",
  in_progress: "In progress",
  remediation_ready: "Remediation ready",
  verifying: "Verifying",
  resolved: "Resolved",
  accepted_risk: "Accepted risk",
  false_positive: "False positive",
};

export function riskColor(score) {
  if (score >= 90) return "#f87171";
  if (score >= 70) return "#fb923c";
  if (score >= 40) return "#fbbf24";
  if (score > 0) return "#60a5fa";
  return "#64748b";
}

// Absolute timestamp with explicit timezone (analyst consoles never rely on "2h ago" alone).
export function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit",
  });
}

export function fmtRelative(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  const secs = (Date.now() - d.getTime()) / 1000;
  if (secs < 60) return "just now";
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

export const titleCase = (s) =>
  (s || "").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
