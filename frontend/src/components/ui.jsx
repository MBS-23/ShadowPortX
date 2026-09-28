import { forwardRef } from "react";
import { SEVERITY, STATE_LABEL, STATUS_LABEL, riskColor, titleCase } from "../lib/format";
import { useTilt } from "../lib/useTilt";

export const Card = forwardRef(function Card({ className = "", children, ...rest }, ref) {
  return (
    <div ref={ref} className={`card ${className}`} {...rest}>
      {children}
    </div>
  );
});

export function StatCard({ label, value, sub, accent }) {
  const tilt = useTilt(7);
  return (
    <Card ref={tilt} className="card-accent card-hover p-4">
      <div className="text-[11px] uppercase tracking-[0.14em] text-faint">{label}</div>
      <div className="h-display mt-2 text-[28px] leading-none font-bold tracking-tight"
        style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      {sub && <div className="mt-2 text-xs text-muted">{sub}</div>}
    </Card>
  );
}

export function SeverityBadge({ severity }) {
  const s = SEVERITY[severity] || SEVERITY.info;
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold"
      style={{ color: s.color, background: `${s.color}1a`, border: `1px solid ${s.color}40` }}
    >
      <span aria-hidden className="text-[10px] leading-none">{s.glyph}</span>
      {s.label}
    </span>
  );
}

export function Pill({ children, tone = "muted" }) {
  const tones = {
    muted: "text-muted bg-surface-2 border-border",
    ok: "text-ok bg-ok/10 border-ok/30",
    primary: "text-primary bg-primary/10 border-primary/30",
    warn: "text-medium bg-medium/10 border-medium/30",
  };
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs ${tones[tone]}`}>
      {children}
    </span>
  );
}

export function StateBadge({ state }) {
  const confirmed = state === "confirmed";
  return (
    <Pill tone={confirmed ? "ok" : "muted"}>
      {STATE_LABEL[state] || titleCase(state)}
    </Pill>
  );
}

export function StatusBadge({ status }) {
  const tone = status === "resolved" ? "ok" : status === "new" ? "warn" : "primary";
  return <Pill tone={tone}>{STATUS_LABEL[status] || titleCase(status)}</Pill>;
}

export function RiskScore({ score, size = "md" }) {
  const color = riskColor(score);
  const cls = size === "lg" ? "text-3xl" : "text-sm";
  return (
    <span className={`font-mono font-semibold ${cls}`} style={{ color }}>
      {Number(score).toFixed(size === "lg" ? 0 : 1)}
    </span>
  );
}

export function RiskBar({ score }) {
  const color = riskColor(score);
  return (
    <div className="h-1.5 w-full rounded-full bg-surface-3 overflow-hidden">
      <div className="h-full rounded-full" style={{ width: `${Math.min(100, score)}%`, background: color }} />
    </div>
  );
}

export function Spinner({ label = "Loading…" }) {
  return (
    <div className="flex items-center gap-3 text-muted text-sm py-10 justify-center">
      <span className="h-4 w-4 rounded-full border-2 border-border border-t-primary animate-spin" />
      {label}
    </div>
  );
}

export function Empty({ title = "Nothing here yet", hint }) {
  return (
    <div className="text-center py-14 text-muted">
      <div className="text-sm font-medium text-text">{title}</div>
      {hint && <div className="mt-1 text-xs text-faint">{hint}</div>}
    </div>
  );
}

export function ErrorNote({ error }) {
  const msg = error?.response?.data?.detail || error?.message || "Request failed";
  return (
    <div className="card p-4 border-critical/40 bg-critical/5 text-sm text-critical">
      {String(msg)}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4 mb-5">
      <div>
        <h1 className="h-display text-[26px] font-bold text-text">{title}</h1>
        {subtitle && <p className="text-sm text-muted mt-1 max-w-2xl">{subtitle}</p>}
      </div>
      {actions}
    </div>
  );
}
