import { useState } from "react";
import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, Pill, Spinner, ErrorNote, PageHeader, Empty, RiskBar } from "../components/ui";
import { titleCase, fmtTime } from "../lib/format";

const STATUS_TONE = {
  completed: "ok", running: "primary", queued: "muted",
  failed: "warn", blocked: "warn", cancelled: "muted",
};

export default function Scans() {
  const { data: scans, loading, error, reload } = useFetch(() => endpoints.scans(), [], { pollMs: 2500 });
  const [form, setForm] = useState({ target: "", ports: "top1000", technique: "tcp_connect", subdomains: true });
  const [submitting, setSubmitting] = useState(false);
  const [note, setNote] = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    setSubmitting(true); setNote(null);
    try {
      const scan = await endpoints.createScan({
        target: form.target.trim(),
        ports: form.ports,
        technique: form.technique,
        subdomains: form.subdomains,
      });
      setNote({ ok: true, msg: `Scan #${scan.id} queued for ${scan.target}.` });
      setForm({ ...form, target: "" });
      reload();
    } catch (err) {
      setNote({ ok: false, msg: err?.response?.data?.detail || "Failed to start scan" });
    } finally { setSubmitting(false); }
  };

  return (
    <div>
      <PageHeader title="Scans" subtitle="Authorized assessments. Targets outside scope are refused before any packet is sent." />

      <Card className="p-4 mb-4">
        <form onSubmit={submit} className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          <div className="md:col-span-4">
            <label className="text-xs text-faint">Target (domain or IP)</label>
            <input className="input w-full mt-1" placeholder="127.0.0.1 or example.com" required
              value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })} />
          </div>
          <div className="md:col-span-3">
            <label className="text-xs text-faint">Ports</label>
            <select className="input w-full mt-1" value={form.ports} onChange={(e) => setForm({ ...form, ports: e.target.value })}>
              <option value="top100">Top 100</option>
              <option value="top1000">Top 1000</option>
              <option value="1-1024">1–1024</option>
              <option value="1-65535">All (1–65535)</option>
            </select>
          </div>
          <div className="md:col-span-2">
            <label className="text-xs text-faint">Technique</label>
            <select className="input w-full mt-1" value={form.technique} onChange={(e) => setForm({ ...form, technique: e.target.value })}>
              <option value="tcp_connect">TCP connect</option>
              <option value="tcp_syn">TCP SYN</option>
              <option value="udp">UDP</option>
            </select>
          </div>
          <div className="md:col-span-2 flex items-center gap-2 pb-2">
            <input id="subs" type="checkbox" checked={form.subdomains} onChange={(e) => setForm({ ...form, subdomains: e.target.checked })} />
            <label htmlFor="subs" className="text-xs text-muted">Subdomains</label>
          </div>
          <div className="md:col-span-1">
            <button className="btn-primary w-full justify-center" disabled={submitting}>{submitting ? "…" : "Scan"}</button>
          </div>
        </form>
        {note && <div className={`mt-3 text-sm ${note.ok ? "text-ok" : "text-critical"}`}>{note.msg}</div>}
      </Card>

      <Card className="p-0 overflow-hidden">
        {loading && !scans ? <Spinner /> : error ? <div className="p-4"><ErrorNote error={error} /></div> :
          scans.length === 0 ? <Empty title="No scans yet" hint="Launch one above." /> : (
            <div className="divide-y divide-border/70">
              {scans.map((s) => (
                <div key={s.id} className="px-4 py-3">
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="font-mono text-sm text-text">#{s.id}</span>
                    <span className="font-medium text-text">{s.target}</span>
                    <Pill tone={STATUS_TONE[s.status] || "muted"}>{titleCase(s.status)}</Pill>
                    <span className="text-xs text-faint">{titleCase(s.scan_type)}</span>
                    <span className="text-xs text-faint ml-auto">{fmtTime(s.started_at || s.created_at)}</span>
                  </div>
                  {(s.status === "running" || s.status === "queued") && (
                    <div className="mt-2 flex items-center gap-3">
                      <div className="flex-1"><RiskBar score={s.progress} /></div>
                      <span className="text-xs text-muted w-28 truncate">{s.stats?.phase || "queued"}</span>
                    </div>
                  )}
                  {s.status === "completed" && s.stats && (
                    <div className="mt-1 text-xs text-muted flex flex-wrap gap-x-4 gap-y-0.5">
                      <span>{s.stats.open_ports} open ports</span>
                      <span>{s.stats.services} services</span>
                      <span>{s.stats.findings} findings ({s.stats.new_findings} new)</span>
                      {s.stats.resolved_findings ? <span className="text-ok">{s.stats.resolved_findings} resolved</span> : null}
                      {s.stats.subdomains ? <span>{s.stats.subdomains} subdomains</span> : null}
                    </div>
                  )}
                  {s.status === "blocked" && <div className="mt-1 text-xs text-medium">Blocked: {s.error}</div>}
                  {s.status === "failed" && <div className="mt-1 text-xs text-critical">Failed: {s.error}</div>}
                  {s.stats?.notes?.length ? <div className="mt-1 text-[11px] text-faint">{s.stats.notes.join(" ")}</div> : null}
                </div>
              ))}
            </div>
          )}
      </Card>
    </div>
  );
}
