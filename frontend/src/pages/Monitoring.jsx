import { useState } from "react";
import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, Pill, Spinner, ErrorNote, PageHeader, Empty } from "../components/ui";
import { fmtTime } from "../lib/format";

export default function Monitoring() {
  const { data, loading, error, reload } = useFetch(() => endpoints.schedules(), [], { pollMs: 10000 });
  const [form, setForm] = useState({ target: "", interval_minutes: 1440, ports: "top1000", subdomains: true });
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState(null);

  const create = async (e) => {
    e.preventDefault();
    setBusy(true); setNote(null);
    try {
      await endpoints.createSchedule({
        target: form.target.trim(),
        interval_minutes: Number(form.interval_minutes),
        ports: form.ports, subdomains: form.subdomains,
      });
      setForm({ ...form, target: "" });
      setNote({ ok: true, msg: "Schedule created — continuous monitoring active." });
      reload();
    } catch (err) {
      setNote({ ok: false, msg: err?.response?.data?.detail || "Failed to create schedule" });
    } finally { setBusy(false); }
  };

  return (
    <div>
      <PageHeader title="Continuous Monitoring" subtitle="Recurring authorized scans that detect attack-surface changes automatically." />

      <Card className="p-4 mb-4">
        <form onSubmit={create} className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          <div className="md:col-span-4">
            <label className="text-xs text-faint">Target</label>
            <input className="input w-full mt-1" required placeholder="127.0.0.1 or example.com"
              value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })} />
          </div>
          <div className="md:col-span-3">
            <label className="text-xs text-faint">Interval</label>
            <select className="input w-full mt-1" value={form.interval_minutes}
              onChange={(e) => setForm({ ...form, interval_minutes: e.target.value })}>
              <option value={60}>Hourly</option>
              <option value={360}>Every 6 hours</option>
              <option value={1440}>Daily</option>
              <option value={10080}>Weekly</option>
            </select>
          </div>
          <div className="md:col-span-3">
            <label className="text-xs text-faint">Ports</label>
            <select className="input w-full mt-1" value={form.ports} onChange={(e) => setForm({ ...form, ports: e.target.value })}>
              <option value="top100">Top 100</option>
              <option value="top1000">Top 1000</option>
              <option value="1-1024">1–1024</option>
            </select>
          </div>
          <div className="md:col-span-2">
            <button className="btn-primary w-full justify-center" disabled={busy}>Schedule</button>
          </div>
        </form>
        {note && <div className={`mt-3 text-sm ${note.ok ? "text-ok" : "text-critical"}`}>{note.msg}</div>}
      </Card>

      <Card className="p-0 overflow-hidden">
        {loading && !data ? <Spinner /> : error ? <div className="p-4"><ErrorNote error={error} /></div> :
          data.length === 0 ? <Empty title="No schedules yet" hint="Create one above to monitor a target continuously." /> : (
            <table className="w-full">
              <thead><tr><th className="th">Target</th><th className="th">Interval</th><th className="th">Next run</th><th className="th">Last run</th><th className="th">State</th><th className="th"></th></tr></thead>
              <tbody>
                {data.map((s) => (
                  <tr key={s.id} className="hover:bg-surface-2/60">
                    <td className="td font-mono">{s.target}</td>
                    <td className="td text-sm text-muted">every {s.interval_minutes} min</td>
                    <td className="td text-xs text-faint">{fmtTime(s.next_run_at)}</td>
                    <td className="td text-xs text-faint">{s.last_run_at ? fmtTime(s.last_run_at) : "—"}</td>
                    <td className="td"><Pill tone={s.enabled ? "ok" : "muted"}>{s.enabled ? "Enabled" : "Paused"}</Pill></td>
                    <td className="td text-right whitespace-nowrap">
                      <button className="text-xs text-primary hover:underline mr-3" onClick={async () => { await endpoints.toggleSchedule(s.id); reload(); }}>
                        {s.enabled ? "Pause" : "Resume"}
                      </button>
                      <button className="text-xs text-critical hover:underline" onClick={async () => { await endpoints.deleteSchedule(s.id); reload(); }}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
      </Card>
    </div>
  );
}
