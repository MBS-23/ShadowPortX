import { useState } from "react";
import { Link } from "react-router-dom";
import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, Pill, Spinner, ErrorNote, PageHeader, Empty } from "../components/ui";
import { titleCase, fmtTime } from "../lib/format";

const STATUS_TONE = { active: "ok", planned: "primary", completed: "muted" };

export default function Engagements() {
  const { data, loading, error, reload } = useFetch(() => endpoints.engagements(), []);
  const [form, setForm] = useState({ name: "", client: "", kind: "pentest", tester: "", scope_note: "" });
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState(null);

  const create = async (e) => {
    e.preventDefault();
    setBusy(true); setNote(null);
    try {
      await endpoints.createEngagement({ ...form });
      setForm({ ...form, name: "", client: "", tester: "", scope_note: "" });
      reload();
    } catch (err) {
      setNote(err?.response?.data?.detail || "Failed to create engagement");
    } finally { setBusy(false); }
  };

  return (
    <div>
      <PageHeader title="Engagements" subtitle="Authorized pentest / bug-bounty workspaces — scope, scans, findings, and evidence in one place." />

      <Card className="p-4 mb-4">
        <form onSubmit={create} className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          <div className="md:col-span-3">
            <label className="text-xs text-faint">Name</label>
            <input className="input w-full mt-1" required placeholder="Acme External Pentest"
              value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </div>
          <div className="md:col-span-2">
            <label className="text-xs text-faint">Client</label>
            <input className="input w-full mt-1" placeholder="Acme Corp"
              value={form.client} onChange={(e) => setForm({ ...form, client: e.target.value })} />
          </div>
          <div className="md:col-span-2">
            <label className="text-xs text-faint">Type</label>
            <select className="input w-full mt-1" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
              <option value="pentest">Pentest</option>
              <option value="bug_bounty">Bug bounty</option>
              <option value="internal">Internal</option>
            </select>
          </div>
          <div className="md:col-span-2">
            <label className="text-xs text-faint">Tester</label>
            <input className="input w-full mt-1" placeholder="You"
              value={form.tester} onChange={(e) => setForm({ ...form, tester: e.target.value })} />
          </div>
          <div className="md:col-span-2">
            <label className="text-xs text-faint">Scope note</label>
            <input className="input w-full mt-1" placeholder="*.acme.com"
              value={form.scope_note} onChange={(e) => setForm({ ...form, scope_note: e.target.value })} />
          </div>
          <div className="md:col-span-1"><button className="btn-primary w-full justify-center" disabled={busy}>Create</button></div>
        </form>
        {note && <div className="mt-2 text-sm text-critical">{note}</div>}
      </Card>

      <Card className="p-0 overflow-hidden">
        {loading && !data ? <Spinner /> : error ? <div className="p-4"><ErrorNote error={error} /></div> :
          data.length === 0 ? <Empty title="No engagements yet" hint="Create one to start an authorized assessment." /> : (
            <table className="w-full">
              <thead><tr><th className="th">Name</th><th className="th">Client</th><th className="th">Type</th><th className="th">Tester</th><th className="th">Status</th><th className="th">Started</th></tr></thead>
              <tbody>
                {data.map((e) => (
                  <tr key={e.id} className="hover:bg-surface-2/60">
                    <td className="td"><Link to={`/engagements/${e.id}`} className="text-text hover:text-primary font-medium">{e.name}</Link></td>
                    <td className="td text-muted">{e.client || "—"}</td>
                    <td className="td text-xs text-muted">{titleCase(e.kind)}</td>
                    <td className="td text-xs text-muted">{e.tester || "—"}</td>
                    <td className="td"><Pill tone={STATUS_TONE[e.status] || "muted"}>{titleCase(e.status)}</Pill></td>
                    <td className="td text-xs text-faint">{fmtTime(e.starts_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
      </Card>
    </div>
  );
}
