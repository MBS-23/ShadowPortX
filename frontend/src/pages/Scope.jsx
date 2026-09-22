import { useState } from "react";
import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, Pill, Spinner, ErrorNote, PageHeader, Empty } from "../components/ui";

export default function Scope() {
  const { data, loading, error, reload } = useFetch(() => endpoints.scope(), []);
  const [form, setForm] = useState({ kind: "allow", target_type: "domain", value: "", note: "" });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);

  const add = async (e) => {
    e.preventDefault();
    setBusy(true); setMsg(null);
    try { await endpoints.addScope({ ...form, value: form.value.trim() }); setForm({ ...form, value: "", note: "" }); reload(); }
    catch (err) { setMsg(err?.response?.data?.detail || "Failed"); }
    finally { setBusy(false); }
  };
  const remove = async (id) => { await endpoints.deleteScope(id); reload(); };

  return (
    <div>
      <PageHeader title="Authorization Scope" subtitle="The guardrail. Deny always wins; a target with no matching allow rule is refused." />

      <Card className="p-4 mb-4">
        <form onSubmit={add} className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          <div className="md:col-span-2">
            <label className="text-xs text-faint">Rule</label>
            <select className="input w-full mt-1" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
              <option value="allow">Allow</option><option value="deny">Deny</option>
            </select>
          </div>
          <div className="md:col-span-2">
            <label className="text-xs text-faint">Type</label>
            <select className="input w-full mt-1" value={form.target_type} onChange={(e) => setForm({ ...form, target_type: e.target.value })}>
              <option value="domain">Domain</option><option value="wildcard">Wildcard</option>
              <option value="ip">IP</option><option value="cidr">CIDR</option>
            </select>
          </div>
          <div className="md:col-span-4">
            <label className="text-xs text-faint">Value</label>
            <input className="input w-full mt-1" required placeholder="example.com / *.example.com / 10.0.0.0/24"
              value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} />
          </div>
          <div className="md:col-span-3">
            <label className="text-xs text-faint">Note</label>
            <input className="input w-full mt-1" value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} />
          </div>
          <div className="md:col-span-1"><button className="btn-primary w-full justify-center" disabled={busy}>Add</button></div>
        </form>
        {msg && <div className="mt-2 text-sm text-critical">{msg}</div>}
      </Card>

      <Card className="p-0 overflow-hidden">
        {loading && !data ? <Spinner /> : error ? <div className="p-4"><ErrorNote error={error} /></div> :
          data.length === 0 ? <Empty title="No scope rules" hint="Add an allow rule to authorize scanning." /> : (
            <table className="w-full">
              <thead><tr><th className="th">Rule</th><th className="th">Type</th><th className="th">Value</th><th className="th">Note</th><th className="th"></th></tr></thead>
              <tbody>
                {data.map((r) => (
                  <tr key={r.id} className="hover:bg-surface-2/60">
                    <td className="td"><Pill tone={r.kind === "allow" ? "ok" : "warn"}>{r.kind}</Pill></td>
                    <td className="td text-xs text-muted">{r.target_type}</td>
                    <td className="td font-mono text-sm">{r.value}</td>
                    <td className="td text-xs text-faint">{r.note || "—"}</td>
                    <td className="td text-right">
                      <button className="text-xs text-critical hover:underline" onClick={() => remove(r.id)}>Remove</button>
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
