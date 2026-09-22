import { useState } from "react";
import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, Pill, Spinner, ErrorNote, PageHeader, Empty } from "../components/ui";
import { titleCase } from "../lib/format";

export default function Integrations() {
  const { data, loading, error, reload } = useFetch(() => endpoints.channels(), []);
  const [form, setForm] = useState({ name: "", kind: "slack", url: "", min_severity: "high" });
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState(null);

  const add = async (e) => {
    e.preventDefault();
    setBusy(true); setNote(null);
    try {
      await endpoints.addChannel({ ...form, url: form.url.trim() });
      setForm({ ...form, name: "", url: "" });
      reload();
    } catch (err) {
      setNote({ ok: false, msg: err?.response?.data?.detail || "Failed to add channel" });
    } finally { setBusy(false); }
  };

  const test = async (id) => {
    const res = await endpoints.testChannel(id);
    setNote({ ok: res.delivered, msg: res.delivered ? "Test alert delivered." : "Delivery failed (check the URL)." });
  };

  return (
    <div>
      <PageHeader
        title="Integrations"
        subtitle="Outbound alerts on new high/critical findings. Slack, Teams, and Discord accept incoming-webhook URLs directly."
      />

      <Card className="p-4 mb-4">
        <form onSubmit={add} className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          <div className="md:col-span-3">
            <label className="text-xs text-faint">Name</label>
            <input className="input w-full mt-1" required placeholder="Security Slack"
              value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </div>
          <div className="md:col-span-2">
            <label className="text-xs text-faint">Type</label>
            <select className="input w-full mt-1" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
              <option value="slack">Slack/Teams/Discord</option>
              <option value="generic">Generic JSON</option>
            </select>
          </div>
          <div className="md:col-span-4">
            <label className="text-xs text-faint">Webhook URL</label>
            <input className="input w-full mt-1" required type="url" placeholder="https://hooks.slack.com/services/…"
              value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} />
          </div>
          <div className="md:col-span-2">
            <label className="text-xs text-faint">Min severity</label>
            <select className="input w-full mt-1" value={form.min_severity} onChange={(e) => setForm({ ...form, min_severity: e.target.value })}>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
            </select>
          </div>
          <div className="md:col-span-1"><button className="btn-primary w-full justify-center" disabled={busy}>Add</button></div>
        </form>
        {note && <div className={`mt-3 text-sm ${note.ok ? "text-ok" : "text-critical"}`}>{note.msg}</div>}
      </Card>

      <Card className="p-0 overflow-hidden">
        {loading && !data ? <Spinner /> : error ? <div className="p-4"><ErrorNote error={error} /></div> :
          data.length === 0 ? <Empty title="No channels configured" hint="Add a webhook to receive alerts." /> : (
            <table className="w-full">
              <thead><tr><th className="th">Name</th><th className="th">Type</th><th className="th">Min severity</th><th className="th">Status</th><th className="th"></th></tr></thead>
              <tbody>
                {data.map((c) => (
                  <tr key={c.id} className="hover:bg-surface-2/60">
                    <td className="td">{c.name}</td>
                    <td className="td text-xs text-muted">{c.kind === "slack" ? "Slack/Teams/Discord" : "Generic JSON"}</td>
                    <td className="td text-xs">{titleCase(c.min_severity)}</td>
                    <td className="td"><Pill tone={c.enabled ? "ok" : "muted"}>{c.enabled ? "Enabled" : "Disabled"}</Pill></td>
                    <td className="td text-right whitespace-nowrap">
                      <button className="text-xs text-primary hover:underline mr-3" onClick={() => test(c.id)}>Send test</button>
                      <button className="text-xs text-critical hover:underline" onClick={async () => { await endpoints.deleteChannel(c.id); reload(); }}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
      </Card>
      <p className="text-xs text-faint mt-3">
        Enterprise connectors (Jira, ServiceNow, Splunk, Microsoft Sentinel) extend the same
        notification interface — add them as additional channel types.
      </p>
    </div>
  );
}
