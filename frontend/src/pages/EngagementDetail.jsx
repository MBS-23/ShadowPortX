import { useParams, Link } from "react-router-dom";
import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, StatCard, SeverityBadge, StatusBadge, RiskScore, Pill, Spinner, ErrorNote, Empty } from "../components/ui";
import { titleCase, fmtTime } from "../lib/format";

export default function EngagementDetail() {
  const { id } = useParams();
  const { data: e, loading, error } = useFetch(() => endpoints.engagement(id), [id]);
  if (loading && !e) return <Spinner />;
  if (error) return <ErrorNote error={error} />;

  const sev = e.stats?.severity || {};
  return (
    <div>
      <Link to="/engagements" className="text-xs text-primary hover:underline">← Back to engagements</Link>
      <div className="flex flex-wrap items-start justify-between gap-4 mt-2 mb-5">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-xl font-semibold">{e.name}</h1>
            <Pill tone={e.status === "active" ? "ok" : "muted"}>{titleCase(e.status)}</Pill>
            <Pill tone="primary">{titleCase(e.kind)}</Pill>
          </div>
          <div className="text-sm text-muted mt-1">
            {e.client && <>Client: {e.client} · </>}{e.tester && <>Tester: {e.tester} · </>}
            {e.scope_note && <>Scope: <span className="font-mono">{e.scope_note}</span> · </>}
            started {fmtTime(e.starts_at)}
          </div>
        </div>
        <a href={`/api/v1/engagements/${e.id}/report`} target="_blank" rel="noreferrer" className="btn-primary">
          Download evidence package
        </a>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
        <StatCard label="Scans" value={e.stats?.scans ?? 0} />
        <StatCard label="Assets" value={e.stats?.assets ?? 0} />
        <StatCard label="Findings" value={e.stats?.findings ?? 0} />
        <StatCard label="Critical / High" value={`${sev.critical || 0} / ${sev.high || 0}`} accent="#f87171" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <Card className="p-0 overflow-hidden">
          <div className="px-4 py-3 border-b border-border text-sm font-medium">Scans ({e.scans?.length || 0})</div>
          {!e.scans || e.scans.length === 0 ? <Empty title="No scans linked" hint="Run a scan and select this engagement." /> : (
            <div className="divide-y divide-border/70">
              {e.scans.map((s) => (
                <div key={s.id} className="px-4 py-2.5 flex items-center gap-3 text-sm">
                  <span className="font-mono text-faint">#{s.id}</span>
                  <span className="font-medium">{s.target}</span>
                  <StatusBadge status={s.status === "completed" ? "resolved" : "new"} />
                  <span className="text-xs text-faint ml-auto">{fmtTime(s.started_at || s.created_at)}</span>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card className="p-0 overflow-hidden">
          <div className="px-4 py-3 border-b border-border text-sm font-medium">Findings ({e.findings?.length || 0})</div>
          {!e.findings || e.findings.length === 0 ? <Empty title="No findings yet" /> : (
            <table className="w-full">
              <thead><tr><th className="th w-16">Risk</th><th className="th">Severity</th><th className="th">Finding</th></tr></thead>
              <tbody>
                {e.findings.map((f) => (
                  <tr key={f.id} className="hover:bg-surface-2/60">
                    <td className="td"><RiskScore score={f.risk_score} /></td>
                    <td className="td"><SeverityBadge severity={f.severity} /></td>
                    <td className="td"><Link to={`/findings/${f.id}`} className="text-text hover:text-primary">{f.title}</Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </div>
  );
}
