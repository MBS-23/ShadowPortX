import { Link } from "react-router-dom";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, StatCard, RiskScore, RiskBar, Spinner, ErrorNote, PageHeader, Empty } from "../components/ui";
import { SEVERITY, titleCase, riskColor } from "../lib/format";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

export default function Risk() {
  const { data, loading, error } = useFetch(() => endpoints.risk(), []);
  if (loading && !data) return <Spinner />;
  if (error) return <ErrorNote error={error} />;
  const r = data;
  const maxCat = Math.max(1, ...Object.values(r.by_category || {}));

  return (
    <div>
      <PageHeader title="Risk" subtitle="Contextual exposure prioritization — the ShadowPortX Exposure Score across the org." />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-3">
        <StatCard label="Org Risk (SPX-ES)" value={<RiskScore score={r.org_risk} size="lg" />} />
        <StatCard label="Critical" value={r.severity.critical} accent={SEVERITY.critical.color} />
        <StatCard label="High" value={r.severity.high} accent={SEVERITY.high.color} />
        <StatCard label="Medium" value={r.severity.medium} accent={SEVERITY.medium.color} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 mb-3">
        <Card className="p-5">
          <div className="text-sm font-medium mb-3">Open findings by category</div>
          {Object.keys(r.by_category || {}).length === 0 ? <Empty title="No open findings" /> : (
            <div className="space-y-2">
              {Object.entries(r.by_category).sort((a, b) => b[1] - a[1]).map(([cat, n]) => (
                <div key={cat} className="flex items-center gap-3">
                  <span className="text-sm text-muted w-52 truncate">{titleCase(cat)}</span>
                  <div className="flex-1"><RiskBar score={(n / maxCat) * 100} /></div>
                  <span className="font-mono text-sm w-8 text-right">{n}</span>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card className="p-5">
          <div className="text-sm font-medium mb-3">Risk trend (per scan)</div>
          {(!r.trend || r.trend.length < 2) ? (
            <Empty title="Not enough history yet" hint="Run more scans to build a trend." />
          ) : (
            <div className="h-52">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={r.trend} margin={{ top: 8, right: 8, bottom: 4, left: -20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#243250" />
                  <XAxis dataKey="date" tick={{ fill: "#64748b", fontSize: 10 }} hide />
                  <YAxis tick={{ fill: "#64748b", fontSize: 10 }} />
                  <Tooltip contentStyle={{ background: "#111a2e", border: "1px solid #243250", borderRadius: 8, fontSize: 12 }} />
                  <Line type="monotone" dataKey="avg_risk" stroke="#22d3ee" strokeWidth={2} dot={false} name="Avg risk" />
                  <Line type="monotone" dataKey="findings" stroke="#fb923c" strokeWidth={2} dot={false} name="Findings" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>
      </div>

      <Card className="p-0 overflow-hidden">
        <div className="px-4 py-3 border-b border-border text-sm font-medium">Top assets by risk</div>
        {(!r.top_assets || r.top_assets.length === 0) ? <Empty title="No scored assets yet" /> : (
          <table className="w-full">
            <thead><tr><th className="th w-16">Risk</th><th className="th">Asset</th><th className="th">Exposure</th><th className="th">Criticality</th></tr></thead>
            <tbody>
              {r.top_assets.map((a) => (
                <tr key={a.id} className="hover:bg-surface-2/60">
                  <td className="td"><RiskScore score={a.risk_score} /></td>
                  <td className="td"><Link to={`/assets/${a.id}`} className="text-text hover:text-primary font-mono">{a.value}</Link></td>
                  <td className="td text-xs text-muted">{titleCase(a.exposure)}</td>
                  <td className="td text-xs text-muted">{titleCase(a.criticality)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
