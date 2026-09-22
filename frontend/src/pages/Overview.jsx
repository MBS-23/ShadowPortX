import { Link } from "react-router-dom";
import { PieChart, Pie, Cell, ResponsiveContainer, RadialBarChart, RadialBar, PolarAngleAxis } from "recharts";
import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, StatCard, SeverityBadge, RiskScore, RiskBar, Spinner, ErrorNote, PageHeader, Empty } from "../components/ui";
import { SEVERITY, riskColor, fmtRelative, titleCase } from "../lib/format";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

export default function Overview() {
  const { data, loading, error } = useFetch(() => endpoints.overview(), [], { pollMs: 8000 });

  if (loading && !data) return <Spinner label="Loading security center…" />;
  if (error) return <ErrorNote error={error} />;
  const o = data;

  const sevData = SEV_ORDER.map((k) => ({ name: SEVERITY[k].label, key: k, value: o.severity[k] || 0, color: SEVERITY[k].color }))
    .filter((d) => d.value > 0);
  const gauge = [{ name: "risk", value: o.org_risk, fill: riskColor(o.org_risk) }];

  return (
    <div>
      <PageHeader
        title="Security Center"
        subtitle="Continuously discovered exposure, correlated to risk and prioritized for remediation."
      />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-3">
        <StatCard label="Assets" value={o.assets} sub={`${o.internet_facing} internet-facing · ${o.unknown_assets} unknown`} />
        <StatCard label="Services" value={o.services} sub={`${o.technologies} technologies`} />
        <StatCard label="Open findings" value={o.open_findings} sub={`${o.resolved_findings} resolved`} accent={o.open_findings ? "#fb923c" : "#34d399"} />
        <StatCard label="Changes (7d)" value={o.recent_changes} sub={`${o.scans} scans run`} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 mb-3">
        {/* Org risk gauge */}
        <Card className="p-5 flex flex-col items-center justify-center">
          <div className="text-xs uppercase tracking-wide text-faint mb-2">Organization Risk (SPX-ES)</div>
          <div className="relative h-44 w-44">
            <ResponsiveContainer width="100%" height="100%">
              <RadialBarChart innerRadius="72%" outerRadius="100%" data={gauge} startAngle={90} endAngle={-270}>
                <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
                <RadialBar background={{ fill: "#1c2842" }} dataKey="value" cornerRadius={8} />
              </RadialBarChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 grid place-items-center">
              <div className="text-center">
                <RiskScore score={o.org_risk} size="lg" />
                <div className="text-[10px] text-faint mt-1">avg exposure score</div>
              </div>
            </div>
          </div>
        </Card>

        {/* Severity distribution */}
        <Card className="p-5 lg:col-span-2">
          <div className="flex items-center justify-between mb-3">
            <div className="text-sm font-medium text-text">Findings by severity</div>
            <Link to="/findings" className="text-xs text-primary hover:underline">View all →</Link>
          </div>
          {sevData.length === 0 ? (
            <Empty title="No open findings" hint="Run a scan to populate findings." />
          ) : (
            <div className="flex items-center gap-6">
              <div className="h-40 w-40 shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={45} outerRadius={70} paddingAngle={2} stroke="none">
                      {sevData.map((d) => <Cell key={d.key} fill={d.color} />)}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="flex-1 space-y-2">
                {SEV_ORDER.map((k) => (
                  <div key={k} className="flex items-center gap-3">
                    <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ background: SEVERITY[k].color }} />
                    <span className="text-sm text-muted w-20">{SEVERITY[k].label}</span>
                    <div className="flex-1"><RiskBar score={o.severity[k] ? Math.min(100, (o.severity[k] / Math.max(1, o.open_findings)) * 100) : 0} /></div>
                    <span className="font-mono text-sm text-text w-8 text-right">{o.severity[k] || 0}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        {/* Top findings */}
        <Card className="p-0 lg:col-span-2 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <div className="text-sm font-medium text-text">Top exposures by risk</div>
            <Link to="/findings" className="text-xs text-primary hover:underline">All findings →</Link>
          </div>
          {o.top_findings.length === 0 ? (
            <Empty title="No findings yet" hint="Launch a scan from the Scans page." />
          ) : (
            <table className="w-full">
              <thead><tr>
                <th className="th">Risk</th><th className="th">Severity</th><th className="th">Finding</th><th className="th hidden md:table-cell">Method</th>
              </tr></thead>
              <tbody>
                {o.top_findings.map((f) => (
                  <tr key={f.id} className="hover:bg-surface-2/60">
                    <td className="td w-16"><RiskScore score={f.risk_score} /></td>
                    <td className="td"><SeverityBadge severity={f.severity} /></td>
                    <td className="td">
                      <Link to={`/findings/${f.id}`} className="text-text hover:text-primary">{f.title}</Link>
                      <div className="text-[11px] text-faint font-mono">{f.spx_id}</div>
                    </td>
                    <td className="td hidden md:table-cell text-muted text-xs">{titleCase(f.detection_method)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        {/* Recent changes */}
        <Card className="p-0 overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <div className="text-sm font-medium text-text">Attack surface changes</div>
            <Link to="/changes" className="text-xs text-primary hover:underline">All →</Link>
          </div>
          <div className="divide-y divide-border/70 max-h-[360px] overflow-y-auto">
            {o.recent_changes_list.length === 0 ? (
              <Empty title="No changes recorded" />
            ) : o.recent_changes_list.map((c) => (
              <div key={c.id} className="px-4 py-3">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] uppercase font-semibold tracking-wide text-primary">{titleCase(c.change_type)}</span>
                  <span className="text-[10px] text-faint ml-auto">{fmtRelative(c.detected_at)}</span>
                </div>
                <div className="text-sm text-muted mt-0.5">{c.summary}</div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
