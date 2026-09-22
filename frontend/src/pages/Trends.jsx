import { LineChart, Line, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, CartesianGrid } from "recharts";
import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, StatCard, RiskScore, Spinner, ErrorNote, PageHeader, Empty } from "../components/ui";
import { riskColor } from "../lib/format";

function Delta({ value, invert }) {
  if (!value) return <span className="text-faint text-xs">no change</span>;
  const good = invert ? value < 0 : value > 0;
  return <span className={`text-xs font-medium ${good ? "text-ok" : "text-critical"}`}>{value > 0 ? "+" : ""}{value}</span>;
}

export default function Trends() {
  const { data, loading, error } = useFetch(() => endpoints.trends(), []);
  if (loading && !data) return <Spinner label="Building security trends…" />;
  if (error) return <ErrorNote error={error} />;

  const ex = data.executive || {};
  const contrib = data.contributors || {};
  const chart = (data.series || []).map((p, i) => ({
    t: `#${i + 1}`,
    risk: p.org_risk,
    findings: p.metrics?.open_findings ?? 0,
    assets: p.metrics?.assets ?? 0,
    internet: p.metrics?.internet_facing ?? 0,
  }));

  const reducers = [
    ["Findings resolved", contrib.findings_resolved],
    ["Services removed", contrib.services_removed],
  ].filter(([, v]) => v);
  const increasers = [
    ["New findings", contrib.new_findings],
    ["New assets", contrib.new_assets],
    ["New services", contrib.new_services],
    ["Technology changes", contrib.technology_changes],
    ["Certificate changes", contrib.certificate_changes],
  ].filter(([, v]) => v);

  return (
    <div>
      <PageHeader title="Security Trends" subtitle="Executive posture over time, and what moved the risk." />

      {/* Executive posture */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-3">
        <Card className="p-4">
          <div className="text-xs uppercase tracking-wide text-faint">Current Exposure</div>
          <div className="mt-1 flex items-baseline gap-2">
            <RiskScore score={ex.current_exposure ?? 0} size="lg" />
            <Delta value={ex.change} invert />
          </div>
          <div className="text-xs text-muted mt-0.5">was {ex.previous_exposure ?? "—"}</div>
        </Card>
        <StatCard label="Critical findings" value={ex.critical_findings ?? 0} accent="#f87171" />
        <StatCard label="Resolved this period" value={ex.resolved_this_period ?? 0} accent="#34d399" />
        <StatCard label="New exposures" value={ex.new_exposures ?? 0} sub={`${ex.internet_facing ?? 0} internet-facing`} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <Card className="p-5 lg:col-span-2">
          <div className="text-sm font-medium mb-3">Exposure &amp; findings trend</div>
          {chart.length < 2 ? (
            <Empty title="Trend builds after the next scan" hint="Each completed scan records a posture snapshot." />
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chart} margin={{ top: 8, right: 12, bottom: 4, left: -18 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#243250" />
                  <XAxis dataKey="t" tick={{ fill: "#64748b", fontSize: 11 }} />
                  <YAxis tick={{ fill: "#64748b", fontSize: 11 }} />
                  <Tooltip contentStyle={{ background: "#111a2e", border: "1px solid #243250", borderRadius: 8, fontSize: 12 }} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Line type="monotone" dataKey="risk" name="Org risk" stroke="#22d3ee" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="findings" name="Open findings" stroke="#fb923c" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="assets" name="Assets" stroke="#818cf8" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="internet" name="Internet-facing" stroke="#34d399" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>

        <Card className="p-5">
          <div className="text-sm font-medium mb-3">Why risk changed</div>
          {reducers.length === 0 && increasers.length === 0 ? (
            <Empty title="No movement yet" hint="Contributors appear once a second scan runs." />
          ) : (
            <div className="space-y-4">
              {reducers.length > 0 && (
                <div>
                  <div className="text-xs text-ok font-medium mb-1">Reduced risk</div>
                  {reducers.map(([l, v]) => (
                    <div key={l} className="flex justify-between text-sm"><span className="text-muted">{l}</span><span className="text-ok font-mono">-{v}</span></div>
                  ))}
                </div>
              )}
              {increasers.length > 0 && (
                <div>
                  <div className="text-xs text-critical font-medium mb-1">Increased risk</div>
                  {increasers.map(([l, v]) => (
                    <div key={l} className="flex justify-between text-sm"><span className="text-muted">{l}</span><span className="text-critical font-mono">+{v}</span></div>
                  ))}
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
