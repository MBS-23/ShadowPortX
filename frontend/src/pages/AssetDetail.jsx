import { useParams, Link } from "react-router-dom";
import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, RiskScore, SeverityBadge, Pill, Spinner, ErrorNote, Empty } from "../components/ui";
import { titleCase, fmtTime, fmtRelative } from "../lib/format";

export default function AssetDetail() {
  const { id } = useParams();
  const { data: a, loading, error } = useFetch(() => endpoints.asset(id), [id]);
  const { data: findings } = useFetch(() => endpoints.findings({ asset_id: id }), [id]);
  const { data: changes } = useFetch(() => endpoints.changes({ asset_id: id }), [id]);

  if (loading && !a) return <Spinner />;
  if (error) return <ErrorNote error={error} />;

  const meta = a.meta || {};
  return (
    <div>
      <div className="flex items-center justify-between">
        <Link to="/assets" className="text-xs text-primary hover:underline">← Back to assets</Link>
        <Link to={`/graph?asset=${a.id}`} className="text-xs text-primary hover:underline">View attack-surface map →</Link>
      </div>
      <div className="flex flex-wrap items-start justify-between gap-4 mt-2 mb-5">
        <div>
          <h1 className="text-xl font-semibold font-mono">{a.value}</h1>
          <div className="flex items-center gap-2 mt-2 flex-wrap">
            <Pill tone="primary">{titleCase(a.type)}</Pill>
            <Pill tone={a.exposure === "internet_facing" ? "warn" : "muted"}>{titleCase(a.exposure)}</Pill>
            <Pill>{titleCase(a.criticality)} criticality</Pill>
            <Pill>{titleCase(a.environment)}</Pill>
            {a.ip_address && <span className="text-xs font-mono text-faint">{a.ip_address}</span>}
          </div>
        </div>
        <Card className="p-4 text-center min-w-[120px]">
          <div className="text-[10px] uppercase tracking-wide text-faint">Asset Risk</div>
          <RiskScore score={a.risk_score} size="lg" />
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <div className="lg:col-span-2 space-y-3">
          <Card className="p-0 overflow-hidden">
            <div className="px-4 py-3 border-b border-border text-sm font-medium">Services ({(a.ports || []).length})</div>
            {(!a.ports || a.ports.length === 0) ? <Empty title="No open ports observed" /> : (
              <table className="w-full">
                <thead><tr><th className="th">Port</th><th className="th">Service</th><th className="th">Product / Version</th><th className="th">Confidence</th></tr></thead>
                <tbody>
                  {a.ports.map((p) => p.services.length ? p.services.map((s) => (
                    <tr key={s.id} className="hover:bg-surface-2/60">
                      <td className="td font-mono">{p.number}/{p.protocol}{s.verified && <span className="ml-1 text-ok" title="verified">✓</span>}</td>
                      <td className="td">{s.name || "—"}</td>
                      <td className="td text-muted">{s.product || "—"} {s.version || ""}</td>
                      <td className="td text-xs text-faint">{titleCase(s.confidence)}</td>
                    </tr>
                  )) : (
                    <tr key={p.id}><td className="td font-mono">{p.number}/{p.protocol}</td><td className="td text-faint" colSpan={3}>open</td></tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>

          <Card className="p-0 overflow-hidden">
            <div className="px-4 py-3 border-b border-border text-sm font-medium">Security findings ({findings?.length || 0})</div>
            {!findings || findings.length === 0 ? <Empty title="No findings for this asset" /> : (
              <table className="w-full">
                <thead><tr><th className="th w-16">Risk</th><th className="th">Severity</th><th className="th">Finding</th></tr></thead>
                <tbody>
                  {findings.map((f) => (
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

        <div className="space-y-3">
          {a.technologies?.length > 0 && (
            <Card className="p-4">
              <div className="text-sm font-medium mb-2">Technologies</div>
              <div className="flex flex-wrap gap-1.5">
                {a.technologies.map((t) => <Pill key={t.id}>{t.name}{t.version ? ` ${t.version}` : ""}</Pill>)}
              </div>
            </Card>
          )}
          {a.certificates?.length > 0 && (
            <Card className="p-4">
              <div className="text-sm font-medium mb-2">TLS Certificate</div>
              {a.certificates.map((c) => (
                <div key={c.id} className="text-xs text-muted space-y-1">
                  <div>Issuer: {c.issuer}</div>
                  <div>Expires: {fmtTime(c.not_after)}</div>
                  <div>TLS: {(c.tls_versions || []).join(", ") || "—"}</div>
                </div>
              ))}
            </Card>
          )}
          {meta.dns && Object.keys(meta.dns).length > 0 && (
            <Card className="p-4">
              <div className="text-sm font-medium mb-2">DNS</div>
              {Object.entries(meta.dns).map(([rt, vals]) => (
                <div key={rt} className="text-xs mb-1">
                  <span className="text-faint font-mono">{rt}</span>
                  <div className="text-muted font-mono break-all">{Array.isArray(vals) ? vals.join(", ") : String(vals)}</div>
                </div>
              ))}
            </Card>
          )}
          {meta.subdomains?.length > 0 && (
            <Card className="p-4">
              <div className="text-sm font-medium mb-2">Subdomains ({meta.subdomains.length})</div>
              <div className="text-xs text-muted font-mono space-y-0.5 max-h-40 overflow-y-auto">
                {meta.subdomains.map((s) => <div key={s}>{s}</div>)}
              </div>
            </Card>
          )}
          <Card className="p-4">
            <div className="text-sm font-medium mb-2">Change history</div>
            {!changes || changes.length === 0 ? <div className="text-xs text-faint">No changes recorded.</div> : (
              <div className="space-y-2">
                {changes.map((c) => (
                  <div key={c.id} className="text-xs">
                    <span className="text-primary">{titleCase(c.change_type)}</span>
                    <span className="text-faint ml-2">{fmtRelative(c.detected_at)}</span>
                    <div className="text-muted">{c.summary}</div>
                  </div>
                ))}
              </div>
            )}
          </Card>
          <Card className="p-4">
            <div className="text-xs text-faint space-y-1">
              <div>First seen: {fmtTime(a.first_seen)}</div>
              <div>Last scan: {fmtTime(a.last_seen)}</div>
              {a.owner && <div>Owner: {a.owner}</div>}
              {a.business_unit && <div>Business unit: {a.business_unit}</div>}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
