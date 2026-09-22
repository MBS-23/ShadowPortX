import { useState } from "react";
import { Link } from "react-router-dom";
import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, SeverityBadge, StateBadge, StatusBadge, RiskScore, Spinner, ErrorNote, PageHeader, Empty } from "../components/ui";
import { titleCase } from "../lib/format";

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];
const STATUSES = ["", "new", "triaged", "in_progress", "verifying", "resolved", "accepted_risk", "false_positive"];

export default function Findings() {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const params = {};
  if (severity) params.severity = severity;
  if (status) params.status_ = status;

  const { data, loading, error } = useFetch(() => endpoints.findings(params), [severity, status]);

  return (
    <div>
      <PageHeader title="Findings" subtitle="Evidence-based exposures, ranked by ShadowPortX Exposure Score." />
      <Card className="p-3 mb-3 flex flex-wrap items-center gap-3">
        <label className="text-xs text-faint">Severity
          <select className="input ml-2 py-1" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s ? titleCase(s) : "All"}</option>)}
          </select>
        </label>
        <label className="text-xs text-faint">Status
          <select className="input ml-2 py-1" value={status} onChange={(e) => setStatus(e.target.value)}>
            {STATUSES.map((s) => <option key={s} value={s}>{s ? titleCase(s) : "All"}</option>)}
          </select>
        </label>
        {data && <span className="text-xs text-muted ml-auto">{data.length} findings</span>}
      </Card>

      <Card className="p-0 overflow-hidden">
        {loading && !data ? <Spinner /> : error ? <div className="p-4"><ErrorNote error={error} /></div> :
          data.length === 0 ? <Empty title="No findings match" hint="Adjust filters or run a scan." /> : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[820px]">
                <thead><tr>
                  <th className="th w-16">Risk</th><th className="th">Severity</th><th className="th">Finding</th>
                  <th className="th">State</th><th className="th">Status</th><th className="th">Category</th>
                </tr></thead>
                <tbody>
                  {data.map((f) => (
                    <tr key={f.id} className="hover:bg-surface-2/60">
                      <td className="td"><RiskScore score={f.risk_score} /></td>
                      <td className="td"><SeverityBadge severity={f.severity} /></td>
                      <td className="td max-w-[380px]">
                        <Link to={`/findings/${f.id}`} className="text-text hover:text-primary">{f.title}</Link>
                        <div className="text-[11px] text-faint font-mono">{f.spx_id}</div>
                      </td>
                      <td className="td"><StateBadge state={f.state} /></td>
                      <td className="td"><StatusBadge status={f.status} /></td>
                      <td className="td text-xs text-muted">{titleCase(f.category)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </Card>
    </div>
  );
}
