import { Link } from "react-router-dom";
import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, RiskScore, Pill, Spinner, ErrorNote, PageHeader, Empty } from "../components/ui";
import { titleCase, fmtTime } from "../lib/format";

export default function Assets() {
  const { data, loading, error } = useFetch(() => endpoints.assets(), []);

  return (
    <div>
      <PageHeader title="Asset Inventory" subtitle="Everything discovered within authorized scope — domains, subdomains, hosts." />
      <Card className="p-0 overflow-hidden">
        {loading && !data ? <Spinner /> : error ? <div className="p-4"><ErrorNote error={error} /></div> :
          data.length === 0 ? <Empty title="No assets yet" hint="Run a scan to build the inventory." /> : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px]">
                <thead><tr>
                  <th className="th w-16">Risk</th><th className="th">Asset</th><th className="th">Type</th>
                  <th className="th">Exposure</th><th className="th">Criticality</th><th className="th">Last seen</th>
                </tr></thead>
                <tbody>
                  {data.map((a) => (
                    <tr key={a.id} className="hover:bg-surface-2/60">
                      <td className="td"><RiskScore score={a.risk_score} /></td>
                      <td className="td">
                        <Link to={`/assets/${a.id}`} className="text-text hover:text-primary font-medium">{a.value}</Link>
                        {a.ip_address && <div className="text-[11px] text-faint font-mono">{a.ip_address}</div>}
                      </td>
                      <td className="td text-xs text-muted">{titleCase(a.type)}</td>
                      <td className="td">
                        <Pill tone={a.exposure === "internet_facing" ? "warn" : "muted"}>{titleCase(a.exposure)}</Pill>
                      </td>
                      <td className="td text-xs text-muted">{titleCase(a.criticality)}</td>
                      <td className="td text-xs text-faint">{fmtTime(a.last_seen)}</td>
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
