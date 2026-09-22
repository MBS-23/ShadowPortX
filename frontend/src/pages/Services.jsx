import { Link } from "react-router-dom";
import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, Pill, Spinner, ErrorNote, PageHeader, Empty } from "../components/ui";
import { titleCase } from "../lib/format";

export default function Services() {
  const { data, loading, error } = useFetch(() => endpoints.services(), []);
  return (
    <div>
      <PageHeader title="Services" subtitle="Every exposed service identified across the inventory (protocol-first detection)." />
      <Card className="p-0 overflow-hidden">
        {loading && !data ? <Spinner /> : error ? <div className="p-4"><ErrorNote error={error} /></div> :
          data.length === 0 ? <Empty title="No services yet" hint="Run a scan to discover services." /> : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px]">
                <thead><tr>
                  <th className="th">Asset</th><th className="th">Port</th><th className="th">Service</th>
                  <th className="th">Product / Version</th><th className="th">Detection</th><th className="th">Confidence</th>
                </tr></thead>
                <tbody>
                  {data.map((s) => (
                    <tr key={s.id} className="hover:bg-surface-2/60">
                      <td className="td"><Link to={`/assets/${s.asset_id}`} className="text-text hover:text-primary font-mono">{s.asset}</Link></td>
                      <td className="td font-mono">{s.port}/{s.protocol}{s.verified && <span className="ml-1 text-ok" title="verified">✓</span>}</td>
                      <td className="td">{s.name || "—"}</td>
                      <td className="td text-muted">{s.product || "—"} {s.version || ""}</td>
                      <td className="td text-xs text-muted">{titleCase(s.detection_method)}</td>
                      <td className="td"><Pill tone={s.confidence === "high" ? "ok" : "muted"}>{titleCase(s.confidence)}</Pill></td>
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
