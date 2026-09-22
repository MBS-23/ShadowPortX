import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, SeverityBadge, Pill, Spinner, ErrorNote, PageHeader, Empty } from "../components/ui";

export default function Vulnerabilities() {
  const { data, loading, error } = useFetch(() => endpoints.vulnerabilities(), []);
  return (
    <div>
      <PageHeader
        title="Vulnerability Intelligence"
        subtitle="Public CVE intelligence correlated to detected versions. Correlation, not exploitation — confirm before acting."
      />
      <Card className="p-0 overflow-hidden">
        {loading && !data ? <Spinner /> : error ? <div className="p-4"><ErrorNote error={error} /></div> :
          data.length === 0 ? <Empty title="No correlated vulnerabilities" hint="Detected versions are matched against the CVE dataset during scans." /> : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[820px]">
                <thead><tr>
                  <th className="th">CVE</th><th className="th">Severity</th><th className="th">CVSS</th>
                  <th className="th">Exploit</th><th className="th">Affected findings</th><th className="th">Summary</th>
                </tr></thead>
                <tbody>
                  {data.map((v) => (
                    <tr key={v.id} className="hover:bg-surface-2/60">
                      <td className="td font-mono">
                        {v.references?.[0]
                          ? <a href={v.references[0]} target="_blank" rel="noreferrer" className="text-primary hover:underline">{v.cve_id}</a>
                          : v.cve_id}
                      </td>
                      <td className="td"><SeverityBadge severity={v.severity} /></td>
                      <td className="td font-mono">{v.cvss_score ?? "—"}</td>
                      <td className="td">{v.exploit_known ? <Pill tone="warn">Known exploit</Pill> : <span className="text-faint text-xs">—</span>}</td>
                      <td className="td font-mono">{v.affected_findings}</td>
                      <td className="td text-muted text-sm max-w-[360px]">{v.title}</td>
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
