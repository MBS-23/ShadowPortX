import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, Pill, Spinner, ErrorNote, PageHeader, Empty } from "../components/ui";
import { titleCase, fmtTime } from "../lib/format";

const TONE = {
  new_asset: "primary", new_port: "warn", new_service: "warn",
  risk_increased: "warn", risk_decreased: "ok", port_closed: "muted",
};

export default function Changes() {
  const { data, loading, error } = useFetch(() => endpoints.changes(), []);

  return (
    <div>
      <PageHeader title="Attack Surface Changes" subtitle="What appeared, disappeared, or shifted since the previous scan." />
      <Card className="p-0 overflow-hidden">
        {loading && !data ? <Spinner /> : error ? <div className="p-4"><ErrorNote error={error} /></div> :
          data.length === 0 ? <Empty title="No changes recorded" hint="Changes appear after the second scan of an asset." /> : (
            <div className="divide-y divide-border/70">
              {data.map((c) => (
                <div key={c.id} className="px-4 py-3 flex items-start gap-3 hover:bg-surface-2/50">
                  <Pill tone={TONE[c.change_type] || "muted"}>{titleCase(c.change_type)}</Pill>
                  <div className="flex-1">
                    <div className="text-sm text-text">{c.summary}</div>
                    {c.risk_delta ? <div className="text-xs text-muted mt-0.5">Risk Δ {c.risk_delta > 0 ? "+" : ""}{c.risk_delta}</div> : null}
                  </div>
                  <div className="text-xs text-faint whitespace-nowrap">{fmtTime(c.detected_at)}</div>
                </div>
              ))}
            </div>
          )}
      </Card>
    </div>
  );
}
