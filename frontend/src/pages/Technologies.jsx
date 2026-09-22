import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, Pill, Spinner, ErrorNote, PageHeader, Empty } from "../components/ui";
import { titleCase } from "../lib/format";

export default function Technologies() {
  const { data, loading, error } = useFetch(() => endpoints.technologies(), []);
  return (
    <div>
      <PageHeader title="Technologies" subtitle="Software and frameworks fingerprinted across assets, with evidence-based detection." />
      {loading && !data ? <Spinner /> : error ? <ErrorNote error={error} /> :
        !data || data.length === 0 ? <Card className="p-0"><Empty title="No technologies detected yet" hint="Run a scan against web assets." /></Card> : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {data.map((t) => (
              <Card key={t.name} className="p-4">
                <div className="flex items-center justify-between">
                  <div className="font-medium text-text">{t.name}</div>
                  <Pill tone="primary">{t.asset_count} asset{t.asset_count !== 1 ? "s" : ""}</Pill>
                </div>
                {t.category && <div className="text-xs text-faint mt-0.5">{titleCase(t.category)}</div>}
                {t.versions.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-3">
                    {t.versions.map((v) => <Pill key={v}>{v}</Pill>)}
                  </div>
                )}
              </Card>
            ))}
          </div>
        )}
    </div>
  );
}
