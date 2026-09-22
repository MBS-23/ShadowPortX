import { Card, PageHeader } from "../components/ui";

const FORMATS = [
  ["pdf", "PDF report", "Executive + technical, formatted for sharing"],
  ["html", "HTML report", "Styled, self-contained web report"],
  ["csv", "CSV (findings)", "Spreadsheet-ready findings export"],
  ["json", "JSON", "Full machine-readable dataset"],
];

export default function Reports() {
  const url = (fmt) => `/api/v1/reports/security?fmt=${fmt}`;
  return (
    <div>
      <PageHeader title="Reports" subtitle="Executive and technical security assessment reports." />
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
        {FORMATS.map(([fmt, label, desc]) => (
          <a key={fmt} href={url(fmt)} target="_blank" rel="noreferrer" className="card p-4 hover:border-primary/50 transition-colors">
            <div className="text-sm font-medium text-text">{label}</div>
            <div className="text-xs text-muted mt-1">{desc}</div>
            <div className="text-xs text-primary mt-3">Open {fmt.toUpperCase()} →</div>
          </a>
        ))}
      </div>
      <Card className="p-0 overflow-hidden">
        <div className="px-4 py-3 border-b border-border text-sm font-medium">Live preview (HTML)</div>
        <iframe title="report" src={url("html")} className="w-full bg-white" style={{ height: "70vh", border: "none" }} />
      </Card>
    </div>
  );
}
