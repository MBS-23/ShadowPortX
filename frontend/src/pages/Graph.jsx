import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, Spinner, ErrorNote, PageHeader, Empty, Pill, RiskScore } from "../components/ui";
import { SEVERITY, riskColor, titleCase } from "../lib/format";

const TIER = { asset: 0, ip: 1, port: 2, service: 3, technology: 4, vulnerability: 4, finding: 5 };
const TYPE_COLOR = {
  asset: "#22d3ee", ip: "#94a3b8", port: "#64748b", service: "#38bdf8",
  technology: "#818cf8", vulnerability: "#fb923c", finding: "#f87171",
};
const NODE_W = 168, NODE_H = 42, COL_W = 212, ROW_H = 62, PAD = 24;

function GraphSVG({ graph, onNode }) {
  const { pos, width, height } = useMemo(() => {
    const tiers = {};
    for (const n of graph.nodes) {
      const t = TIER[n.type] ?? 5;
      (tiers[t] ||= []).push(n);
    }
    const pos = {};
    let maxRows = 0;
    Object.entries(tiers).forEach(([t, ns]) => {
      maxRows = Math.max(maxRows, ns.length);
      ns.forEach((n, i) => { pos[n.id] = { x: Number(t) * COL_W + PAD, y: i * ROW_H + PAD, node: n }; });
    });
    const maxTier = Math.max(...Object.keys(tiers).map(Number), 0);
    return { pos, width: (maxTier + 1) * COL_W + PAD, height: Math.max(1, maxRows) * ROW_H + PAD };
  }, [graph]);

  const nodeColor = (n) =>
    n.type === "finding" && n.ref?.severity ? SEVERITY[n.ref.severity]?.color || TYPE_COLOR.finding
      : TYPE_COLOR[n.type] || "#64748b";

  return (
    <div className="overflow-auto">
      <svg width={width} height={height} style={{ minWidth: "100%" }}>
        {graph.edges.map((e, i) => {
          const s = pos[e.source], t = pos[e.target];
          if (!s || !t) return null;
          const x1 = s.x + NODE_W, y1 = s.y + NODE_H / 2, x2 = t.x, y2 = t.y + NODE_H / 2;
          const mx = (x1 + x2) / 2;
          return (
            <path key={i} d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
              fill="none" stroke="#243250" strokeWidth="1.5" />
          );
        })}
        {Object.values(pos).map(({ x, y, node }) => {
          const color = nodeColor(node);
          const clickable = ["finding", "asset", "vulnerability"].includes(node.type);
          return (
            <g key={node.id} transform={`translate(${x},${y})`}
              style={{ cursor: clickable ? "pointer" : "default" }}
              onClick={() => clickable && onNode(node)}>
              <rect width={NODE_W} height={NODE_H} rx="8" fill="#111a2e" stroke={color} strokeWidth="1.5" />
              <rect width="4" height={NODE_H} rx="2" fill={color} />
              <text x="14" y="17" fill="#e5e7eb" fontSize="12" fontWeight="600">
                {node.label.length > 20 ? node.label.slice(0, 19) + "…" : node.label}
              </text>
              <text x="14" y="32" fill="#64748b" fontSize="10">
                {node.type}{node.ref?.risk ? ` · risk ${node.ref.risk}` : ""}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function BlastRadius() {
  const [q, setQ] = useState({ kind: "technology", value: "nginx" });
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const run = async (e) => {
    e?.preventDefault();
    setBusy(true);
    try {
      const params = q.kind === "technology" ? { technology: q.value } : { cve: q.value };
      setRes(await endpoints.blastRadius(params));
    } catch { setRes(null); } finally { setBusy(false); }
  };
  return (
    <Card className="p-4">
      <div className="text-sm font-medium mb-3">Blast radius</div>
      <form onSubmit={run} className="flex gap-2 mb-3">
        <select className="input py-1" value={q.kind} onChange={(e) => setQ({ ...q, value: "", kind: e.target.value })}>
          <option value="technology">Technology</option>
          <option value="cve">CVE</option>
        </select>
        <input className="input flex-1 py-1" placeholder={q.kind === "cve" ? "CVE-2022-0543" : "nginx"}
          value={q.value} onChange={(e) => setQ({ ...q, value: e.target.value })} />
        <button className="btn-primary py-1" disabled={busy || !q.value}>Analyze</button>
      </form>
      {res && (
        <div>
          <div className="grid grid-cols-4 gap-2 mb-3 text-center">
            {[["Affected", res.affected], ["Internet", res.internet_facing], ["Prod", res.production], ["Critical", res.critical_assets]].map(([l, v]) => (
              <div key={l} className="bg-surface-2 rounded-lg py-2">
                <div className="text-lg font-semibold">{v}</div><div className="text-[10px] text-faint">{l}</div>
              </div>
            ))}
          </div>
          {res.assets.length === 0 ? <div className="text-xs text-faint">No assets match.</div> : (
            <div className="space-y-1 max-h-40 overflow-y-auto">
              {res.assets.map((a) => (
                <div key={a.id} className="flex items-center gap-2 text-xs">
                  <RiskScore score={a.risk_score} />
                  <span className="font-mono text-muted">{a.value}</span>
                  <Pill tone={a.exposure === "internet_facing" ? "warn" : "muted"}>{titleCase(a.exposure)}</Pill>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

export default function Graph() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const { data: assets } = useFetch(() => endpoints.assets(), []);
  const [assetId, setAssetId] = useState(params.get("asset") || "");

  useEffect(() => {
    if (!assetId && assets && assets.length) setAssetId(String(assets[0].id));
  }, [assets, assetId]);

  const { data: graph, loading, error } = useFetch(
    () => (assetId ? endpoints.assetGraph(assetId) : Promise.resolve(null)), [assetId]
  );

  const onNode = (n) => {
    if (n.type === "finding" && n.ref?.finding_id) navigate(`/findings/${n.ref.finding_id}`);
    else if (n.type === "asset" && n.ref?.asset_id) navigate(`/assets/${n.ref.asset_id}`);
    else if (n.type === "vulnerability") navigate(`/vulnerabilities`);
  };

  return (
    <div>
      <PageHeader title="Asset Graph" subtitle="A navigation map of what each asset exposes and the findings tied to it. Click a finding or vulnerability node to open it." />
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-3">
        <div className="lg:col-span-3 space-y-3">
          <Card className="p-3 flex items-center gap-3">
            <span className="text-xs text-faint">Asset</span>
            <select className="input py-1 flex-1 max-w-md" value={assetId}
              onChange={(e) => { setAssetId(e.target.value); setParams({ asset: e.target.value }); }}>
              {(assets || []).map((a) => <option key={a.id} value={a.id}>{a.value}</option>)}
            </select>
            <div className="ml-auto flex items-center gap-2 text-[10px] text-faint">
              {Object.entries(TYPE_COLOR).map(([t, c]) => (
                <span key={t} className="inline-flex items-center gap-1">
                  <span className="w-2 h-2 rounded-sm" style={{ background: c }} />{t}
                </span>
              ))}
            </div>
          </Card>
          <Card className="p-3">
            {loading && !graph ? <Spinner /> : error ? <ErrorNote error={error} /> :
              !graph || graph.nodes.length <= 1 ? <Empty title="No graph data" hint="Scan this asset to build its map." /> :
                <GraphSVG graph={graph} onNode={onNode} />}
          </Card>
        </div>
        <div><BlastRadius /></div>
      </div>
    </div>
  );
}
