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
    const maxRows = Math.max(1, ...Object.values(tiers).map((ns) => ns.length));
    // Vertically center each column so sparse tiers (asset/ip) align with the node mass.
    Object.entries(tiers).forEach(([t, ns]) => {
      const offset = ((maxRows - ns.length) / 2) * ROW_H;
      ns.forEach((n, i) => {
        pos[n.id] = { x: Number(t) * COL_W + PAD, y: PAD + offset + i * ROW_H, node: n };
      });
    });
    const maxTier = Math.max(...Object.keys(tiers).map(Number), 0);
    return { pos, width: (maxTier + 1) * COL_W + PAD, height: maxRows * ROW_H + PAD };
  }, [graph]);

  const nodeColor = (n) =>
    n.type === "finding" && n.ref?.severity ? SEVERITY[n.ref.severity]?.color || TYPE_COLOR.finding
      : TYPE_COLOR[n.type] || "#64748b";

  return (
    <div className="overflow-auto">
      <svg width={width} height={height} style={{ minWidth: "100%" }}>
        <defs>
          <linearGradient id="spx-edge" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.55" />
            <stop offset="100%" stopColor="#8b7cff" stopOpacity="0.55" />
          </linearGradient>
          <filter id="spx-glow" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="3" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>
        {graph.edges.map((e, i) => {
          const s = pos[e.source], t = pos[e.target];
          if (!s || !t) return null;
          const x1 = s.x + NODE_W, y1 = s.y + NODE_H / 2, x2 = t.x, y2 = t.y + NODE_H / 2;
          const mx = (x1 + x2) / 2;
          return (
            <path key={i} d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
              fill="none" stroke="url(#spx-edge)" strokeWidth="1.75" />
          );
        })}
        {Object.values(pos).map(({ x, y, node }) => {
          const color = nodeColor(node);
          const clickable = ["finding", "asset", "vulnerability"].includes(node.type);
          const glow = node.type === "finding" || node.type === "vulnerability";
          return (
            <g key={node.id} transform={`translate(${x},${y})`}
              className="spx-node"
              style={{ cursor: clickable ? "pointer" : "default" }}
              filter={glow ? "url(#spx-glow)" : undefined}
              onClick={() => clickable && onNode(node)}>
              <rect width={NODE_W} height={NODE_H} rx="9" fill="#0f1930" stroke={color}
                strokeWidth="1.5" strokeOpacity="0.9" />
              <rect width="3.5" height={NODE_H} rx="2" fill={color} />
              <text x="15" y="17" fill="#e5e7eb" fontSize="12" fontWeight="600" fontFamily="Inter, sans-serif">
                {node.label.length > 20 ? node.label.slice(0, 19) + "…" : node.label}
              </text>
              <text x="15" y="32" fill="#64748b" fontSize="10">
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
  const tiles = res ? [
    ["Affected", res.affected, "#22d3ee"],
    ["Internet", res.internet_facing, "#fb923c"],
    ["Production", res.production, "#8b7cff"],
    ["Critical", res.critical_assets, "#f87171"],
  ] : [];

  return (
    <Card className="card-accent p-4">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
        <div className="text-sm font-medium">
          Blast radius <span className="text-faint font-normal">— how far a technology or CVE reaches</span>
        </div>
        <form onSubmit={run} className="flex flex-wrap gap-2">
          <select className="input py-1.5" value={q.kind} onChange={(e) => setQ({ ...q, value: "", kind: e.target.value })}>
            <option value="technology">Technology</option>
            <option value="cve">CVE</option>
          </select>
          <input className="input py-1.5 w-52" placeholder={q.kind === "cve" ? "CVE-2022-0543" : "nginx"}
            value={q.value} onChange={(e) => setQ({ ...q, value: e.target.value })} />
          <button className="btn-primary py-1.5" disabled={busy || !q.value}>Analyze</button>
        </form>
      </div>
      {!res ? (
        <p className="text-xs text-faint">
          Enter a technology (e.g. <span className="font-mono text-muted">nginx</span>) or a CVE
          (e.g. <span className="font-mono text-muted">CVE-2022-0543</span>) to see every asset it touches.
        </p>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="grid grid-cols-2 gap-2 content-start">
            {tiles.map(([l, v, c]) => (
              <div key={l} className="rounded-lg border border-border bg-surface-2/60 py-3 text-center">
                <div className="h-display text-2xl font-bold" style={{ color: c }}>{v}</div>
                <div className="text-[10px] text-faint uppercase tracking-wide mt-0.5">{l}</div>
              </div>
            ))}
          </div>
          <div className="md:col-span-2">
            {res.assets.length === 0 ? <Empty title="No assets match" /> : (
              <div className="rounded-lg border border-border divide-y divide-border/70 max-h-56 overflow-y-auto">
                {res.assets.map((a) => (
                  <div key={a.id} className="flex items-center gap-3 px-3 py-2 text-sm hover:bg-surface-2/60">
                    <RiskScore score={a.risk_score} />
                    <span className="font-mono text-muted flex-1 truncate">{a.value}</span>
                    <Pill tone={a.exposure === "internet_facing" ? "warn" : "muted"}>{titleCase(a.exposure)}</Pill>
                  </div>
                ))}
              </div>
            )}
          </div>
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
      <div className="space-y-3">
        <Card className="p-3">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <div className="flex items-center gap-2">
              <span className="text-xs text-faint">Asset</span>
              <select className="input py-1.5 min-w-[220px]" value={assetId}
                onChange={(e) => { setAssetId(e.target.value); setParams({ asset: e.target.value }); }}>
                {(assets || []).map((a) => <option key={a.id} value={a.id}>{a.value}</option>)}
              </select>
            </div>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 md:ml-auto text-[10px] text-faint">
              {Object.entries(TYPE_COLOR).map(([t, c]) => (
                <span key={t} className="inline-flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-sm" style={{ background: c }} />{t}
                </span>
              ))}
            </div>
          </div>
        </Card>
        <Card className="card-accent p-3">
          {loading && !graph ? <Spinner /> : error ? <ErrorNote error={error} /> :
            !graph || graph.nodes.length <= 1 ? <Empty title="No graph data" hint="Scan this asset to build its map." /> :
              <GraphSVG graph={graph} onNode={onNode} />}
        </Card>
        <BlastRadius />
      </div>
    </div>
  );
}
