import { useParams, Link, useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, SeverityBadge, StateBadge, StatusBadge, RiskScore, Spinner, ErrorNote, Pill } from "../components/ui";
import { titleCase, fmtTime } from "../lib/format";

const STATUSES = ["new", "triaged", "in_progress", "remediation_ready", "verifying", "resolved", "accepted_risk", "false_positive"];

export default function FindingDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { data: f, loading, error, reload } = useFetch(() => endpoints.finding(id), [id]);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);
  const [notes, setNotes] = useState("");
  useEffect(() => { if (f) setNotes(f.notes || ""); }, [f]);

  if (loading && !f) return <Spinner />;
  if (error) return <ErrorNote error={error} />;

  const setStatus = async (status) => {
    setBusy(true);
    try { await endpoints.updateFinding(id, { status }); await reload(); }
    finally { setBusy(false); }
  };
  const verify = async () => {
    setBusy(true); setMsg(null);
    try {
      const scan = await endpoints.verifyFinding(id);
      setMsg(`Re-verification scan #${scan.id} queued. The finding auto-resolves if the condition is gone.`);
      await reload();
    } catch (e) { setMsg(e?.response?.data?.detail || "Failed to queue verification"); }
    finally { setBusy(false); }
  };
  const validate = async () => {
    setBusy(true); setMsg(null);
    try {
      const res = await endpoints.validateFinding(id);
      setMsg(res.message);
      await reload();
    } catch (e) { setMsg(e?.response?.data?.detail || "Validation failed"); }
    finally { setBusy(false); }
  };
  const saveNotes = async () => {
    setBusy(true);
    try { await endpoints.updateFinding(id, { notes }); setMsg("Notes saved."); await reload(); }
    finally { setBusy(false); }
  };

  const bd = f.risk_breakdown || {};
  const factors = Object.entries(bd).filter(([k, v]) => v && typeof v === "object" && "contribution" in v);

  return (
    <div>
      <Link to="/findings" className="text-xs text-primary hover:underline">← Back to findings</Link>
      <div className="flex flex-wrap items-start justify-between gap-4 mt-2 mb-5">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={f.severity} />
            <StateBadge state={f.state} />
            <StatusBadge status={f.status} />
            <span className="font-mono text-xs text-faint">{f.spx_id}</span>
          </div>
          <h1 className="text-xl font-semibold mt-2">{f.title}</h1>
          <div className="text-sm text-muted mt-1">
            {titleCase(f.category)} · detected via {titleCase(f.detection_method)} · exposure {titleCase(f.exposure)}
          </div>
        </div>
        <Card className="p-4 text-center min-w-[130px]">
          <div className="text-[10px] uppercase tracking-wide text-faint">SPX Exposure</div>
          <RiskScore score={f.risk_score} size="lg" />
        </Card>
      </div>

      {msg && <div className="card p-3 mb-3 text-sm text-primary border-primary/30 bg-primary/5">{msg}</div>}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <div className="lg:col-span-2 space-y-3">
          <Card className="p-4">
            <h2 className="text-sm font-medium mb-2">Description</h2>
            <p className="text-sm text-muted leading-relaxed">{f.description}</p>
          </Card>

          {f.evidence?.validation && (
            <Card className="p-4 border-ok/40 bg-ok/5">
              <h2 className="text-sm font-medium mb-2 flex items-center gap-2">
                <span className="inline-grid place-items-center h-4 w-4 rounded-full bg-ok/20 text-ok text-[10px]">✓</span>
                Validation proof
              </h2>
              <div className="text-xs space-y-1.5">
                {f.evidence.validation.condition && (
                  <div><span className="text-faint">Condition: </span><span className="text-text">{titleCase(f.evidence.validation.condition)}</span></div>
                )}
                {f.evidence.validation.method && (
                  <div><span className="text-faint">Method: </span><span className="text-text">{f.evidence.validation.method}</span></div>
                )}
                {f.evidence.validation.probe && (
                  <div><span className="text-faint">Probe: </span><span className="font-mono text-primary">{f.evidence.validation.probe}</span></div>
                )}
                {f.evidence.validation.response_snippet && (
                  <div><span className="text-faint">Response: </span><span className="font-mono text-muted break-all">{f.evidence.validation.response_snippet}</span></div>
                )}
              </div>
            </Card>
          )}

          <Card className="p-4">
            <h2 className="text-sm font-medium mb-2">Evidence</h2>
            <pre className="text-xs bg-bg rounded-lg p-3 overflow-x-auto text-muted font-mono border border-border">
{JSON.stringify(f.evidence, null, 2)}
            </pre>
          </Card>

          <Card className="p-4">
            <h2 className="text-sm font-medium mb-2">Recommendation</h2>
            <p className="text-sm text-muted leading-relaxed">{f.recommendation}</p>
          </Card>

          {f.references?.length > 0 && (
            <Card className="p-4">
              <h2 className="text-sm font-medium mb-2">References</h2>
              <ul className="space-y-1">
                {f.references.map((r) => (
                  <li key={r}><a href={r} target="_blank" rel="noreferrer" className="text-sm text-primary hover:underline break-all">{r}</a></li>
                ))}
              </ul>
            </Card>
          )}
        </div>

        <div className="space-y-3">
          <Card className="p-4">
            <h2 className="text-sm font-medium mb-3">SPX-ES breakdown</h2>
            <div className="space-y-2">
              {factors.map(([name, v]) => (
                <div key={name} className="flex items-center justify-between text-xs">
                  <span className="text-muted">{titleCase(name)}</span>
                  <span className="font-mono text-text">
                    {v.factor} × {v.weight} = <span className="text-primary">{v.contribution}</span>
                  </span>
                </div>
              ))}
            </div>
            <div className="text-[10px] text-faint mt-3 font-mono">{bd.formula}</div>
          </Card>

          <Card className="p-4 space-y-3">
            <h2 className="text-sm font-medium">Remediation workflow</h2>
            <div className="text-xs text-muted space-y-1">
              <div>First seen: {fmtTime(f.first_seen)}</div>
              <div>Last seen: {fmtTime(f.last_seen)}</div>
              {f.resolved_at && <div>Resolved: {fmtTime(f.resolved_at)}</div>}
              {f.assignee && <div>Assignee: {f.assignee}</div>}
            </div>
            <div>
              <label className="text-xs text-faint">Status</label>
              <select className="input w-full mt-1" value={f.status} disabled={busy}
                onChange={(e) => setStatus(e.target.value)}>
                {STATUSES.map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
              </select>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <button className="btn-ghost justify-center" disabled={busy} onClick={validate}>
                {busy ? "…" : "Validate (safe)"}
              </button>
              <button className="btn-primary justify-center" disabled={busy} onClick={verify}>
                {busy ? "…" : "Verify fix"}
              </button>
            </div>
            {f.validated_at && <div className="text-[10px] text-ok">Last validated {fmtTime(f.validated_at)}</div>}
            <p className="text-[10px] text-faint">
              Validate = safe confirmation (L0–L3): non-destructive verification plus read-only
              proof-of-concept. Verify fix = authorized re-scan. Weaponized exploitation (L4) is
              not enabled.
            </p>
          </Card>

          <Card className="p-4 space-y-2">
            <h2 className="text-sm font-medium">Analyst notes</h2>
            <textarea className="input w-full h-24 resize-y" placeholder="Reproduction steps, context, evidence notes…"
              value={notes} onChange={(e) => setNotes(e.target.value)} />
            <button className="btn-ghost w-full justify-center" disabled={busy} onClick={saveNotes}>Save notes</button>
          </Card>

          <Card className="p-4">
            <div className="text-xs text-faint">Asset</div>
            <Link to={`/assets/${f.asset_id}`} className="text-sm text-primary hover:underline">View asset #{f.asset_id} →</Link>
          </Card>
        </div>
      </div>
    </div>
  );
}
