import { useState } from "react";
import { endpoints } from "../api";

export default function Login({ onSuccess }) {
  const [email, setEmail] = useState("admin@shadowportx.local");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      const res = await endpoints.login({ email, password });
      localStorage.setItem("spx_token", res.access_token);
      onSuccess?.();
    } catch (err) {
      setError(err?.response?.data?.detail || "Login failed");
    } finally { setBusy(false); }
  };

  return (
    <div className="min-h-screen grid place-items-center bg-bg px-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-2.5 mb-6 justify-center">
          <img src="/icon.svg" alt="ShadowPortX" className="h-10 w-10" />
          <div>
            <div className="font-semibold text-text">ShadowPort<span className="text-primary">X</span></div>
            <div className="text-[10px] text-faint tracking-wide">Attack Surface Intelligence</div>
          </div>
        </div>
        <form onSubmit={submit} className="card p-6 space-y-4">
          <div>
            <label className="text-xs text-faint">Email</label>
            <input className="input w-full mt-1" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div>
            <label className="text-xs text-faint">Password</label>
            <input className="input w-full mt-1" type="password" required value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
          </div>
          {error && <div className="text-sm text-critical">{error}</div>}
          <button className="btn-primary w-full justify-center" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        </form>
        <p className="text-center text-[11px] text-faint mt-4">Authorized security assessment platform</p>
      </div>
    </div>
  );
}
