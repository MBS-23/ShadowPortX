import { useState } from "react";
import { endpoints } from "../api";
import Logo from "../components/Logo";

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
        <div className="flex items-center gap-3 mb-6 justify-center">
          <Logo size={40} />
          <div>
            <div className="h-display font-bold text-lg gradient-text gradient-text-animated">ShadowPortX</div>
            <div className="text-[10px] text-faint tracking-[0.16em] uppercase">Attack Surface Intelligence</div>
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
