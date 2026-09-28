import { useEffect, useMemo, useState } from "react";
import { endpoints, setToken } from "../api";
import Logo from "../components/Logo";
import AuthBackground from "../components/AuthBackground";
import { useTilt } from "../lib/useTilt";

const TRUST = [
  ["Authorized assessment only", "Every scan is gated by an explicit allow/deny scope."],
  ["Non-destructive verification", "Safe checks confirm exposure without exploiting it."],
  ["Correlation, not exploitation", "Vulnerability intelligence mapped to your real assets."],
];

function strength(pw) {
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  return Math.min(4, s);
}
const STRENGTH_LABEL = ["Too short", "Weak", "Fair", "Good", "Strong"];
const STRENGTH_COLOR = ["#f87171", "#fb923c", "#fbbf24", "#60a5fa", "#34d399"];

export default function Login({ onSuccess }) {
  const [mode, setMode] = useState("signin"); // signin | signup
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [cfg, setCfg] = useState({
    oidc_enabled: false,
    oidc_button_label: "Sign in with SSO",
    allow_self_registration: true,
  });
  const tilt = useTilt(5);

  useEffect(() => {
    endpoints.authConfig().then((c) => setCfg((prev) => ({ ...prev, ...c }))).catch(() => {});
  }, []);

  const isSignup = mode === "signup";
  const pwScore = useMemo(() => strength(password), [password]);

  const switchMode = (next) => {
    setMode(next);
    setError(null);
    setConfirm("");
  };

  const submit = async (e) => {
    e.preventDefault();
    setError(null);

    if (isSignup) {
      if (password.length < 8) return setError("Password must be at least 8 characters.");
      if (password !== confirm) return setError("Passwords do not match.");
    }

    setBusy(true);
    try {
      const res = isSignup
        ? await endpoints.register({ email, password, full_name: name || undefined })
        : await endpoints.login({ email, password });
      setToken(res.access_token);
      onSuccess?.(res);
    } catch (err) {
      const detail = err?.response?.data?.detail;
      setError(
        (Array.isArray(detail) ? detail[0]?.msg : detail) ||
          (isSignup ? "Could not create your account." : "Invalid email or password.")
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="spx-auth">
      <AuthBackground />

      <div className="spx-auth-shell">
        {/* Brand / value story */}
        <section className="spx-auth-hero">
          <div className="flex items-center gap-3">
            <Logo size={44} />
            <div>
              <div className="h-display text-2xl font-bold gradient-text gradient-text-animated leading-none">
                ShadowPortX
              </div>
              <div className="text-[11px] text-faint tracking-[0.18em] uppercase mt-1">
                Attack Surface Intelligence
              </div>
            </div>
          </div>

          <h1 className="h-display text-[30px] md:text-[38px] font-bold text-text leading-[1.1] mt-8">
            See your attack surface
            <br />
            <span className="gradient-text">the way an attacker does.</span>
          </h1>
          <p className="text-sm text-muted mt-4 max-w-md leading-relaxed">
            Continuous discovery, evidence-based findings and contextual exposure scoring —
            correlated across every asset, port, service and CVE.
          </p>

          <ul className="mt-8 space-y-3">
            {TRUST.map(([t, d]) => (
              <li key={t} className="flex items-start gap-3">
                <span className="spx-auth-check" aria-hidden="true">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6 9 17l-5-5" /></svg>
                </span>
                <div>
                  <div className="text-sm text-text font-medium">{t}</div>
                  <div className="text-xs text-faint">{d}</div>
                </div>
              </li>
            ))}
          </ul>
        </section>

        {/* Auth card */}
        <section className="spx-auth-cardwrap">
          <div ref={tilt} className="spx-auth-card card card-accent">
            {/* Compact brand for small screens */}
            <div className="flex items-center gap-2.5 mb-5 lg:hidden">
              <Logo size={34} />
              <div className="h-display font-bold text-lg gradient-text gradient-text-animated">ShadowPortX</div>
            </div>

            <div className="spx-seg" role="tablist" aria-label="Authentication mode">
              <button
                type="button" role="tab" aria-selected={!isSignup}
                className={`spx-seg-btn ${!isSignup ? "spx-seg-active" : ""}`}
                onClick={() => switchMode("signin")}
              >
                Sign in
              </button>
              {cfg.allow_self_registration && (
                <button
                  type="button" role="tab" aria-selected={isSignup}
                  className={`spx-seg-btn ${isSignup ? "spx-seg-active" : ""}`}
                  onClick={() => switchMode("signup")}
                >
                  Create account
                </button>
              )}
            </div>

            <div className="mb-4">
              <h2 className="h-display text-xl font-bold text-text">
                {isSignup ? "Create your account" : "Welcome back"}
              </h2>
              <p className="text-xs text-faint mt-1">
                {isSignup
                  ? "Set up access to your exposure workspace."
                  : "Sign in to your exposure workspace."}
              </p>
            </div>

            <form onSubmit={submit} className="space-y-3.5" noValidate>
              {isSignup && (
                <Field label="Full name" hint="optional">
                  <input
                    className="input w-full mt-1" type="text" autoComplete="name"
                    placeholder="Alex Rivera" value={name} onChange={(e) => setName(e.target.value)}
                  />
                </Field>
              )}

              <Field label="Email">
                <input
                  className="input w-full mt-1" type="email" required autoComplete="email"
                  placeholder="you@company.com" value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoFocus={!isSignup}
                />
              </Field>

              <Field label="Password">
                <div className="relative">
                  <input
                    className="input w-full mt-1 pr-16" required
                    type={showPw ? "text" : "password"}
                    autoComplete={isSignup ? "new-password" : "current-password"}
                    placeholder={isSignup ? "At least 8 characters" : "••••••••"}
                    value={password} onChange={(e) => setPassword(e.target.value)}
                  />
                  <button
                    type="button" onClick={() => setShowPw((v) => !v)}
                    className="spx-pw-toggle" aria-label={showPw ? "Hide password" : "Show password"}
                  >
                    {showPw ? "Hide" : "Show"}
                  </button>
                </div>
                {isSignup && password.length > 0 && (
                  <div className="mt-2">
                    <div className="spx-pw-meter" aria-hidden="true">
                      {[0, 1, 2, 3].map((i) => (
                        <span key={i} style={{ background: i < pwScore ? STRENGTH_COLOR[pwScore] : "#243250" }} />
                      ))}
                    </div>
                    <div className="text-[11px] mt-1" style={{ color: STRENGTH_COLOR[pwScore] }}>
                      {STRENGTH_LABEL[pwScore]}
                    </div>
                  </div>
                )}
              </Field>

              {isSignup && (
                <Field label="Confirm password">
                  <input
                    className="input w-full mt-1" required type={showPw ? "text" : "password"}
                    autoComplete="new-password" placeholder="Re-enter password"
                    value={confirm} onChange={(e) => setConfirm(e.target.value)}
                    aria-invalid={confirm.length > 0 && confirm !== password}
                  />
                </Field>
              )}

              {error && (
                <div className="spx-auth-error" role="alert">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10" /><path d="M12 8v4M12 16h.01" /></svg>
                  <span>{String(error)}</span>
                </div>
              )}

              <button className="btn-primary w-full justify-center !py-2.5" disabled={busy}>
                {busy ? (
                  <><span className="h-4 w-4 rounded-full border-2 border-bg/40 border-t-bg animate-spin" />{isSignup ? "Creating account…" : "Signing in…"}</>
                ) : (
                  isSignup ? "Create account" : "Sign in"
                )}
              </button>

              {cfg.oidc_enabled && (
                <>
                  <div className="flex items-center gap-3 text-[10px] uppercase tracking-widest text-faint py-1">
                    <span className="h-px flex-1 bg-border" />or<span className="h-px flex-1 bg-border" />
                  </div>
                  <a href={endpoints.oidcLoginUrl()} className="btn-ghost w-full justify-center">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
                    {cfg.oidc_button_label || "Sign in with SSO"}
                  </a>
                </>
              )}
            </form>

            <p className="text-center text-[11px] text-faint mt-5">
              {isSignup ? "New accounts start with read-only access." : "Authorized security assessment platform"}
            </p>
          </div>
        </section>
      </div>
    </div>
  );
}

function Field({ label, hint, children }) {
  return (
    <label className="block">
      <span className="text-xs text-faint flex items-center justify-between">
        {label}
        {hint && <span className="text-faint/70 normal-case">{hint}</span>}
      </span>
      {children}
    </label>
  );
}
