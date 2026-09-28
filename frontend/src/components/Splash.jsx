import { useEffect, useRef, useState } from "react";
import Logo from "./Logo";

/**
 * Cinematic opening: the mark assembles at screen center inside a sweeping scan ring, the
 * wordmark rises in, then the whole thing lifts and fades to reveal the app (or sign-in).
 * Timeline collapses to a brief, motion-free hold under prefers-reduced-motion.
 */
export default function Splash({ onDone }) {
  const [leaving, setLeaving] = useState(false);
  const doneRef = useRef(onDone);
  doneRef.current = onDone;

  useEffect(() => {
    const reduce =
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const HOLD = reduce ? 500 : 1650;
    const EXIT = reduce ? 200 : 480;

    const t1 = setTimeout(() => setLeaving(true), HOLD);
    const t2 = setTimeout(() => doneRef.current?.(), HOLD + EXIT);
    return () => { clearTimeout(t1); clearTimeout(t2); };
  }, []);

  return (
    <div className={`spx-splash ${leaving ? "spx-splash-leaving" : ""}`} role="status" aria-label="Loading ShadowPortX">
      <AuthGlow />
      <div className="spx-splash-stage">
        <div className="spx-splash-rings" aria-hidden="true">
          <span className="spx-splash-ring spx-splash-ring-1" />
          <span className="spx-splash-ring spx-splash-ring-2" />
          <span className="spx-splash-sweep" />
        </div>
        <div className="spx-splash-mark">
          <Logo size={92} />
        </div>
      </div>
      <div className="spx-splash-word h-display gradient-text gradient-text-animated">ShadowPortX</div>
      <div className="spx-splash-tag">Attack Surface Intelligence</div>
      <div className="spx-splash-progress" aria-hidden="true"><span /></div>
    </div>
  );
}

// Shared soft radial glow used by the splash and the auth screen.
function AuthGlow() {
  return <div className="spx-auth-glow" aria-hidden="true" />;
}
