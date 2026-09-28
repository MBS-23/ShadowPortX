import { useEffect, useRef } from "react";

/**
 * Living attack-surface backdrop for the sign-in screen: a network of nodes and edges that
 * drifts slowly and reacts to the pointer (nearby nodes link to the cursor and lean toward it),
 * rendered on a single canvas. It is purely decorative (aria-hidden) and imperative — it never
 * triggers a React re-render. Under prefers-reduced-motion it paints one calm static frame and
 * stops; it also pauses when the tab is hidden to save CPU.
 */
export default function AuthBackground() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const reduce =
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const CYAN = "34, 211, 238";
    const VIOLET = "139, 124, 255";
    const LINK_DIST = 132; // px between nodes that still get an edge
    const MOUSE_DIST = 200; // px around the cursor that lights nodes up

    let width = 0;
    let height = 0;
    let dpr = Math.min(window.devicePixelRatio || 1, 2);
    let nodes = [];
    let raf = 0;
    const mouse = { x: -9999, y: -9999, active: false };

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      width = rect.width;
      height = rect.height;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.max(1, Math.floor(width * dpr));
      canvas.height = Math.max(1, Math.floor(height * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      // Scale node count to area, but keep it bounded for performance.
      const target = Math.round(Math.min(74, Math.max(26, (width * height) / 16000)));
      nodes = Array.from({ length: target }, () => ({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.22,
        vy: (Math.random() - 0.5) * 0.22,
        r: Math.random() * 1.6 + 1,
        violet: Math.random() < 0.42,
      }));
    };

    const draw = () => {
      ctx.clearRect(0, 0, width, height);

      // Edges first (behind the nodes).
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist = Math.hypot(dx, dy);
          if (dist < LINK_DIST) {
            const alpha = (1 - dist / LINK_DIST) * 0.22;
            ctx.strokeStyle = `rgba(${a.violet || b.violet ? VIOLET : CYAN}, ${alpha})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }

      // Nodes + pointer links.
      for (const n of nodes) {
        let lit = 0;
        if (mouse.active) {
          const dist = Math.hypot(n.x - mouse.x, n.y - mouse.y);
          if (dist < MOUSE_DIST) {
            lit = 1 - dist / MOUSE_DIST;
            // Link the node to the cursor and lean it gently inward.
            ctx.strokeStyle = `rgba(${n.violet ? VIOLET : CYAN}, ${lit * 0.5})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(n.x, n.y);
            ctx.lineTo(mouse.x, mouse.y);
            ctx.stroke();
            n.vx += ((mouse.x - n.x) / dist) * 0.015 * lit;
            n.vy += ((mouse.y - n.y) / dist) * 0.015 * lit;
          }
        }
        const color = n.violet ? VIOLET : CYAN;
        const glow = n.r + lit * 2.5;
        if (lit > 0) {
          ctx.shadowBlur = 12 * lit;
          ctx.shadowColor = `rgba(${color}, 0.9)`;
        }
        ctx.fillStyle = `rgba(${color}, ${0.55 + lit * 0.45})`;
        ctx.beginPath();
        ctx.arc(n.x, n.y, glow, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    };

    const step = () => {
      for (const n of nodes) {
        n.x += n.vx;
        n.y += n.vy;
        // Gentle friction keeps pointer-induced motion from accumulating.
        n.vx *= 0.99;
        n.vy *= 0.99;
        // Keep a minimum drift so the field never freezes.
        if (Math.abs(n.vx) < 0.04) n.vx += (Math.random() - 0.5) * 0.03;
        if (Math.abs(n.vy) < 0.04) n.vy += (Math.random() - 0.5) * 0.03;
        if (n.x < 0 || n.x > width) n.vx *= -1;
        if (n.y < 0 || n.y > height) n.vy *= -1;
        n.x = Math.max(0, Math.min(width, n.x));
        n.y = Math.max(0, Math.min(height, n.y));
      }
      draw();
      raf = requestAnimationFrame(step);
    };

    const onMove = (e) => {
      const rect = canvas.getBoundingClientRect();
      mouse.x = e.clientX - rect.left;
      mouse.y = e.clientY - rect.top;
      mouse.active = true;
    };
    const onLeave = () => { mouse.active = false; mouse.x = -9999; mouse.y = -9999; };
    const onVisibility = () => {
      cancelAnimationFrame(raf);
      if (!document.hidden && !reduce) raf = requestAnimationFrame(step);
    };

    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerdown", onMove);
    document.addEventListener("visibilitychange", onVisibility);

    if (reduce) {
      draw(); // one calm static frame, no loop
    } else {
      raf = requestAnimationFrame(step);
    }

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerdown", onMove);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  return (
    <div className="spx-auth-bg" aria-hidden="true">
      <canvas ref={canvasRef} className="spx-auth-canvas" />
      <div className="spx-auth-vignette" />
    </div>
  );
}
