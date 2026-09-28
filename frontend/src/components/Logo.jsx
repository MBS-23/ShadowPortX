// ShadowPortX mark — inline SVG so it can be interactive (hover) and animated.
// The core "hub" pulses (live scanning), the exposed-port node blinks (discovered exposure),
// and on hover the whole mark lifts/glows. All motion is disabled under prefers-reduced-motion.
export default function Logo({ size = 32, animated = true, className = "" }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label="ShadowPortX"
      className={`spx-logo ${animated ? "" : "spx-logo-static"} ${className}`}
    >
      <rect x="1.25" y="1.25" width="45.5" height="45.5" rx="12" fill="#0B1220" />
      <rect x="1.25" y="1.25" width="45.5" height="45.5" rx="12" fill="none"
        stroke="#22D3EE" strokeOpacity="0.28" strokeWidth="1.5" />
      <g className="spx-logo-edges">
        <path d="M14 14 L34 34 M34 14 L14 34" stroke="#E5E7EB" strokeWidth="2.6" strokeLinecap="round" />
        <path d="M24 24 L34 14" stroke="#22D3EE" strokeWidth="2.6" strokeLinecap="round" />
      </g>
      <circle cx="14" cy="14" r="3" fill="#E5E7EB" />
      <circle cx="14" cy="34" r="3" fill="#E5E7EB" />
      <circle cx="34" cy="34" r="3" fill="#E5E7EB" />
      <circle className="spx-logo-port" cx="34" cy="14" r="3.4" fill="#0B1220" stroke="#22D3EE" strokeWidth="2" />
      <circle cx="24" cy="24" r="4.1" fill="#0B1220" stroke="#22D3EE" strokeWidth="2.2" />
      <circle className="spx-logo-core" cx="24" cy="24" r="1.5" fill="#22D3EE" />
    </svg>
  );
}
