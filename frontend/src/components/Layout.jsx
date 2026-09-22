import { NavLink } from "react-router-dom";

const IconBase = ({ children }) => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{children}</svg>
);
const icons = {
  overview: <IconBase><rect x="3" y="3" width="7" height="9" rx="1" /><rect x="14" y="3" width="7" height="5" rx="1" /><rect x="14" y="12" width="7" height="9" rx="1" /><rect x="3" y="16" width="7" height="5" rx="1" /></IconBase>,
  assets: <IconBase><path d="M4 7 12 3l8 4v10l-8 4-8-4z" /><path d="M4 7l8 4 8-4M12 11v10" /></IconBase>,
  findings: <IconBase><path d="M12 2 3 7v6c0 5 3.8 8 9 9 5.2-1 9-4 9-9V7z" /><path d="M12 8v4M12 16h.01" /></IconBase>,
  changes: <IconBase><path d="M21 2v6h-6M3 12a9 9 0 0 1 15-6.7L21 8M3 22v-6h6M21 12a9 9 0 0 1-15 6.7L3 16" /></IconBase>,
  scans: <IconBase><circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3M11 8v6M8 11h6" /></IconBase>,
  scope: <IconBase><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="4" /><path d="M12 3v3M12 18v3M3 12h3M18 12h3" /></IconBase>,
  reports: <IconBase><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" /><path d="M14 3v6h6M8 13h8M8 17h6" /></IconBase>,
  services: <IconBase><rect x="3" y="4" width="18" height="6" rx="1" /><rect x="3" y="14" width="18" height="6" rx="1" /><path d="M7 7h.01M7 17h.01" /></IconBase>,
  technologies: <IconBase><path d="M12 2 2 7l10 5 10-5z" /><path d="M2 17l10 5 10-5M2 12l10 5 10-5" /></IconBase>,
  vulns: <IconBase><path d="m12 2 9 4v6c0 5-3.8 8-9 10-5.2-2-9-5-9-10V6z" /><path d="M12 8v4M12 16h.01" /></IconBase>,
  risk: <IconBase><path d="M3 3v18h18" /><path d="m19 9-5 5-4-4-4 4" /></IconBase>,
  monitoring: <IconBase><path d="M3 12h4l3 8 4-16 3 8h4" /></IconBase>,
  integrations: <IconBase><path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1" /><path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1" /></IconBase>,
  graph: <IconBase><circle cx="5" cy="6" r="2.5" /><circle cx="19" cy="6" r="2.5" /><circle cx="12" cy="18" r="2.5" /><path d="M7 7 10.5 16M17 7 13.5 16M7.3 6h9.4" /></IconBase>,
  trends: <IconBase><path d="M3 3v18h18" /><path d="m7 14 3-4 3 3 5-7" /></IconBase>,
};

const NAV = [
  ["/", "Overview", "overview"],
  ["/assets", "Assets", "assets"],
  ["/services", "Services", "services"],
  ["/technologies", "Technologies", "technologies"],
  ["/vulnerabilities", "Vulnerabilities", "vulns"],
  ["/findings", "Findings", "findings"],
  ["/changes", "Changes", "changes"],
  ["/graph", "Asset Graph", "graph"],
  ["/risk", "Risk", "risk"],
  ["/trends", "Trends", "trends"],
  ["/scans", "Scan History", "scans"],
  ["/monitoring", "Monitoring", "monitoring"],
  ["/integrations", "Integrations", "integrations"],
  ["/scope", "Scope", "scope"],
  ["/reports", "Reports", "reports"],
];

export default function Layout({ children }) {
  return (
    <div className="min-h-screen flex bg-bg">
      <aside className="sticky top-0 h-screen shrink-0 w-16 md:w-60 border-r border-border bg-surface/60 backdrop-blur flex flex-col">
        <div className="h-14 flex items-center gap-2.5 px-3 md:px-4 border-b border-border">
          <div className="h-8 w-8 rounded-lg grid place-items-center bg-primary/15 border border-primary/30 shrink-0">
            <span className="text-primary font-bold text-sm">S</span>
          </div>
          <div className="hidden md:block leading-tight">
            <div className="font-semibold text-sm text-text">ShadowPortX</div>
            <div className="text-[10px] text-faint tracking-wide">ASM · v2.5</div>
          </div>
        </div>
        <nav className="flex-1 p-2 space-y-1 overflow-y-auto">
          {NAV.map(([to, label, icon]) => (
            <NavLink key={to} to={to} end={to === "/"}
              className={({ isActive }) => `nav-link ${isActive ? "nav-link-active" : ""} justify-center md:justify-start`}
              title={label}>
              {icons[icon]}
              <span className="hidden md:inline">{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="p-3 border-t border-border hidden md:block">
          <div className="text-[10px] text-faint leading-relaxed">
            Authorized assessment only. Non-destructive verification · correlation, not exploitation.
          </div>
        </div>
      </aside>

      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-14 border-b border-border bg-surface/40 backdrop-blur sticky top-0 z-10 flex items-center justify-between px-4 md:px-6">
          <div className="text-sm text-muted">Attack Surface Intelligence &amp; Exposure Management</div>
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-ok animate-pulse" />
            <span className="text-xs text-muted">API connected</span>
          </div>
        </header>
        <main className="flex-1 p-4 md:p-6 max-w-[1400px] w-full mx-auto">{children}</main>
      </div>
    </div>
  );
}
