import { endpoints } from "../api";
import { useFetch } from "../lib/useFetch";
import { Card, StatCard, PageHeader, Spinner, ErrorNote, Empty, Pill } from "../components/ui";
import { fmtTime, fmtRelative, titleCase } from "../lib/format";

const ROLE_TONE = { owner: "primary", admin: "primary", analyst: "ok", developer: "warn", viewer: "muted" };

function RoleBadge({ role }) {
  return <Pill tone={ROLE_TONE[role] || "muted"}>{titleCase(role)}</Pill>;
}

function ActionLabel({ action }) {
  const map = {
    "auth.login": "Signed in",
    "auth.register": "Created account",
    "scan.created": "Started a scan",
    "scan.completed": "Completed a scan",
  };
  return <span>{map[action] || titleCase(action.replace(/\./g, " "))}</span>;
}

export default function Admin() {
  const { data: ov, loading, error } = useFetch(() => endpoints.adminOverview(), [], { pollMs: 15000 });
  const { data: users } = useFetch(() => endpoints.adminUsers(), []);

  if (loading && !ov) return <Spinner label="Loading admin console…" />;
  if (error) return <ErrorNote error={error} />;

  const roleEntries = Object.entries(ov.users_by_role || {}).sort((a, b) => b[1] - a[1]);

  return (
    <div>
      <PageHeader
        title="Admin Console"
        subtitle="Who is using the platform, what they're doing, and how adoption is trending — visible to owners and admins only."
      />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-3">
        <StatCard label="Users" value={ov.users_total} sub={`${ov.users_active} active · ${ov.new_users_7d} new (7d)`} />
        <StatCard label="Sign-ins (7d)" value={ov.logins_7d} sub="authentication events" accent="#22d3ee" />
        <StatCard label="Scans run" value={ov.scans_total} sub={`${ov.scans_active} running now`} />
        <StatCard label="Open findings" value={ov.open_findings} sub={`${ov.findings_total} total · ${ov.assets_total} assets`} accent={ov.open_findings ? "#fb923c" : "#34d399"} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        {/* Users roster */}
        <Card className="p-0 lg:col-span-2 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <div className="text-sm font-medium text-text">Users</div>
            <div className="flex flex-wrap gap-1.5">
              {roleEntries.map(([role, n]) => (
                <Pill key={role} tone={ROLE_TONE[role] || "muted"}>{titleCase(role)} · {n}</Pill>
              ))}
            </div>
          </div>
          {!users ? (
            <div className="p-4"><Spinner label="Loading users…" /></div>
          ) : users.length === 0 ? (
            <Empty title="No users yet" />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead><tr>
                  <th className="th">User</th>
                  <th className="th">Role</th>
                  <th className="th">Status</th>
                  <th className="th hidden md:table-cell">Joined</th>
                  <th className="th">Last active</th>
                </tr></thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id} className="hover:bg-surface-2/60">
                      <td className="td">
                        <div className="flex items-center gap-2.5">
                          <span className="spx-avatar" aria-hidden="true">{(u.email[0] || "?").toUpperCase()}</span>
                          <div className="min-w-0">
                            <div className="text-text truncate">{u.full_name || u.email.split("@")[0]}</div>
                            <div className="text-[11px] text-faint truncate">{u.email}</div>
                          </div>
                        </div>
                      </td>
                      <td className="td"><RoleBadge role={u.role} /></td>
                      <td className="td">
                        <span className="inline-flex items-center gap-1.5">
                          <span className={`h-1.5 w-1.5 rounded-full ${u.is_active ? "bg-ok" : "bg-faint"}`} />
                          <span className="text-xs text-muted">{u.is_active ? "Active" : "Disabled"}</span>
                        </span>
                      </td>
                      <td className="td hidden md:table-cell text-muted text-xs">{fmtTime(u.created_at)}</td>
                      <td className="td text-muted text-xs">{u.last_active_at ? fmtRelative(u.last_active_at) : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        {/* Activity feed */}
        <Card className="p-0 overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <div className="text-sm font-medium text-text">Recent activity</div>
            <span className="text-[10px] text-faint uppercase tracking-wide">live</span>
          </div>
          <div className="divide-y divide-border/70 max-h-[520px] overflow-y-auto">
            {(ov.recent_activity || []).length === 0 ? (
              <Empty title="No activity yet" hint="Sign-ins and scans will appear here." />
            ) : ov.recent_activity.map((a, i) => (
              <div key={i} className="px-4 py-2.5">
                <div className="flex items-center gap-2">
                  <span className="text-sm text-text truncate"><ActionLabel action={a.action} /></span>
                  <span className="text-[10px] text-faint ml-auto shrink-0">{fmtRelative(a.ts)}</span>
                </div>
                <div className="text-[11px] text-faint truncate">{a.actor}{a.target && a.target !== a.actor ? ` → ${a.target}` : ""}</div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
