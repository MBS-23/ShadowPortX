import axios from "axios";

// In dev, Vite proxies /api to the FastAPI backend (see vite.config.js). In production
// (e.g. Vercel frontend + separately hosted backend), set VITE_API_BASE to the backend URL,
// e.g. "https://api.example.com/api/v1". A JWT, if present, is attached automatically.
const api = axios.create({ baseURL: import.meta.env.VITE_API_BASE || "/api/v1" });

const TOKEN_KEY = "spx_token";
export const getToken = () => {
  try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
};
export const setToken = (t) => {
  try { localStorage.setItem(TOKEN_KEY, t); } catch { /* private mode */ }
};
export const clearToken = () => {
  try { localStorage.removeItem(TOKEN_KEY); } catch { /* private mode */ }
};

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// If a *previously authenticated* request comes back 401, the session has expired or the
// token is invalid. Clear it and let the app fall back to the sign-in screen — this prevents
// the dashboard from getting stuck refetching behind an "Authentication required" wall.
// Bad-credential 401s from /login carry no Authorization header, so they never trigger this.
api.interceptors.response.use(
  (r) => r,
  (error) => {
    const hadAuth = Boolean(error?.config?.headers?.Authorization);
    if (error?.response?.status === 401 && hadAuth) {
      clearToken();
      try { window.dispatchEvent(new Event("spx:auth-expired")); } catch { /* SSR/no-window */ }
    }
    return Promise.reject(error);
  }
);

export const endpoints = {
  overview: () => api.get("/overview").then((r) => r.data),
  scans: () => api.get("/scans").then((r) => r.data),
  scan: (id) => api.get(`/scans/${id}`).then((r) => r.data),
  createScan: (body) => api.post("/scans", body).then((r) => r.data),
  assets: (params) => api.get("/assets", { params }).then((r) => r.data),
  asset: (id) => api.get(`/assets/${id}`).then((r) => r.data),
  updateAsset: (id, body) => api.patch(`/assets/${id}`, body).then((r) => r.data),
  findings: (params) => api.get("/findings", { params }).then((r) => r.data),
  finding: (id) => api.get(`/findings/${id}`).then((r) => r.data),
  updateFinding: (id, body) => api.patch(`/findings/${id}`, body).then((r) => r.data),
  verifyFinding: (id) => api.post(`/findings/${id}/verify`).then((r) => r.data),
  validateFinding: (id) => api.post(`/findings/${id}/validate`).then((r) => r.data),
  changes: (params) => api.get("/changes", { params }).then((r) => r.data),
  scope: () => api.get("/scope").then((r) => r.data),
  addScope: (body) => api.post("/scope", body).then((r) => r.data),
  deleteScope: (id) => api.delete(`/scope/${id}`),
  login: (body) => api.post("/auth/login", body).then((r) => r.data),
  register: (body) => api.post("/auth/register", body).then((r) => r.data),
  me: () => api.get("/auth/me").then((r) => r.data),
  authConfig: () => api.get("/auth/config").then((r) => r.data),
  oidcLoginUrl: () => `${import.meta.env.VITE_API_BASE || "/api/v1"}/auth/oidc/login`,
  // inventory + risk + monitoring
  services: () => api.get("/services").then((r) => r.data),
  technologies: () => api.get("/technologies").then((r) => r.data),
  vulnerabilities: () => api.get("/vulnerabilities").then((r) => r.data),
  risk: () => api.get("/risk").then((r) => r.data),
  compareScans: (a, b) => api.get(`/scans/${a}/compare/${b}`).then((r) => r.data),
  schedules: () => api.get("/schedules").then((r) => r.data),
  createSchedule: (body) => api.post("/schedules", body).then((r) => r.data),
  toggleSchedule: (id) => api.post(`/schedules/${id}/toggle`).then((r) => r.data),
  deleteSchedule: (id) => api.delete(`/schedules/${id}`),
  channels: () => api.get("/notifications").then((r) => r.data),
  addChannel: (body) => api.post("/notifications", body).then((r) => r.data),
  testChannel: (id) => api.post(`/notifications/${id}/test`).then((r) => r.data),
  deleteChannel: (id) => api.delete(`/notifications/${id}`),
  // 2.5 intelligence layer
  assetGraph: (id) => api.get(`/graph/assets/${id}`).then((r) => r.data),
  blastRadius: (params) => api.get("/graph/blast-radius", { params }).then((r) => r.data),
  trends: () => api.get("/trends").then((r) => r.data),
  // admin console (owner/admin only)
  adminOverview: () => api.get("/admin/overview").then((r) => r.data),
  adminUsers: () => api.get("/admin/users").then((r) => r.data),
  adminActivity: (limit = 50) => api.get("/admin/activity", { params: { limit } }).then((r) => r.data),
  adminUpdateUser: (id, body) => api.patch(`/admin/users/${id}`, body).then((r) => r.data),
  // 3.0 engagement workspace
  engagements: () => api.get("/engagements").then((r) => r.data),
  engagement: (id) => api.get(`/engagements/${id}`).then((r) => r.data),
  createEngagement: (body) => api.post("/engagements", body).then((r) => r.data),
  updateEngagement: (id, body) => api.patch(`/engagements/${id}`, body).then((r) => r.data),
  deleteEngagement: (id) => api.delete(`/engagements/${id}`),
};

export default api;
