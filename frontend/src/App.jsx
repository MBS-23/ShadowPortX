import { useCallback, useEffect, useState } from "react";
import { Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Splash from "./components/Splash";
import { endpoints, getToken, clearToken } from "./api";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import Assets from "./pages/Assets";
import AssetDetail from "./pages/AssetDetail";
import Services from "./pages/Services";
import Technologies from "./pages/Technologies";
import Vulnerabilities from "./pages/Vulnerabilities";
import Findings from "./pages/Findings";
import FindingDetail from "./pages/FindingDetail";
import Changes from "./pages/Changes";
import Graph from "./pages/Graph";
import Risk from "./pages/Risk";
import Trends from "./pages/Trends";
import Scans from "./pages/Scans";
import Engagements from "./pages/Engagements";
import EngagementDetail from "./pages/EngagementDetail";
import Monitoring from "./pages/Monitoring";
import Integrations from "./pages/Integrations";
import Scope from "./pages/Scope";
import Reports from "./pages/Reports";
import Admin from "./pages/Admin";

function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Overview />} />
      <Route path="/assets" element={<Assets />} />
      <Route path="/assets/:id" element={<AssetDetail />} />
      <Route path="/services" element={<Services />} />
      <Route path="/technologies" element={<Technologies />} />
      <Route path="/vulnerabilities" element={<Vulnerabilities />} />
      <Route path="/findings" element={<Findings />} />
      <Route path="/findings/:id" element={<FindingDetail />} />
      <Route path="/changes" element={<Changes />} />
      <Route path="/graph" element={<Graph />} />
      <Route path="/risk" element={<Risk />} />
      <Route path="/trends" element={<Trends />} />
      <Route path="/scans" element={<Scans />} />
      <Route path="/engagements" element={<Engagements />} />
      <Route path="/engagements/:id" element={<EngagementDetail />} />
      <Route path="/monitoring" element={<Monitoring />} />
      <Route path="/integrations" element={<Integrations />} />
      <Route path="/scope" element={<Scope />} />
      <Route path="/reports" element={<Reports />} />
      <Route path="/admin" element={<Admin />} />
    </Routes>
  );
}

export default function App() {
  // phase: "boot" (checking session) → "guest" (sign-in) | "authed" (app)
  const [phase, setPhase] = useState("boot");
  const [user, setUser] = useState(null);
  // The cinematic opening plays on first load and clears itself; it overlays whatever
  // resolves underneath so the reveal is smooth regardless of how fast the check returns.
  const [splashDone, setSplashDone] = useState(false);

  const check = useCallback(async () => {
    if (!getToken()) {
      setUser(null);
      setPhase("guest");
      return;
    }
    try {
      const me = await endpoints.me();
      setUser(me);
      setPhase("authed");
    } catch {
      // Any failure to validate the stored token (expired/invalid/unreachable) drops to
      // the sign-in screen rather than a broken, endlessly-refetching dashboard.
      clearToken();
      setUser(null);
      setPhase("guest");
    }
  }, []);

  useEffect(() => { check(); }, [check]);

  useEffect(() => {
    const onExpired = () => { setUser(null); setPhase("guest"); };
    window.addEventListener("spx:auth-expired", onExpired);
    return () => window.removeEventListener("spx:auth-expired", onExpired);
  }, []);

  const handleSuccess = useCallback((res) => {
    setUser(res ? { email: res.email, role: res.role, org_id: res.org_id } : null);
    setPhase("authed");
  }, []);

  const handleLogout = useCallback(() => {
    clearToken();
    setUser(null);
    setPhase("guest");
  }, []);

  const showSplash = !splashDone || phase === "boot";

  return (
    <>
      {showSplash && <Splash onDone={() => setSplashDone(true)} />}
      {phase === "guest" && <Login onSuccess={handleSuccess} />}
      {phase === "authed" && (
        <Layout user={user} onLogout={handleLogout}>
          <AppRoutes />
        </Layout>
      )}
    </>
  );
}
