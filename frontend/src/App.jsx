import { useEffect, useState } from "react";
import { Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import { Spinner } from "./components/ui";
import { endpoints } from "./api";
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

function AuthGate({ children }) {
  const [state, setState] = useState("checking");
  useEffect(() => {
    endpoints
      .me()
      .then(() => setState("ok"))
      .catch((e) => setState(e?.response?.status === 401 ? "login" : "ok"));
  }, []);
  if (state === "checking")
    return <div className="min-h-screen grid place-items-center bg-bg"><Spinner label="Connecting to ShadowPortX…" /></div>;
  if (state === "login") return <Login onSuccess={() => setState("ok")} />;
  return children;
}

export default function App() {
  return (
    <AuthGate>
      <Layout>
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
        </Routes>
      </Layout>
    </AuthGate>
  );
}
