import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App.jsx";
import "./index.css";

// Capture the SSO token handed back in the URL fragment by /auth/oidc/callback.
try {
  const frag = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  const ssoToken = frag.get("spx_token");
  if (ssoToken) {
    localStorage.setItem("spx_token", ssoToken);
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
  }
} catch {
  /* ignore */
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);
