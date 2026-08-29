import React from "react";
import ReactDOM from "react-dom/client";
import AnalysisBar from "./AnalysisBar";
import App from "./App";
import "./tokens.css";
import "./styles.css";
import "./v21.css";
import "./v03.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <div className="desktop-root">
      <AnalysisBar />
      <App />
    </div>
  </React.StrictMode>
);
