import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App, storedTheme } from "./app/App";
import { ErrorBoundary } from "./app/ErrorBoundary";
import "./styles.css";

// Before the first paint, so a saved theme doesn't flash the other one on load.
const saved = storedTheme();
if (saved !== undefined) document.documentElement.dataset["theme"] = saved;

const root = document.getElementById("root");
if (root === null) throw new Error("no root element");
createRoot(root).render(
  <StrictMode>
    <ErrorBoundary area="shell" fallback={<p role="alert">Thadam failed to load. Reload the page to try again.</p>}>
      <App />
    </ErrorBoundary>
  </StrictMode>,
);
