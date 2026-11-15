// The Export CSV action (ADR-012): fetches the file, then hands it to the browser to save.
// A primary action, so it carries a text label beside its icon (global UI rule).
import { Download } from "lucide-react";
import { useState } from "react";
import { api, AuditUnavailable, Rejected, SignedOut, TooMany, type ExportSource } from "../api/client";
import { num } from "./format";
import { useSignedOut } from "./session";

function message(e: unknown): string {
  if (e instanceof AuditUnavailable) return e.message;
  if (e instanceof TooMany) {
    const n = e.rows === null ? "More than" : `${num(e.rows)} rows match;`;
    return `${n} the limit is ${num(e.limit)}. Narrow the time range or add a filter.`;
  }
  if (e instanceof Rejected) return "Fix the search first: Thadam cannot export it.";
  return "The export failed. Try again.";
}

function save({ blob, fileName }: { blob: Blob; fileName: string }) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); }, 0);
}

export function ExportButton({ source }: { source: ExportSource }) {
  const signedOut = useSignedOut();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const run = async () => {
    setBusy(true);
    setError(undefined);
    try {
      save(await api.exportCsv(source));
    } catch (e) {
      if (e instanceof SignedOut) {
        signedOut();
        return;
      }
      setError(message(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <span className="row">
      <button type="button" className="btn" onClick={() => { void run(); }} disabled={busy} aria-busy={busy}
        title="Export these rows as CSV (audit logged)">
        <Download className="ic" aria-hidden="true" />
        {busy ? "Exporting…" : "Export CSV"}
      </button>
      {error !== undefined && <span className="sub error" role="alert">{error}</span>}
    </span>
  );
}
