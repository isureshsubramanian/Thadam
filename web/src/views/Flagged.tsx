// Flagged queue (mock-up view 2): grouped items, newest first; Mark reviewed / Reopen are
// the API's only domain writes (ADR-008 Decision 7). Commit actions carry text labels.
import { Check, ExternalLink, RotateCcw } from "lucide-react";
import { useState } from "react";
import { api, AuditUnavailable, SignedOut } from "../api/client";
import type { FlagItem, Severity } from "../api/schemas";
import { cap, count, ruleTitle, utc, when, words } from "../app/format";
import type { TimeRange } from "../app/range";
import { go } from "../app/route";
import { useSignedOut } from "../app/session";
import { Empty, IconButton, Loading, PageHead, SeverityPill } from "../app/ui";
import { usePaged } from "../app/usePaged";

type Status = "open" | "reviewed";
const severities: (Severity | undefined)[] = [undefined, "high", "medium", "low"];

function Item({ f, onChanged }: { f: FlagItem; onChanged: () => void }) {
  const signedOut = useSignedOut();
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string>();
  const act = (review: boolean) => {
    setBusy(true);
    setFailed(undefined);
    (review ? api.review(f.eventId) : api.reopen(f.eventId)).then(
      () => { setBusy(false); onChanged(); },
      (e: unknown) => {
        setBusy(false);
        if (e instanceof SignedOut) signedOut();
        else setFailed(e instanceof AuditUnavailable ? e.message : "That did not save. Try again.");
      },
    );
  };
  return (
    <article className="card flagitem">
      <div className="grow">
        <div className="row">
          <SeverityPill severity={f.severity} />
          <h2 className="h2">{ruleTitle[f.rule] ?? words(f.rule)}</h2>
        </div>
        <code className="mono target">{f.target || "(no target)"}</code>
        <div className="row meta">
          <span>{f.displayName}</span>
          {f.sessionId !== null && <span>Session {f.sessionId}</span>}
          <span title={utc(f.last)}>{when(f.last)}</span>
          <span>
            {count(f.rows, "row")} · {count(f.count, "event")}
          </span>
        </div>
        {failed && <p className="sub error" role="status">{failed}</p>}
      </div>
      <div className="row actions">
        {f.sessionId !== null && (
          <IconButton label={`Open session ${f.sessionId} timeline`} onClick={() => { go({ view: "sessions", sessionId: f.sessionId ?? undefined }); }}>
            <ExternalLink className="ic" aria-hidden="true" />
          </IconButton>
        )}
        {f.reviewed ? (
          <>
            <span className="pill ok"><Check className="ic" aria-hidden="true" />Reviewed</span>
            <button type="button" className="btn" disabled={busy} onClick={() => { act(false); }}>
              <RotateCcw className="ic" aria-hidden="true" />Reopen
            </button>
          </>
        ) : (
          <button type="button" className="btn primary" disabled={busy} onClick={() => { act(true); }}>
            <Check className="ic" aria-hidden="true" />Mark reviewed
          </button>
        )}
      </div>
    </article>
  );
}

export function Flagged({ range, onChanged }: { range: TimeRange; onChanged: () => void }) {
  const [status, setStatus] = useState<Status>("open");
  const [severity, setSeverity] = useState<Severity>();
  const page = usePaged(
    (after, signal) => api.flags({ ...range, status, severity, after }, signal),
    [range.from, range.to, status, severity],
  );
  const changed = () => { page.reload(); onChanged(); };
  return (
    <div className="stack">
      <PageHead title="Flagged for review" sub="Grouped by what happened, newest first. Reviewing covers activity up to the newest row; new activity reopens it." />
      <div className="row tabs" role="group" aria-label="Status">
        {(["open", "reviewed"] as const).map((s) => (
          <button key={s} type="button" className={`tab${status === s ? " on" : ""}`} aria-pressed={status === s} onClick={() => { setStatus(s); }}>
            {s === "open" ? "Open" : "Reviewed"}
          </button>
        ))}
        <span className="spacer" />
        {severities.map((s) => (
          <button key={s ?? "all"} type="button" className={`tab${severity === s ? " on" : ""}`} aria-pressed={severity === s} onClick={() => { setSeverity(s); }}>
            {s === undefined ? "All severities" : cap(s)}
          </button>
        ))}
      </div>
      {page.items === undefined ? (
        page.loading && <Loading />
      ) : page.items.length === 0 ? (
        <Empty>{status === "open" ? "Nothing open in this range." : "Nothing reviewed in this range."}</Empty>
      ) : (
        page.items.map((f) => <Item key={`${f.rule} ${f.eventId}`} f={f} onChanged={changed} />)
      )}
      {page.more && <button type="button" className="btn" onClick={page.more}>Load more</button>}
    </div>
  );
}
