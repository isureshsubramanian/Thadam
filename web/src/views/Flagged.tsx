// Flagged queue (mock-up view 2) as a grid (ADR-014 Decision 5): one row per grouped item,
// newest first; tick one or more and Mark reviewed / Reopen them together. These are the
// API's only domain writes (ADR-008 Decision 7). Commit actions carry text labels.
import { Check, ExternalLink, RotateCcw } from "lucide-react";
import { useState } from "react";
import { api, AuditUnavailable, SignedOut } from "../api/client";
import type { FlagItem, Severity } from "../api/schemas";
import { cap, count, num, ruleTitle, utc, when, words, zone } from "../app/format";
import { GridSearch, Pager } from "../app/grid";
import type { TimeRange } from "../app/range";
import { go } from "../app/route";
import { useSignedOut } from "../app/session";
import { Empty, IconButton, Loading, PageHead, SeverityPill } from "../app/ui";
import { usePaged } from "../app/usePaged";

type Status = "open" | "reviewed";
const severities: (Severity | undefined)[] = [undefined, "high", "medium", "low"];

/** Session ids are time-ordered, so the random tail tells neighbours apart; the full id is in the title. */
const shortId = (id: string): string => (id.length > 12 ? `…${id.slice(-12)}` : id);

function Row({ f, selected, reviewed, onToggle }: { f: FlagItem; selected: boolean; reviewed: boolean; onToggle: () => void }) {
  const what = ruleTitle[f.rule] ?? words(f.rule);
  return (
    <tr className={selected ? "sel" : undefined}>
      <td className="pick">
        <input type="checkbox" checked={selected} onChange={onToggle} aria-label={`Select: ${what}, ${f.target || "no target"}`} />
      </td>
      <td><SeverityPill severity={f.severity} /></td>
      <td className="what">{what}</td>
      <td className="cut"><code className="mono" title={f.target}>{f.target || "(no target)"}</code></td>
      <td>{f.displayName}</td>
      <td>{f.sessionId === null ? <span className="muted">none</span> : <span className="mono" title={f.sessionId}>{shortId(f.sessionId)}</span>}</td>
      <td title={utc(f.last)}>{when(f.last)}</td>
      <td className="num">{num(f.rows)}</td>
      <td className="num">{num(f.count)}</td>
      {reviewed && (
        <td title={f.reviewedAt === null ? undefined : utc(f.reviewedAt)}>
          {f.reviewedBy === null ? <span className="muted">unknown</span> : <>{f.reviewedBy}{f.reviewedAt !== null && <span className="muted"> · {when(f.reviewedAt)}</span>}</>}
        </td>
      )}
      <td className="act">
        {f.sessionId !== null && (
          <IconButton label={`Open session ${f.sessionId} timeline`} onClick={() => { go({ view: "sessions", sessionId: f.sessionId ?? undefined }); }}>
            <ExternalLink className="ic" aria-hidden="true" />
          </IconButton>
        )}
      </td>
    </tr>
  );
}

export function Flagged({ range, onChanged }: { range: TimeRange; onChanged: () => void }) {
  const signedOut = useSignedOut();
  const [status, setStatus] = useState<Status>("open");
  const [severity, setSeverity] = useState<Severity>();
  const [q, setQ] = useState("");
  const [picked, setPicked] = useState<{ key: string; ids: ReadonlySet<string> }>({ key: "", ids: new Set() });
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ text: string; error: boolean }>();
  const { from, to } = range;
  const page = usePaged(
    (after, signal) => api.flags({ from, to, status, severity, q, after }, signal),
    [from, to, status, severity, q],
  );
  // Selection belongs to the rows on screen: a new page, tab or search clears it.
  const key = JSON.stringify([range.from, range.to, status, severity, q, page.index]);
  const items = page.items ?? [];
  const selected = picked.key === key ? picked.ids : new Set<string>();
  const onPage = items.filter((f) => selected.has(f.eventId));
  const all = items.length > 0 && onPage.length === items.length;

  const toggle = (id: string) => {
    const next = new Set(selected);
    if (!next.delete(id)) next.add(id);
    setPicked({ key, ids: next });
  };
  const toggleAll = () => { setPicked({ key, ids: all ? new Set() : new Set(items.map((f) => f.eventId)) }); };

  const reviewing = status === "open";
  const act = () => {
    // An event can head two groups (two rules); its review covers both, so send it once.
    const ids = [...new Set(onPage.map((f) => f.eventId))];
    setBusy(true);
    setNote(undefined);
    api.reviewMany(ids, reviewing).then(
      (n) => {
        setBusy(false);
        setPicked({ key, ids: new Set() });
        setNote({ text: `${count(n, "flag")} ${reviewing ? "marked reviewed" : "reopened"}`, error: false });
        page.reload();
        onChanged();
      },
      (e: unknown) => {
        setBusy(false);
        if (e instanceof SignedOut) {
          signedOut();
          return;
        }
        setNote({ text: e instanceof AuditUnavailable ? e.message : "That did not save. Try again.", error: true });
        page.reload(); // show what the server holds now
      },
    );
  };

  return (
    <div className="stack">
      <PageHead title="Flagged for review" sub="Grouped by what happened, newest first. Reviewing covers activity up to the newest row; new activity reopens it." />
      <div className="row tabs" role="group" aria-label="Status">
        {(["open", "reviewed"] as const).map((s) => (
          <button key={s} type="button" className={`tab${status === s ? " on" : ""}`} aria-pressed={status === s} onClick={() => { setStatus(s); setNote(undefined); }}>
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
      <section className="card">
        <div className="cardhead toolbar">
          <button type="button" className={`btn${reviewing ? " primary" : ""}`} disabled={busy || onPage.length === 0} onClick={act}>
            {reviewing ? <Check className="ic" aria-hidden="true" /> : <RotateCcw className="ic" aria-hidden="true" />}
            {reviewing ? "Mark reviewed" : "Reopen"}{onPage.length > 0 ? ` (${num(onPage.length)})` : ""}
          </button>
          {note && <span className={`small ${note.error ? "error" : "muted"}`} role="status">{note.text}</span>}
          <span className="spacer" />
          <GridSearch label="Search flagged items" placeholder="Path, host, tool or session" onSearch={setQ} />
        </div>
        {page.items === undefined ? (
          page.loading && <Loading />
        ) : items.length === 0 ? (
          <Empty>{q !== "" ? "Nothing matches." : reviewing ? "Nothing open in this range." : "Nothing reviewed in this range."}</Empty>
        ) : (
          <div className="scroll">
            <table className="tbl flags">
              <thead>
                <tr>
                  <th className="pick"><input type="checkbox" checked={all} onChange={toggleAll} aria-label="Select every row on this page" /></th>
                  <th>Severity</th>
                  <th>What</th>
                  <th>Target</th>
                  <th>Tool</th>
                  <th>Session</th>
                  <th>Last ({zone})</th>
                  <th className="num">Rows</th>
                  <th className="num">Events</th>
                  {!reviewing && <th>Reviewed by</th>}
                  <th><span className="vh">Open</span></th>
                </tr>
              </thead>
              <tbody>
                {items.map((f) => <Row key={`${f.rule} ${f.eventId}`} f={f} selected={selected.has(f.eventId)} reviewed={!reviewing} onToggle={() => { toggle(f.eventId); }} />)}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <Pager page={page} />
    </div>
  );
}
