// Sessions list and session timeline (mock-up view 3), with delegated child sessions.
// Prompt rows and other rows the tool reports come from its hook (ADR-011 Decision 6).
import { useState } from "react";
import { api, Rejected } from "../api/client";
import type { Session } from "../api/schemas";
import { OsOnly, TimelineCoverage } from "../app/coverage";
import { EventTable } from "../app/events";
import { freeTerms } from "../app/highlight";
import { ExportButton } from "../app/ExportButton";
import { num, utc, when } from "../app/format";
import type { TimeRange } from "../app/range";
import { href } from "../app/route";
import { Empty, Loading, PageHead } from "../app/ui";
import { GridSearch, Pager } from "../app/grid";
import { usePaged } from "../app/usePaged";
import { rejection } from "./Search";

/** Session ids are time-ordered, so neighbours share their start; the random tail tells them apart. The full id is in the link's title. */
const shortId = (id: string): string => (id.length > 12 ? `…${id.slice(-12)}` : id);

const projectName = (p: string | null): string => (p === null ? "no project" : (p.split("/").filter(Boolean).at(-1) ?? p));

function SessionList({ range }: { range: TimeRange }) {
  const [q, setQ] = useState("");
  const page = usePaged((after, signal) => api.sessions({ ...range, q, after }, signal), [range.from, range.to, q]);
  return (
    <div className="stack">
      <PageHead title="Sessions" sub="Most recently active first" />
      <section className="card">
        <div className="cardhead">
          <GridSearch label="Search sessions" placeholder="Session id, tool or project" onSearch={setQ} />
        </div>
        <div className="scroll">
          <table className="tbl">
            <thead>
              <tr><th>Session</th><th>Tool</th><th>Project</th><th>Last active</th><th className="num">Rows</th><th className="num">Events</th></tr>
            </thead>
            <tbody>
              {page.items?.map((s) => (
                <tr key={s.sessionId}>
                  <td><a className="mono" href={href({ view: "sessions", sessionId: s.sessionId })} title={s.sessionId} aria-label={`Session ${s.sessionId}`}>{shortId(s.sessionId)}</a>{s.parentSessionId !== null && <span className="muted"> · delegated</span>}</td>
                  <td>{s.displayName} {s.prompts === 0 && <OsOnly short />}</td>
                  <td>{projectName(s.project)}</td>
                  <td title={utc(s.last)}>{when(s.last)}</td>
                  <td className="num">{num(s.rows)}</td>
                  <td className="num">{num(s.events)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {page.items === undefined && page.loading && <Loading />}
          {page.items?.length === 0 && <Empty>{q === "" ? "No sessions in this range." : "No sessions match."}</Empty>}
        </div>
      </section>
      <Pager page={page} />
    </div>
  );
}

function Child({ s }: { s: Session }) {
  return (
    <li>
      <a className="mono" href={href({ view: "sessions", sessionId: s.sessionId })}>{s.sessionId}</a>
      <span className="muted"> · {s.displayName} · {when(s.first)} · {num(s.rows)} rows</span>
    </li>
  );
}

function Timeline({ sessionId }: { sessionId: string }) {
  const [internal, setInternal] = useState(false);
  const [q, setQ] = useState("");
  const [rejected, setRejected] = useState<string[]>();
  const [head, setHead] = useState<{ session: Session; children: Session[] }>();
  const page = usePaged(
    async (after, signal) => {
      setRejected(undefined);
      if (q === "") {
        const t = await api.timeline(sessionId, { internal, after }, signal);
        setHead((h) => (after === null || h === undefined ? { session: t.session, children: t.children } : h));
        return { items: t.events, next: t.next, total: t.total, totalCapped: t.totalCapped };
      }
      // Text in the grid's box is a search scoped to this session (ADR-014 Decision 3), with the Search page's fields.
      try {
        return await api.search(`session:"${sessionId}" ${q}`, after, signal);
      } catch (e) {
        if (!(e instanceof Rejected)) throw e;
        setRejected(e.fields);
        return { items: [], next: null };
      }
    },
    [sessionId, internal, q],
  );
  const s = head?.session.sessionId === sessionId ? head.session : undefined;
  return (
    <div className="stack">
      <p className="sub"><a href={href({ view: "sessions" })}>Sessions</a> / {sessionId}</p>
      {s && (
        <PageHead
          title={`${s.displayName} · ${projectName(s.project)}`}
          sub={`${when(s.first)} to ${when(s.last)} · ${num(s.events)} events stored as ${num(s.rows)} rows`}
        />
      )}
      {s?.prompts === 0 && <OsOnly />}
      {s && <TimelineCoverage range={{ from: s.first, to: s.last }} />}
      {s?.parentSessionId != null && (
        <p className="sub">Delegated from <a className="mono" href={href({ view: "sessions", sessionId: s.parentSessionId })}>{s.parentSessionId}</a></p>
      )}
      {head && head.children.length > 0 && head.session.sessionId === sessionId && (
        <section className="card pad">
          <h2 className="h2">Delegated sessions</h2>
          <ul className="plain">{head.children.map((c) => <Child key={c.sessionId} s={c} />)}</ul>
        </section>
      )}
      <div className="row">
        <input id="internal" type="checkbox" checked={internal} onChange={(e) => { setInternal(e.target.checked); }} />
        <label htmlFor="internal">Show tool-internal activity (the tool&apos;s own state folder and helper sessions)</label>
        <ExportButton source={{ session: sessionId, internal }} />
      </div>
      <section className="card">
        <div className="cardhead">
          <GridSearch label="Search this session" placeholder='Text or fields, e.g. npm or outcome:denied' onSearch={setQ} />
        </div>
        {rejected !== undefined ? <p className="pad error" role="alert">{rejection(rejected)}</p>
          : page.items === undefined ? page.loading && <Loading />
          : page.items.length === 0 ? <Empty>{q === "" ? "No rows." : "No rows in this session match."}</Empty>
          : <EventTable events={page.items} showTool showDay highlight={freeTerms(q)} />}
      </section>
      <Pager page={page} />
    </div>
  );
}

export function Sessions({ range, sessionId }: { range: TimeRange; sessionId?: string | undefined }) {
  return sessionId === undefined ? <SessionList range={range} /> : <Timeline key={sessionId} sessionId={sessionId} />;
}
