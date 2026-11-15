// Search (mock-up view 4). Free text and field:value terms (ADR-008 Decision 5); the
// first page brings a summary and the hosts for the same tool, project and time.
import { Search as SearchIcon } from "lucide-react";
import { useState, type SubmitEvent } from "react";
import { api, Rejected } from "../api/client";
import { EventTable } from "../app/events";
import { ExportButton } from "../app/ExportButton";
import { bytes, count, num } from "../app/format";
import { go } from "../app/route";
import { Empty, HostFlag, Loading, PageHead } from "../app/ui";
import { usePaged } from "../app/usePaged";

const examples = [
  { label: "What did it touch, where did it connect", q: "outside:sample-app since:7d" },
  { label: "Refused actions", q: "outcome:denied since:30d" },
  { label: "Unknown hosts", q: "flag:unknown-host since:30d" },
];

/** Field names the API can reject, as words; never the text typed. */
function rejection(fields: string[]): string {
  const f = fields[0] ?? "q";
  if (f === "q.unknown") return "That search uses a field name Thadam does not know. Quote text that contains a colon.";
  if (f.startsWith("q.")) return `Check the ${f.slice(2)}: value.`;
  return "Check the search text: it is empty, too long or has an unclosed quote.";
}

function Results({ q }: { q: string }) {
  const [summary, setSummary] = useState<Awaited<ReturnType<typeof api.search>>>();
  const [rejected, setRejected] = useState<string[]>();
  const page = usePaged(
    async (after, signal) => {
      try {
        const r = await api.search(q, after, signal);
        if (after === null) setSummary(r);
        return { items: r.items, next: r.next };
      } catch (e) {
        if (e instanceof Rejected) {
          setRejected(e.fields);
          return { items: [], next: null };
        }
        throw e;
      }
    },
    [q],
  );
  if (rejected !== undefined) return <p className="card pad error" role="alert">{rejection(rejected)}</p>;
  if (page.items === undefined) return page.loading ? <Loading /> : null;
  const s = summary?.summary;
  const hosts = summary?.hosts ?? [];
  return (
    <div className="stack">
      {s && (
        <div className="kpis three">
          <div className="card kpi static">
            <span className="kl">Touched outside the project</span>
            <span className="kv">{num(s.outsideFolders.reduce((n, f) => n + f.records, 0))}</span>
            <span className="ks">records in {count(s.outsideFolders.length, "folder")}</span>
          </div>
          <div className="card kpi static">
            <span className="kl">Connected to</span>
            <span className="kv">{count(hosts.length, "host")}</span>
            <span className="ks">{num(hosts.filter((h) => h.unknown).length)} unknown</span>
          </div>
          <div className="card kpi static">
            <span className="kl">Needs a look</span>
            <span className="kv">{num(s.flagged)}</span>
            <span className="ks">flagged {s.flagged === 1 ? "row" : "rows"} among {count(s.rows, "match", "matches")}</span>
          </div>
        </div>
      )}
      {summary?.partial === true && <p className="sub">Many rows match: the summary covers the newest of them.</p>}
      {hosts.length > 0 && (
        <section className="card pad">
          <h2 className="h2">Hosts for the same tool, project and time</h2>
          <ul className="hosts scrollbox" tabIndex={0} aria-label="Hosts for the same tool, project and time">
            {hosts.map((h) => (
              <li key={`${h.target} ${h.category}`}>
                <span className="mono clip">{h.target}</span>
                <HostFlag host={h} />
                <span className="muted numv">{count(h.flows, "flow")} · ↑ {bytes(h.bytesOut)} · ↓ {bytes(h.bytesIn)}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
      {page.items.length > 0 && <div className="row"><ExportButton source={{ q }} /></div>}
      <section className="card">
        {page.items.length === 0 ? <Empty>No rows match.</Empty> : <EventTable events={page.items} showTool showDay />}
      </section>
      {page.more && <button type="button" className="btn" onClick={page.more}>Load more</button>}
    </div>
  );
}

export function Search({ q }: { q?: string | undefined }) {
  const [text, setText] = useState(q ?? "");
  const submit = (e: SubmitEvent<HTMLFormElement>) => {
    e.preventDefault();
    go({ view: "search", q: text.trim() || undefined });
  };
  return (
    <div className="stack">
      <PageHead
        title="Search"
        sub="Full-text and field search over every kept record. Searches are audit logged (time and outcome; not the query or its results)."
      />
      <form className="row searchbar" onSubmit={submit} role="search">
        <label htmlFor="q" className="vh">Search records</label>
        <span className="fieldwrap">
          <SearchIcon className="ic" aria-hidden="true" />
          <input id="q" className="field mono" type="search" value={text} maxLength={512} spellCheck={false}
            placeholder='e.g. tool:"CLI agent" outside:sample-app since:7d' onChange={(e) => { setText(e.target.value); }} />
        </span>
        <button type="submit" className="btn primary"><SearchIcon className="ic" aria-hidden="true" />Search</button>
      </form>
      <p className="sub">
        Fields: tool, session, project, outside, category, action, outcome, flag, host, since (7d, 24h), from, to. Words of 3 or more characters use the index.
      </p>
      <div className="row">
        {examples.map((x) => (
          <button key={x.q} type="button" className="pill acc chip" onClick={() => { setText(x.q); go({ view: "search", q: x.q }); }}>
            {x.label}
          </button>
        ))}
      </div>
      {q !== undefined && q !== "" && <Results key={q} q={q} />}
    </div>
  );
}
