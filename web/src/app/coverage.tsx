import { api } from "../api/client";
import type { Coverage, Gap } from "../api/schemas";
import { num, when, words } from "./format";
import type { TimeRange } from "./range";
import { useApi } from "./useApi";

export function gapWords(g: Gap): string {
  switch (g.reason) {
    case "not_running": return `Thadam not running${g.detail ? ` (${g.detail})` : ""}`;
    case "machine_off": return "Mac off";
    case "before_start": return "Starting after boot";
    case "dropped": return `${num(g.missed ?? 0)} events dropped by ${g.detail === "network" ? "the network extension" : "macOS"}`;
    case "paused": return `Writing paused: disk low (${num(g.missed ?? 0)} events not written)`;
    default: return words(g.reason);
  }
}

/** Whole minutes; a gap shorter than one (a quick restart) is not shown as "0 min". */
function minutes(seconds: number): string {
  return seconds < 60 ? "under 1 min" : `${num(Math.floor(seconds / 60))} min`;
}

export function CoveragePill({ data }: { data: Coverage }) {
  const gaps = data.gaps.filter(g => g.reason !== "machine_off");
  const counts = new Map<string, number>();
  for (const g of data.gaps) counts.set(g.reason, (counts.get(g.reason) ?? 0) + 1);
  const title = [...counts].map(([reason, n]) => `${words(reason)}: ${String(n)}`).join("; ");
  const droppedOnly = gaps.length > 0 && gaps.every(g => g.reason === "dropped");
  return <span className={`pill ${gaps.length === 0 ? "ok" : "flag"}`} title={title}>
    {gaps.length === 0 ? "Watching" : droppedOnly ? `Events dropped: ${num(gaps.reduce((n, g) => n + (g.missed ?? 0), 0))}` : `Not watching: ${minutes(data.notWatchedSeconds)}`}
  </span>;
}

export function HeaderCoverage({ range }: { range: TimeRange }) {
  const { data, loading } = useApi(signal => api.coverage(range, signal), [range.from, range.to]);
  return data && !loading ? <CoveragePill data={data} /> : null;
}

export function CoverageCard({ range }: { range: TimeRange }) {
  const { data, loading } = useApi(signal => api.coverage(range, signal), [range.from, range.to]);
  return <section className="card pad"><h2 className="h2">Coverage</h2>
    {data && !loading && (data.gaps.length === 0 ? <p>No gaps in this range.</p> : <ul className="plain">{[...data.gaps].reverse().map((g, i) => <li key={i}>{when(g.from)} to {when(g.to)} · {gapWords(g)}</li>)}</ul>)}
  </section>;
}

export function TimelineCoverage({ range }: { range: TimeRange }) {
  const { data, loading } = useApi(signal => api.coverage(range, signal), [range.from, range.to]);
  const gaps = data?.gaps.filter(g => g.reason !== "machine_off" && Date.parse(g.from) <= Date.parse(range.to) && Date.parse(g.to) >= Date.parse(range.from)) ?? [];
  if (loading || gaps.length === 0) return null;
  return <div role="status" className="card pad">{gaps.slice(0, 5).map((g, i) => <p key={i}>Thadam was not watching {when(g.from)} to {when(g.to)} ({gapWords(g)}): activity in that window is missing.</p>)}{gaps.length > 5 && <p>and {num(gaps.length - 5)} more</p>}</div>;
}

export function OsOnly() {
  return <span className="pill" title="The tool's hooks sent no prompts for this session: it started before the hooks were installed, the tool has no hooks, or no prompt was typed.">OS only: no prompts recorded</span>;
}
