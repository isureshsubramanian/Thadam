import { api } from "../api/client";
import type { Coverage, Gap } from "../api/schemas";
import { clock, count, day, num, span, utc, when, words, zone } from "./format";
import type { TimeRange } from "./range";
import { useApi } from "./useApi";

export function gapWords(g: Gap): string {
  switch (g.reason) {
    case "not_running": return `Thadam not running${g.detail ? ` (${g.detail})` : ""}`;
    case "machine_off": return "Mac off";
    case "before_start": return "Starting after boot";
    case "dropped": return `${num(g.missed ?? 0)} events dropped by ${g.detail === "network" ? "the network extension" : g.detail === "agent" ? "the hook socket" : "macOS"}`;
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

/** How a gap reads on the timeline: the Mac being off is expected, Thadam stopping is a warning, lost events are worse. */
type Tone = "off" | "stopped" | "dropped";

const tone = (reason: string): Tone =>
  reason === "machine_off" || reason === "before_start" ? "off" : reason === "dropped" ? "dropped" : "stopped";

const toneName: Record<Tone, string> = { off: "Mac off or starting", stopped: "Thadam not running", dropped: "Events dropped" };

export interface GapGroup {
  key: string;
  reason: string;
  label: string;
  from: string;
  to: string;
  count: number;
  missed: number;
}

/** Gaps of the same kind that follow within this many seconds read as one (a restart loop). */
const MERGE_WITHIN_S = 120;

/**
 * Display grouping only: the store keeps every gap. A Mac-off gap and the boot start-up after
 * it are one restart; repeats of the same reason close together (a restart loop) are one row.
 */
export function groupGaps(gaps: readonly Gap[]): GapGroup[] {
  const sorted = [...gaps].sort((a, b) => Date.parse(a.from) - Date.parse(b.from));
  const groups: GapGroup[] = [];
  for (const g of sorted) {
    const restart = tone(g.reason) === "off";
    const key = restart ? "restart" : `${g.reason}:${g.detail ?? ""}`;
    const last = groups.at(-1);
    if (last?.key === key && (Date.parse(g.from) - Date.parse(last.to)) / 1000 <= MERGE_WITHIN_S) {
      if (Date.parse(g.to) > Date.parse(last.to)) last.to = g.to;
      last.count += restart && g.reason === "before_start" ? 0 : 1;
      last.missed += g.missed ?? 0;
      if (restart && !last.label.includes("Starting") && g.reason === "before_start") last.label = "Mac off · Starting after boot";
      continue;
    }
    groups.push({ key, reason: g.reason, label: gapWords(g), from: g.from, to: g.to, count: 1, missed: g.missed ?? 0 });
  }
  for (const grp of groups) {
    if (grp.reason === "dropped") grp.label = gapWords({ from: grp.from, to: grp.to, reason: "dropped", detail: grp.key.slice("dropped:".length) || null, missed: grp.missed });
  }
  return groups;
}

const seconds = (from: string, to: string): number => (Date.parse(to) - Date.parse(from)) / 1000;

/** Axis labels: clock times for a day or less, dates beyond that. */
function ticks(from: number, to: number): string[] {
  const short = to - from <= 36 * 3_600_000;
  return [0, 0.25, 0.5, 0.75, 1].map((f) => {
    const iso = new Date(from + (to - from) * f).toISOString();
    return short ? clock(iso).slice(0, 5) : day(iso);
  });
}

export function CoverageCard({ range }: { range: TimeRange }) {
  const { data, loading } = useApi(signal => api.coverage(range, signal), [range.from, range.to]);
  if (!data || loading) return null;
  const from = Date.parse(data.range.from);
  const to = Date.parse(data.range.to);
  const total = Math.max(1, to - from);
  const groups = groupGaps(data.gaps);
  const pct = (t: number) => `${String(Math.min(100, Math.max(0, ((t - from) / total) * 100)))}%`;
  const counts = new Map<Tone, number>();
  for (const g of groups) counts.set(tone(g.reason), (counts.get(tone(g.reason)) ?? 0) + 1);
  const summary = groups.length === 0 ? "No gaps in this range." : `${count(groups.length, "gap")} · not watching ${span(data.notWatchedSeconds)}`;
  return (
    <section className="card pad coverage" aria-labelledby="coverage-h">
      <div className="row">
        <h2 id="coverage-h" className="h2">Coverage</h2>
        <span className="muted small">{summary}</span>
        <span className="spacer" />
        {[...counts].map(([t, n]) => <span key={t} className="legend small"><i className={`sw ${t}`} aria-hidden="true" />{toneName[t]} · {num(n)}</span>)}
      </div>
      <div className="track" role="img" aria-label={`Coverage from ${when(data.range.from)} to ${when(data.range.to)} ${zone}: ${summary}`}>
        {groups.map((g, i) => (
          <span key={i} className={`seg ${tone(g.reason)}`} style={{ left: pct(Date.parse(g.from)), width: `calc(${pct(Date.parse(g.to))} - ${pct(Date.parse(g.from))})` }}
            title={`${when(g.from)} to ${when(g.to)} ${zone} (${span(seconds(g.from, g.to))}) · ${g.label}${g.count > 1 ? ` · ${num(g.count)} times` : ""}`} />
        ))}
      </div>
      <div className="axis small muted" aria-hidden="true">{ticks(from, to).map((t, i) => <span key={i}>{t}</span>)}</div>
      {groups.length > 0 && (
        <details className="gaps">
          <summary className="small">Show {count(groups.length, "gap")}</summary>
          <div className="scrollbox short">
            <table className="tbl">
              <thead><tr><th>From ({zone})</th><th>To</th><th className="num">Length</th><th>What</th></tr></thead>
              <tbody>
                {[...groups].reverse().map((g, i) => (
                  <tr key={i}>
                    <td title={utc(g.from)}>{when(g.from)}</td>
                    <td title={utc(g.to)}>{when(g.to)}</td>
                    <td className="num">{span(seconds(g.from, g.to))}</td>
                    <td><i className={`sw ${tone(g.reason)}`} aria-hidden="true" /> {g.label}{g.count > 1 && <span className="muted"> · {num(g.count)} times</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </section>
  );
}

export function TimelineCoverage({ range }: { range: TimeRange }) {
  const { data, loading } = useApi(signal => api.coverage(range, signal), [range.from, range.to]);
  const gaps = data?.gaps.filter(g => g.reason !== "machine_off" && Date.parse(g.from) <= Date.parse(range.to) && Date.parse(g.to) >= Date.parse(range.from)) ?? [];
  if (loading || gaps.length === 0) return null;
  return <div role="status" className="card pad">{gaps.slice(0, 5).map((g, i) => <p key={i}>Thadam was not watching {when(g.from)} to {when(g.to)} ({gapWords(g)}): activity in that window is missing.</p>)}{gaps.length > 5 && <p>and {num(gaps.length - 5)} more</p>}</div>;
}

/** `short` is for list rows, where the long label would push columns out of the card. */
export function OsOnly({ short = false }: { short?: boolean }) {
  return <span className="pill" title="The tool's hooks sent no prompts for this session: it started before the hooks were installed, the tool has no hooks, or no prompt was typed.">{short ? "OS only" : "OS only: no prompts recorded"}</span>;
}
