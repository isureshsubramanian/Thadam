// Stored rows as a table: the timeline and search share it. Every value is rendered as
// text; nothing from the store becomes markup (ADR-008 Decision 3).
import { Copy } from "lucide-react";
import type { Event } from "../api/schemas";
import { bytes, categoryName, clock, day, num, utc, words, zone } from "./format";
import { Highlight, matches } from "./highlight";
import { FlagPills, IconButton, SeverityPill } from "./ui";

function detail(e: Event): string {
  const parts: string[] = [];
  if (e.bytesOut !== null || e.bytesIn !== null) parts.push(`↑ ${bytes(e.bytesOut ?? 0)} · ↓ ${bytes(e.bytesIn ?? 0)}`);
  if (e.count > 1) parts.push(`${num(e.count)} events`);
  const found = Object.entries(e.detections);
  if (found.length > 0) parts.push(found.map(([k, n]) => `${k.toLowerCase()} ×${num(n)} (redacted)`).join(", "));
  return parts.join(" · ");
}

function outcomeClass(outcome: string): string {
  if (outcome.startsWith("denied")) return "pill denied";
  if (outcome === "failed" || outcome === "never_ran") return "pill flag";
  return "pill";
}

/**
 * Rows the tool's hook sent (ADR-011 Decision 6): what the tool says happened, not what the OS
 * saw. The transcript is a path to copy, never a link: the browser must not open local files.
 */
function Reported() {
  return <span className="pill acc" title="Sent by the tool's hook, not observed by macOS">reported by the tool</span>;
}

function Transcript({ path }: { path: string }) {
  const copy = () => { void navigator.clipboard.writeText(path).catch(() => undefined); };
  return (
    <span className="detail transcript">
      <span className="label">transcript</span>
      <span className="mono">{path}</span>
      <IconButton label="Copy transcript path" onClick={copy}>
        <Copy className="ic" aria-hidden="true" />
      </IconButton>
    </span>
  );
}

/**
 * `highlight`: a search's free-text terms, marked where they occur. A row that matched on its
 * process path alone shows that path too, so every row shows why it is there.
 */
export function EventTable({ events, showTool, showDay, highlight = [] }: {
  events: readonly Event[];
  showTool?: boolean;
  showDay?: boolean;
  highlight?: readonly string[];
}) {
  return (
    <div className="scroll">
      <table className="tbl events">
        <thead>
          <tr>
            <th>Time ({zone})</th>
            {showTool === true && <th>Tool</th>}
            <th>Activity</th>
            <th>Target</th>
            <th>Outcome</th>
            <th>Flags</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.seq}>
              <td className="mono" title={utc(e.ts)}>{showDay === true ? `${day(e.ts)} ` : ""}{clock(e.ts)}</td>
              {showTool === true && <td>{e.displayName}</td>}
              <td>
                {categoryName[e.category] ?? words(e.category)} · {e.action}
                {e.source === "agent" && <span className="detail"><Reported /></span>}
              </td>
              <td className={e.category === "prompt" ? "wrap" : "mono wrap"}>
                <Highlight text={e.target} terms={highlight} />
                {highlight.length > 0 && !matches(e.target, highlight) && matches(e.processPath, highlight) && (
                  <span className="detail mono">process <Highlight text={e.processPath} terms={highlight} /></span>
                )}
                {detail(e) !== "" && <span className="detail">{detail(e)}</span>}
                {e.transcript !== null && <Transcript path={e.transcript} />}
              </td>
              <td><span className={outcomeClass(e.outcome)}>{words(e.outcome)}</span></td>
              <td>
                <div className="row">
                  {e.severity !== null && <SeverityPill severity={e.severity} />}
                  <FlagPills flags={e.flags} />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
