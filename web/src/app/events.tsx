// Stored rows as a table: the timeline and search share it. Every value is rendered as
// text; nothing from the store becomes markup (ADR-008 Decision 3).
import type { Event } from "../api/schemas";
import { bytes, categoryName, clock, day, num, words } from "./format";
import { FlagPills, SeverityPill } from "./ui";

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
  if (outcome === "failed") return "pill flag";
  return "pill";
}

export function EventTable({ events, showTool, showDay }: { events: readonly Event[]; showTool?: boolean; showDay?: boolean }) {
  return (
    <div className="scroll">
      <table className="tbl events">
        <thead>
          <tr>
            <th>Time (UTC)</th>
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
              <td className="mono">{showDay === true ? `${day(e.ts)} ` : ""}{clock(e.ts)}</td>
              {showTool === true && <td>{e.displayName}</td>}
              <td>{categoryName[e.category] ?? words(e.category)} · {e.action}</td>
              <td className="mono wrap">
                {e.target}
                {detail(e) !== "" && <span className="detail">{detail(e)}</span>}
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
