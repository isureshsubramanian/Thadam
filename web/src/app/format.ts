// Display formatting. The store records UTC; the page shows this Mac's local time, and the
// UTC instant on hover (`utc`).
const dateFmt = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short" });
const timeFmt = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" });
const utcFmt = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23", timeZone: "UTC" });
const numFmt = new Intl.NumberFormat("en-GB");

export const num = (n: number): string => numFmt.format(n);

/** A count and its noun: `1 host`, `3 hosts`, `2 matches`. */
export const count = (n: number, one: string, many = `${one}s`): string => `${num(n)} ${n === 1 ? one : many}`;

export const day = (iso: string): string => dateFmt.format(new Date(iso));

export const clock = (iso: string): string => timeFmt.format(new Date(iso));

/** The local zone's short name (`IST`, or `GMT+5:30` where the locale has no abbreviation). */
export const zone: string = new Intl.DateTimeFormat(undefined, { timeZoneName: "short" }).formatToParts(new Date()).find((p) => p.type === "timeZoneName")?.value ?? "local";

export const when = (iso: string): string => `${day(iso)} ${clock(iso).slice(0, 5)}`;

/** The same instant in UTC, for a hover title. */
export const utc = (iso: string): string => `${utcFmt.format(new Date(iso))} UTC`;

/** A length of time in words: `45 s`, `12 min`, `3 h 5 min`, `2 d 4 h`. */
export function span(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${String(s)} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${String(m)} min`;
  const h = Math.floor(m / 60);
  if (h < 48) return m % 60 === 0 ? `${String(h)} h` : `${String(h)} h ${String(m % 60)} min`;
  const d = Math.floor(h / 24);
  return h % 24 === 0 ? `${String(d)} d` : `${String(d)} d ${String(h % 24)} h`;
}

export function bytes(n: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${i === 0 ? String(v) : v.toFixed(1)} ${units[i] ?? "B"}`;
}

/** First letter in capitals: `high` is `High`. */
export const cap = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);

/** Wire names (`outside_project`) as words (`outside project`). */
export const words = (wire: string): string => wire.replaceAll("_", " ");

/** What each flag rule means, as the queue's heading (ADR-008 Decision 7). */
export const ruleTitle: Record<string, string> = {
  secret: "Secret or sensitive data detected",
  blocked_by_guard: "Blocked by Thadam guard",
  would_block: "Would be blocked by Thadam guard (monitor)",
  sensitive_path: "Sensitive path accessed",
  launch_outside: "Started outside the tool's process tree",
  large_upload_unknown_host: "Large upload to an unknown host",
  denied: "Refused by the agent or by you",
  tool_config_change: "Changed the tool's own configuration",
  outside_change: "Changed a file outside the project",
  unknown_host: "Connected to an unknown host",
  large_upload: "Large upload",
  outside_read: "Read outside the project",
  denied_by_os: "Refused by macOS",
};

export const categoryName: Record<string, string> = {
  file: "File",
  command: "Command",
  prompt: "Prompt",
  network_internal: "Network internal",
  network_external: "Network external",
  network_volume: "Network volume",
};
