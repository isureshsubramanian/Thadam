// Display formatting. Times are shown in UTC, as the store records them.
const dateFmt = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", timeZone: "UTC" });
const timeFmt = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23", timeZone: "UTC" });
const numFmt = new Intl.NumberFormat("en-GB");

export const num = (n: number): string => numFmt.format(n);

/** A count and its noun: `1 host`, `3 hosts`, `2 matches`. */
export const count = (n: number, one: string, many = `${one}s`): string => `${num(n)} ${n === 1 ? one : many}`;

export const day = (iso: string): string => dateFmt.format(new Date(iso));

export const clock = (iso: string): string => timeFmt.format(new Date(iso));

export const when = (iso: string): string => `${day(iso)} ${clock(iso).slice(0, 5)} UTC`;

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
  sensitive_path: "Sensitive path accessed",
  large_upload_unknown_host: "Large upload to an unknown host",
  denied: "Refused by the agent or by you",
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
