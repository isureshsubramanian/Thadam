// The header's time range, shared by the list views.
export const ranges = [
  { key: "24h", label: "Last 24 hours", hours: 24 },
  { key: "7d", label: "Last 7 days", hours: 24 * 7 },
  { key: "30d", label: "Last 30 days", hours: 24 * 30 },
  { key: "90d", label: "Last 90 days", hours: 24 * 90 },
] as const;

export type RangeKey = (typeof ranges)[number]["key"];

export interface TimeRange {
  from: string;
  to: string;
}

export function resolve(key: RangeKey, now: Date = new Date()): TimeRange {
  const hours = ranges.find((r) => r.key === key)?.hours ?? 24 * 7;
  return { from: new Date(now.getTime() - hours * 3_600_000).toISOString(), to: now.toISOString() };
}
