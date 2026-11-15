// Response shapes of /api/v1 (ADR-008 Decision 4). Every response is parsed here before
// a view sees it; a mismatch throws, and the view's Error Boundary shows its fallback.
import { z } from "zod";

const count = z.number().int().nonnegative();
const seq = z.number().int().positive();
const time = z.iso.datetime({ offset: true });
export const severity = z.enum(["high", "medium", "low"]);
export type Severity = z.infer<typeof severity>;

export const range = z.object({ from: time, to: time });

export const gap = z.object({ from: time, to: time, reason: z.string(), detail: z.string().nullable(), missed: count.nullable() });
export type Gap = z.infer<typeof gap>;
export const coverage = z.object({ range, gaps: z.array(gap), notWatchedSeconds: count });
export type Coverage = z.infer<typeof coverage>;

export const chain = z.discriminatedUnion("state", [
  z.object({ state: z.literal("pending") }),
  z.object({ state: z.literal("unreadable") }),
  z.object({
    state: z.literal("verified"),
    firstSeq: z.number().int().nullable(),
    lastSeq: z.number().int().nullable(),
    rows: count,
  }),
  z.object({ state: z.literal("broken"), kind: z.string(), seq: z.number().int().nullable() }),
]);
export type Chain = z.infer<typeof chain>;

export const tool = z.object({ key: z.string(), displayName: z.string() });

export const meta = z.object({
  chain,
  tools: z.array(tool),
  data: range.nullable(),
  user: z.string().nullable(),
});
export type Meta = z.infer<typeof meta>;

export const host = z.object({
  target: z.string(),
  category: z.string(),
  flows: count,
  bytesOut: count,
  bytesIn: count,
  /** The newest connection in the range was to a host the registry did not list. */
  unknown: z.boolean(),
  /** Connections in the range flagged as unknown when they were recorded. */
  flaggedFlows: count,
});
export type Host = z.infer<typeof host>;

export const overview = z.object({
  range,
  kpis: z.object({
    sessions: count,
    outsideProject: z.object({ records: count, folders: count }),
    flaggedOpen: z.object({ high: count, medium: count, low: count }),
    denied: z.object({ byAgent: count, byUser: count, byOs: count }),
    hosts: z.object({ total: count, unknown: count, networkVolume: count }),
    sensitive: z.record(z.string(), count),
  }),
  byTool: z.array(
    z.object({
      tool: z.string(),
      displayName: z.string(),
      sessions: count,
      filesRead: count,
      filesWritten: count,
      commands: count,
      denied: count,
      outside: count,
      hosts: count,
      flagged: count,
    }),
  ),
  outsideFolders: z.array(
    z.object({ folder: z.string(), records: count, tools: z.array(z.string()), flags: z.array(z.string()) }),
  ),
  hosts: z.array(host),
});
export type Overview = z.infer<typeof overview>;

export const flagItem = z.object({
  eventId: z.string(),
  rule: z.string(),
  severity,
  target: z.string(),
  sessionId: z.string().nullable(),
  tool: z.string(),
  displayName: z.string(),
  rows: count,
  count,
  first: time,
  last: time,
  reviewed: z.boolean(),
  /** Who marked it reviewed and when (ADR-015 Decision 1); null while open, or from an older API. */
  reviewedBy: z.string().nullable().default(null),
  reviewedAt: time.nullable().default(null),
});
export type FlagItem = z.infer<typeof flagItem>;

/** Paging totals (ADR-014): defaults keep a page working against an API that sends none. */
const totals = { total: count.nullable().default(null), totalCapped: z.boolean().default(false) };

export const flags = z.object({ range, items: z.array(flagItem), next: seq.nullable(), ...totals });

export const session = z.object({
  sessionId: z.string(),
  tool: z.string(),
  displayName: z.string(),
  parentSessionId: z.string().nullable(),
  project: z.string().nullable(),
  first: time,
  last: time,
  rows: count,
  events: count,
  prompts: count,
});
export type Session = z.infer<typeof session>;

export const sessions = z.object({ range, items: z.array(session), next: seq.nullable(), ...totals });

export const event = z.object({
  seq,
  eventId: z.string(),
  ts: time,
  tool: z.string(),
  displayName: z.string(),
  sessionId: z.string().nullable(),
  pid: z.number().int(),
  processPath: z.string(),
  category: z.string(),
  action: z.string(),
  target: z.string(),
  outcome: z.string(),
  sizeBytes: z.number().int().nullable(),
  bytesOut: z.number().int().nullable(),
  bytesIn: z.number().int().nullable(),
  flags: z.array(z.string()),
  count,
  detections: z.record(z.string(), count),
  source: z.string(),
  severity: severity.nullable(),
  rule: z.string().nullable(),
  /** Agent rows only (ADR-011): the tool's own session ID and its transcript file. */
  agentSessionId: z.string().nullable(),
  transcript: z.string().nullable(),
});
export type Event = z.infer<typeof event>;

export const timeline = z.object({
  session,
  children: z.array(session),
  events: z.array(event),
  next: seq.nullable(),
  ...totals,
});
export type Timeline = z.infer<typeof timeline>;

export const search = z.object({
  range: range.nullable(),
  index: z.object({ indexedSeq: z.number().int().nonnegative() }),
  partial: z.boolean(),
  summary: z
    .object({
      rows: count,
      records: count,
      byCategory: z.record(z.string(), count),
      flagged: count,
      outsideFolders: z.array(z.object({ folder: z.string(), records: count })),
    })
    .nullable(),
  hosts: z.array(host).nullable(),
  items: z.array(event),
  next: seq.nullable(),
  ...totals,
});
export type SearchResult = z.infer<typeof search>;

export const errors = z.object({ errors: z.array(z.string()) });
/** 429 from sign-in (ADR-015 Decision 1): seconds before the next attempt is checked. */
export const wait = z.object({ retryAfter: z.number().int().positive().max(86_400) });
/** Reply to a bulk review or reopen (ADR-014 Decision 5): how many flags changed state. */
export const changed = z.object({ changed: count });
/** 413 from /export (ADR-012 Decision 4): how many rows match (null: too many to count) and the limit. */
export const tooMany = z.object({ errors: z.array(z.string()), rows: count.nullable(), limit: count });
export const token = z.object({ token: z.string() });
