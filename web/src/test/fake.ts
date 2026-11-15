// A fake API for component tests: synthetic responses keyed by path, and a record of
// the requests made. All data is synthetic.
import { vi } from "vitest";

export interface Call {
  method: string;
  path: string;
  headers: Record<string, string>;
  body?: string | undefined;
}

type Reply = { status: number; body?: unknown; text?: string; headers?: Record<string, string> };
export type Routes = Record<string, Reply | ((call: Call) => Reply)>;

export const meta = {
  chain: { state: "verified", firstSeq: 5, lastSeq: 33, rows: 29 },
  tools: [
    { key: "cli_agent", displayName: "CLI agent" },
    { key: "desktop_assistant", displayName: "desktop_assistant" },
  ],
  data: { from: "2026-11-11T09:00:00.000000Z", to: "2026-11-17T09:31:00.000000Z" },
  user: "dev",
};

const range = { from: "2026-11-08T00:00:00.000000Z", to: "2026-11-15T00:00:00.000000Z" };

export const overview = {
  range,
  kpis: {
    sessions: 3,
    outsideProject: { records: 2, folders: 2 },
    flaggedOpen: { high: 1, medium: 2, low: 2 },
    denied: { byAgent: 0, byUser: 0, byOs: 1 },
    hosts: { total: 1, unknown: 1, networkVolume: 0 },
    sensitive: { SECRET: 1 },
  },
  byTool: [
    { tool: "cli_agent", displayName: "CLI agent", sessions: 2, filesRead: 35, filesWritten: 0, commands: 1, denied: 1, outside: 1, hosts: 1, flagged: 4 },
  ],
  outsideFolders: [{ folder: "~/.cargo/registry", records: 1, tools: ["cli_agent"], flags: [] }],
  hosts: [
    { target: "203.0.113.7:443", category: "network_external", flows: 1, bytesOut: 5000, bytesIn: 20000, unknown: true, flaggedFlows: 1 },
    // Listed in the registry after its first connections: the newest is known.
    { target: "api.example-agent.test:443", category: "network_external", flows: 9, bytesOut: 900, bytesIn: 400, unknown: false, flaggedFlows: 4 },
  ],
};

export const flagItem = {
  eventId: "0190f1a2-0000-7000-8000-000000000007",
  rule: "secret",
  severity: "high",
  target: "curl -H \"Authorization: Bearer [REDACTED:SECRET]\" https://api.example.test/v1",
  sessionId: "s-b1",
  tool: "cli_agent",
  displayName: "CLI agent",
  rows: 1,
  count: 1,
  first: "2026-11-11T09:00:06.000000Z",
  last: "2026-11-11T09:00:06.000000Z",
  reviewed: false,
};

export const event = {
  seq: 40,
  eventId: "0190f1a2-0000-7000-8000-000000000040",
  ts: "2026-11-11T09:01:00.000000Z",
  tool: "cli_agent",
  displayName: "CLI agent",
  sessionId: "s-b1",
  pid: 4100,
  processPath: "/Users/dev/.local/bin/cli-agent",
  category: "command",
  action: "exec",
  target: "cargo test",
  outcome: "allowed",
  sizeBytes: null,
  bytesOut: null,
  bytesIn: null,
  flags: [] as string[],
  count: 1,
  detections: {},
  source: "os",
  severity: null,
  rule: null,
  agentSessionId: null,
  transcript: null,
};

export const search = {
  range: null,
  index: { indexedSeq: 40 },
  partial: false,
  summary: null,
  hosts: [],
  items: [event],
  next: null,
};

/** A session timeline with what the OS saw and what the tool's hook reported (ADR-011). */
export const timeline = {
  session: { sessionId: "s-b1", tool: "cli_agent", displayName: "CLI agent", parentSessionId: null, project: "/Users/dev/projects/sample-app", first: "2026-11-11T09:00:00.000000Z", last: "2026-11-11T09:02:00.000000Z", rows: 3, events: 3, prompts: 1 },
  children: [],
  events: [
    { ...event, seq: 38, category: "prompt", action: "prompt", target: "fix the failing test", source: "agent", agentSessionId: "a-51c2", transcript: "/Users/dev/.cli-agent/a-51c2.jsonl" },
    { ...event, seq: 39, target: "touch probe-x", outcome: "never_ran", flags: ["unconfirmed"], source: "agent", agentSessionId: "a-51c2", transcript: "/Users/dev/.cli-agent/a-51c2.jsonl" },
    event,
  ],
  next: null,
};

export function install(routes: Routes): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", (input: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    const path = input.replace(/^\/api\/v1/, "");
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const call = { method, path, headers, body: typeof init?.body === "string" ? init.body : undefined };
    calls.push(call);
    const key = Object.keys(routes).find((k) => {
      const [m, p] = k.split(" ", 2);
      return m === method && p !== undefined && path.split("?")[0] === p;
    });
    const found = key === undefined ? undefined : routes[key];
    const reply = found === undefined ? { status: 404 } : typeof found === "function" ? found(call) : found;
    const body = reply.text ?? (reply.body === undefined ? null : JSON.stringify(reply.body));
    return Promise.resolve(new Response(body, { status: reply.status, ...(reply.headers ? { headers: reply.headers } : {}) }));
  });
  return calls;
}

export function stubBrowser(): void {
  vi.stubGlobal("matchMedia", (query: string) => ({ matches: false, media: query, addEventListener: () => undefined, removeEventListener: () => undefined }));
}
