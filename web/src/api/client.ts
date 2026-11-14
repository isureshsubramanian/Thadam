// The typed client for /api/v1. Same origin, cookie session; writes carry the antiforgery
// token in X-Thadam-Csrf (ADR-008 Decision 2).
import type { z } from "zod";
import * as s from "./schemas";

const base = "/api/v1";

/** The session ended or never started: the app shows sign-in. */
export class SignedOut extends Error {
  override name = "SignedOut";
}

/** A 400 from the API: the field names it rejected (never values). */
export class Rejected extends Error {
  override name = "Rejected";
  constructor(readonly fields: string[]) {
    super("rejected");
  }
}

/** Any other failure; the message names the status only. */
export class ApiFailed extends Error {
  override name = "ApiFailed";
}

async function request<T>(schema: z.ZodType<T>, path: string, init?: RequestInit): Promise<T | undefined> {
  const res = await fetch(base + path, { credentials: "same-origin", ...init });
  if (res.status === 401) throw new SignedOut("signed out");
  if (res.status === 400) {
    const body: unknown = await res.json().catch(() => ({}));
    const parsed = s.errors.safeParse(body);
    throw new Rejected(parsed.success ? parsed.data.errors : []);
  }
  if (res.status === 204) return undefined;
  if (!res.ok) throw new ApiFailed(`HTTP ${res.status}`);
  // parse() throws on a malformed response; the view's Error Boundary catches it.
  return schema.parse(await res.json());
}

async function get<T>(schema: z.ZodType<T>, path: string, signal?: AbortSignal): Promise<T> {
  const r = await request(schema, path, signal ? { signal } : undefined);
  if (r === undefined) throw new ApiFailed("empty response");
  return r;
}

async function csrf(): Promise<string> {
  return (await get(s.token, "/antiforgery")).token;
}

async function write(method: "POST" | "DELETE", path: string, body?: unknown): Promise<void> {
  const headers: Record<string, string> = { "X-Thadam-Csrf": await csrf() };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  await request(s.errors, path, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

function query(params: Record<string, string | number | boolean | undefined | null>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
  const text = q.toString();
  return text ? `?${text}` : "";
}

export interface RangeArgs {
  from: string;
  to: string;
  tool?: string | undefined;
}

export const api = {
  signIn: (password: string) => write("POST", "/session", { password }),
  signOut: () => write("DELETE", "/session"),
  meta: (signal?: AbortSignal) => get(s.meta, "/meta", signal),
  overview: (a: RangeArgs, signal?: AbortSignal) => get(s.overview, `/overview${query({ ...a })}`, signal),
  flags: (a: RangeArgs & { status: "open" | "reviewed"; severity?: s.Severity | undefined; after?: number | null }, signal?: AbortSignal) =>
    get(s.flags, `/flags${query({ ...a })}`, signal),
  review: (eventId: string) => write("POST", `/flags/${encodeURIComponent(eventId)}/review`),
  reopen: (eventId: string) => write("POST", `/flags/${encodeURIComponent(eventId)}/reopen`),
  sessions: (a: RangeArgs & { after?: number | null }, signal?: AbortSignal) =>
    get(s.sessions, `/sessions${query({ ...a })}`, signal),
  timeline: (id: string, a: { internal: boolean; after?: number | null }, signal?: AbortSignal) =>
    get(s.timeline, `/sessions/${encodeURIComponent(id)}${query({ ...a })}`, signal),
  search: (q: string, after?: number | null, signal?: AbortSignal) =>
    get(s.search, `/events${query({ q, after })}`, signal),
};
