import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../app/App";
import { parse, href } from "../app/route";
import * as fake from "./fake";

beforeEach(() => {
  fake.stubBrowser();
  window.location.hash = "#/overview";
  vi.spyOn(console, "error").mockImplementation(() => undefined);
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const base: fake.Routes = {
  "GET /coverage": { status: 200, body: { range: fake.overview.range, gaps: [], notWatchedSeconds: 0 } },
  "GET /meta": { status: 200, body: fake.meta },
  "GET /overview": { status: 200, body: fake.overview },
  "GET /antiforgery": { status: 200, body: { token: "t-123" } },
  "GET /flags": { status: 200, body: { range: fake.overview.range, items: [fake.flagItem], next: null } },
};

describe("routes", () => {
  it("round-trips every view", () => {
    for (const r of [{ view: "overview" }, { view: "flagged" }, { view: "sessions" }, { view: "sessions", sessionId: "s/1 x" }, { view: "search", q: "tool:\"CLI agent\" since:7d" }] as const) {
      expect(parse(href(r))).toEqual(r);
    }
  });
});

describe("dashboard", () => {
  it("shows sign-in when the API says 401", async () => {
    fake.install({ "GET /meta": { status: 401 } });
    render(<App />);
    expect(await screen.findByLabelText("Password")).toBeTruthy();
  });

  it("shows the collector message when sign-in cannot be audited", async () => {
    fake.install({ ...base, "GET /meta": { status: 401 }, "POST /session": { status: 503, body: { errors: ["audit"] } } });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Password"), { target: { value: "synthetic password" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Not done: the audit log is unavailable because the Thadam collector is not running.");
    expect(screen.getByLabelText("Password")).toBeTruthy();
  });

  it("shows the collector message when search cannot be audited", async () => {
    fake.install({ ...base, "GET /events": { status: 503, body: { errors: ["audit"] } } });
    window.location.hash = "#/search?q=since%3A7d";
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Not done: the audit log is unavailable because the Thadam collector is not running.");
    expect(screen.queryByRole("button", { name: "Export CSV" })).toBeNull();
  });

  it("renders the overview from the API", async () => {
    fake.install(base);
    render(<App />);
    expect(await screen.findByText("Activity by tool")).toBeTruthy();
    expect(screen.getByText("~/.cargo/registry")).toBeTruthy();
    expect(screen.getByText(/Chain verified · seq 5–33/)).toBeTruthy();
  });

  it("marks a host by its newest connection and keeps earlier flags in the tooltip", async () => {
    fake.install(base);
    render(<App />);
    const now = await screen.findByText("unknown host");
    expect(now.getAttribute("title")).toBe("Flagged as unknown on 1 of 1 connections in this range");
    const before = screen.getByText("was unknown");
    expect(before.getAttribute("title")).toBe("Flagged as unknown on 4 of 9 connections in this range; the newest was to a known host");
  });

  it("a malformed response fails one view; the others keep working", async () => {
    fake.install({ ...base, "GET /overview": { status: 200, body: { kpis: "not an object" } } });
    render(<App />);
    expect(await screen.findByText("This view failed to load.")).toBeTruthy();
    // The report names the area and error type only.
    expect(console.error).toHaveBeenCalledWith("thadam: overview failed (ZodError)");
    act(() => { window.location.hash = "#/flagged"; window.dispatchEvent(new HashChangeEvent("hashchange")); });
    expect(await screen.findByText("Secret or sensitive data detected")).toBeTruthy();
    expect(screen.queryByText("This view failed to load.")).toBeNull();
  });

  it("every icon-only button has an accessible name that is also its tooltip", async () => {
    fake.install(base);
    render(<App />);
    await screen.findByText("Activity by tool");
    for (const b of document.querySelectorAll("button.ibtn")) {
      const label = b.getAttribute("aria-label");
      expect(label).toBeTruthy();
      expect(b.getAttribute("title")).toBe(label);
    }
  });

  it("Mark reviewed carries the antiforgery token and a text label", async () => {
    const calls = fake.install({ ...base, "POST /flags/0190f1a2-0000-7000-8000-000000000007/review": { status: 204 } });
    window.location.hash = "#/flagged";
    render(<App />);
    const button = await screen.findByRole("button", { name: "Mark reviewed" });
    fireEvent.click(button);
    await waitFor(() => { expect(calls.some((c) => c.method === "POST")).toBe(true); });
    const post = calls.find((c) => c.method === "POST");
    expect(post?.headers["X-Thadam-Csrf"]).toBe("t-123");
  });

  it("stored values are shown as text, never as markup", async () => {
    const hostile = { ...fake.flagItem, target: "<img src=x onerror=alert(1)>" };
    fake.install({ ...base, "GET /flags": { status: 200, body: { range: fake.overview.range, items: [hostile], next: null } } });
    window.location.hash = "#/flagged";
    render(<App />);
    expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
  });

  it("marks the rows the tool reported and offers its transcript path to copy, not open", async () => {
    fake.install({ ...base, "GET /sessions/s-b1": { status: 200, body: fake.timeline } });
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    window.location.hash = "#/sessions/s-b1";
    render(<App />);
    expect(await screen.findByText("fix the failing test")).toBeTruthy();
    expect(screen.getAllByText("reported by the tool")).toHaveLength(2);
    expect(screen.getByText("never ran").className).toContain("flag");
    expect(screen.getAllByText("/Users/dev/.cli-agent/a-51c2.jsonl")).toHaveLength(2);
    expect(document.querySelector("a[href^='file:']")).toBeNull();
    fireEvent.click(screen.getAllByRole("button", { name: "Copy transcript path" })[0] as HTMLElement);
    expect(writeText).toHaveBeenCalledWith("/Users/dev/.cli-agent/a-51c2.jsonl");
  });

  it("Export CSV saves the file the API names, and carries a text label", async () => {
    const calls = fake.install({
      ...base,
      "GET /events": { status: 200, body: fake.search },
      "GET /export": {
        status: 200,
        text: "seq,event_id\r\n40,x\r\n",
        headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": 'attachment; filename="thadam-export-20261115T0612Z-s40.csv"' },
      },
    });
    const createObjectURL = vi.fn(() => "blob:synthetic");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    window.location.hash = `#/search?q=${encodeURIComponent("tool:cli_agent")}`;
    render(<App />);
    const button = await screen.findByRole("button", { name: "Export CSV" });
    fireEvent.click(button);
    await waitFor(() => { expect(click).toHaveBeenCalled(); });
    const anchor = click.mock.contexts[0] as HTMLAnchorElement;
    expect(anchor.download).toBe("thadam-export-20261115T0612Z-s40.csv");
    expect(createObjectURL).toHaveBeenCalled();
    expect(calls.find((c) => c.path.startsWith("/export"))?.path).toBe("/export?q=tool%3Acli_agent");
  });

  it("an export over the limit says how many rows match and produces no file", async () => {
    fake.install({
      ...base,
      "GET /sessions/s-b1": { status: 200, body: fake.timeline },
      "GET /export": { status: 413, body: { errors: ["rows"], rows: 250000, limit: 100000 } },
    });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    window.location.hash = "#/sessions/s-b1";
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Export CSV" }));
    expect((await screen.findByRole("alert")).textContent).toBe("250,000 rows match; the limit is 100,000. Narrow the time range or add a filter.");
    expect(click).not.toHaveBeenCalled();
  });

  it("a rejected search names the field, not the text typed", async () => {
    fake.install({ ...base, "GET /events": { status: 400, body: { errors: ["q.tool"] } } });
    window.location.hash = `#/search?q=${encodeURIComponent("tool:secret_name")}`;
    render(<App />);
    const alert = await screen.findByText("Check the tool: value.");
    expect(alert.textContent).not.toContain("secret_name");
  });
});

describe("coverage and session labels", () => {
  const gap = (reason: string, detail: string | null = null, missed: number | null = null) => ({
    from: fake.timeline.session.first, to: fake.timeline.session.last, reason, detail, missed,
  });
  const coverageRoute = (gaps: ReturnType<typeof gap>[], notWatchedSeconds = 840): fake.Routes => ({
    ...base, "GET /coverage": { status: 200, body: { range: fake.overview.range, gaps, notWatchedSeconds } },
  });
  it.each([{ gaps: [] }, { gaps: [gap("machine_off")] }])("shows Watching for empty or Mac-off-only coverage", async ({ gaps }) => {
    fake.install(coverageRoute(gaps));
    render(<App />);
    expect((await screen.findByText("Watching")).className).toBe("pill ok");
  });
  it("shows union minutes, reason counts, and coverage wording", async () => {
    fake.install(coverageRoute([gap("not_running", "stopped"), gap("not_running", "crashed"), gap("machine_off"), gap("before_start"), gap("dropped", "os", 2), gap("dropped", "network", 3), gap("paused", null, 9)]));
    render(<App />);
    const pill = await screen.findByText("Not watching: 14 min");
    expect(pill.className).toBe("pill flag");
    expect(pill.title).toContain("not running: 2");
    for (const label of ["Thadam not running (stopped)", "Thadam not running (crashed)", "Mac off", "Starting after boot", "2 events dropped by macOS", "3 events dropped by the network extension", "Writing paused: disk low (9 events not written)"]) {
      expect(await screen.findByText((text) => text.includes(label))).toBeTruthy();
    }
  });
  it("says under 1 min for a quick restart, not 0 min", async () => {
    fake.install(coverageRoute([gap("not_running", "stopped")], 0));
    render(<App />);
    expect((await screen.findByText("Not watching: under 1 min")).className).toBe("pill flag");
  });
  it("reports dropped events without counting minutes", async () => {
    fake.install(coverageRoute([gap("dropped", "os", 7), gap("machine_off")], 0));
    render(<App />);
    expect((await screen.findByText("Events dropped: 7")).className).toBe("pill flag");
  });
  it("shows the empty coverage card", async () => {
    fake.install(base);
    render(<App />);
    expect(await screen.findByText("No gaps in this range.")).toBeTruthy();
  });
  it("shows OS-only labels and limits missing-activity lines", async () => {
    const session = { ...fake.timeline.session, prompts: 0 };
    fake.install({
      ...coverageRoute([...Array.from({ length: 7 }, () => gap("not_running", "crashed")), gap("machine_off")]),
      "GET /sessions": { status: 200, body: { range: fake.overview.range, items: [session], next: null } },
      "GET /sessions/s-b1": { status: 200, body: { ...fake.timeline, session } },
    });
    window.location.hash = "#/sessions";
    render(<App />);
    expect((await screen.findByText("OS only: no prompts recorded")).title).toBe("The tool's hooks sent no prompts for this session: it started before the hooks were installed, the tool has no hooks, or no prompt was typed.");
    act(() => { window.location.hash = "#/sessions/s-b1"; window.dispatchEvent(new HashChangeEvent("hashchange")); });
    expect(await screen.findByText("and 2 more")).toBeTruthy();
    expect(screen.getAllByText(/activity in that window is missing/)).toHaveLength(5);
    expect(screen.getByText("OS only: no prompts recorded")).toBeTruthy();
  });
});
