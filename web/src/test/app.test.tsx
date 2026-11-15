import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../app/App";
import { groupGaps } from "../app/coverage";
import { freeTerms, Highlight } from "../app/highlight";
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

  it.each([
    [{ status: 401 }, "That password is not right."],
    [{ status: 409, body: { errors: ["no_password"] } }, "No password is set yet. Set one in Terminal with the command below."],
    [{ status: 429, body: { errors: ["wait"], retryAfter: 8 } }, "Too many wrong passwords. Try again in 8 seconds."],
    [{ status: 429, body: { errors: ["wait"], retryAfter: 300 } }, "Too many wrong passwords. Try again in 5 minutes."],
  ])("says why sign-in was turned away (%o)", async (reply, text) => {
    fake.install({ ...base, "GET /meta": { status: 401 }, "POST /session": reply });
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Password"), { target: { value: "synthetic password" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", text);
    expect(screen.getByText(/thadam-collector" set-password/)).toBeTruthy();
  });

  it("shows who reviewed a flag on the Reviewed tab", async () => {
    const reviewed = { ...fake.flagItem, reviewed: true, reviewedBy: "reviewer-a", reviewedAt: "2026-11-11T10:00:00.000000Z" };
    fake.install({
      ...base,
      "GET /flags": (call) => ({
        status: 200,
        body: { range: fake.overview.range, items: call.path.includes("status=reviewed") ? [reviewed] : [fake.flagItem], next: null },
      }),
    });
    window.location.hash = "#/flagged";
    render(<App />);
    await screen.findByRole("button", { name: "Mark reviewed" });
    expect(screen.queryByRole("columnheader", { name: "Reviewed by" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Reviewed" }));
    expect(await screen.findByRole("columnheader", { name: "Reviewed by" })).toBeTruthy();
    expect(screen.getByText("reviewer-a").closest("td")?.textContent).toMatch(/^reviewer-a · /);
  });

  it("shows the collector message when search cannot be audited", async () => {
    fake.install({ ...base, "GET /events": { status: 503, body: { errors: ["audit"] } } });
    window.location.hash = "#/search?q=since%3A7d";
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Not done: the audit log is unavailable because the Thadam collector is not running.");
    expect(screen.queryByRole("button", { name: "Export CSV" })).toBeNull();
  });

  it("asks for coverage once when the header and the overview both show it", async () => {
    const calls = fake.install(base);
    render(<App />);
    await screen.findByText("Activity by tool");
    await screen.findByText("Coverage");
    expect(calls.filter((c) => c.path.startsWith("/coverage"))).toHaveLength(1);
  });

  it("renders the overview from the API", async () => {
    fake.install(base);
    render(<App />);
    expect(await screen.findByText("Activity by tool")).toBeTruthy();
    expect(screen.getByText("~/.cargo/registry")).toBeTruthy();
    expect(screen.getByText(/Chain verified · seq 5–33/)).toBeTruthy();
  });

  it("moves the range to the present on coming back to the tab after a while, not before", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(new Date("2026-11-15T09:00:00Z"));
      const calls = fake.install(base);
      render(<App />);
      await screen.findByText("Activity by tool");
      const ends = () => calls.filter((c) => c.path.startsWith("/overview")).map((c) => new URLSearchParams(c.path.split("?")[1]).get("to"));
      expect(ends()).toEqual(["2026-11-15T09:00:00.000Z"]);

      vi.setSystemTime(new Date("2026-11-15T09:00:30Z"));
      act(() => { document.dispatchEvent(new Event("visibilitychange")); });
      expect(ends()).toHaveLength(1);

      vi.setSystemTime(new Date("2026-11-15T09:05:00Z"));
      act(() => { document.dispatchEvent(new Event("visibilitychange")); });
      await waitFor(() => { expect(ends()).toEqual(["2026-11-15T09:00:00.000Z", "2026-11-15T09:05:00.000Z"]); });
    } finally {
      vi.useRealTimers();
    }
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

  it("marks the ticked flags reviewed in one call with the antiforgery token and a text label", async () => {
    const second = { ...fake.flagItem, eventId: "0190f1a2-0000-7000-8000-000000000008", target: "/etc/hosts" };
    const calls = fake.install({
      ...base,
      "GET /flags": { status: 200, body: { range: fake.overview.range, items: [fake.flagItem, second], next: null, total: 2, totalCapped: false } },
      "POST /flags/review": { status: 200, body: { changed: 2 } },
    });
    window.location.hash = "#/flagged";
    render(<App />);
    const button = await screen.findByRole("button", { name: "Mark reviewed" });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(await screen.findByRole("checkbox", { name: "Select every row on this page" }));
    fireEvent.click(await screen.findByRole("button", { name: "Mark reviewed (2)" }));
    await waitFor(() => { expect(calls.some((c) => c.method === "POST")).toBe(true); });
    const post = calls.find((c) => c.method === "POST");
    expect(post?.path).toBe("/flags/review");
    expect(post?.headers["X-Thadam-Csrf"]).toBe("t-123");
    expect(JSON.parse(post?.body ?? "{}")).toEqual({ eventIds: [fake.flagItem.eventId, second.eventId] });
    expect(await screen.findByText("2 flags marked reviewed")).toBeTruthy();
  });

  it("ticks one row at a time and counts it on the button", async () => {
    fake.install(base);
    window.location.hash = "#/flagged";
    render(<App />);
    const box = await screen.findByRole("checkbox", { name: /^Select: / });
    fireEvent.click(box);
    expect(await screen.findByRole("button", { name: "Mark reviewed (1)" })).toBeTruthy();
    fireEvent.click(box);
    expect(await screen.findByRole("button", { name: "Mark reviewed" })).toBeTruthy();
  });

  it("pages with Next and Prev by the API's after key and shows the rows and total", async () => {
    const page = (n: number) => ({ ...fake.flagItem, eventId: `0190f1a2-0000-7000-8000-0000000001${String(n).padStart(2, "0")}` });
    const calls = fake.install({
      ...base,
      "GET /flags": (call) => call.path.includes("after=")
        ? { status: 200, body: { range: fake.overview.range, items: [page(2)], next: null, total: null, totalCapped: false } }
        : { status: 200, body: { range: fake.overview.range, items: Array.from({ length: 50 }, (_, i) => page(i)), next: 77, total: 51, totalCapped: false } },
    });
    window.location.hash = "#/flagged";
    render(<App />);
    expect(await screen.findByText("Rows 1–50 of 51")).toBeTruthy();
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Prev" }).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: /Next/ }));
    expect(await screen.findByText("Rows 51–51 of 51")).toBeTruthy();
    expect(calls.some((c) => c.path.startsWith("/flags") && c.path.includes("after=77"))).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: /Prev/ }));
    expect(await screen.findByText("Rows 1–50 of 51")).toBeTruthy();
  });

  it("asks the API with the grid's search text once typing pauses", async () => {
    const calls = fake.install({ ...base, "GET /sessions": { status: 200, body: { range: fake.overview.range, items: [fake.timeline.session], next: null } } });
    window.location.hash = "#/sessions";
    render(<App />);
    await screen.findByText("Rows 1–1");
    const box = screen.getByRole("searchbox", { name: "Search sessions" });
    fireEvent.change(box, { target: { value: " sample " } });
    await waitFor(() => { expect(calls.filter((c) => c.path.startsWith("/sessions")).map((c) => c.path)).toContainEqual(expect.stringContaining("q=sample")); });
  });

  it("searches inside a session with the session scope added", async () => {
    const calls = fake.install({
      ...base,
      "GET /sessions/s-b1": { status: 200, body: fake.timeline },
      "GET /events": { status: 200, body: { ...fake.search, items: [] } },
    });
    window.location.hash = "#/sessions/s-b1";
    render(<App />);
    fireEvent.change(await screen.findByRole("searchbox", { name: "Search this session" }), { target: { value: "npm" } });
    expect(await screen.findByText("No rows in this session match.")).toBeTruthy();
    const search = calls.find((c) => c.path.startsWith("/events"));
    expect(new URLSearchParams(search?.path.split("?")[1]).get("q")).toBe('session:"s-b1" npm');
  });

  it("stored values are shown as text, never as markup", async () => {
    const hostile = { ...fake.flagItem, target: "<img src=x onerror=alert(1)>" };
    fake.install({ ...base, "GET /flags": { status: 200, body: { range: fake.overview.range, items: [hostile], next: null } } });
    window.location.hash = "#/flagged";
    render(<App />);
    expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeTruthy();
    expect(document.querySelector("img:not(.logo)")).toBeNull();
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

describe("search highlighting", () => {
  it("takes free words and quoted phrases, not field:value terms", () => {
    expect(freeTerms('email tool:"CLI agent" "send mail" outcome:denied since:7d Email npm')).toEqual(["email", "send mail", "npm"]);
    expect(freeTerms("outcome:denied")).toEqual([]);
  });
  it("marks every match case-insensitively and keeps stored text as text", () => {
    const { container } = render(<p><Highlight text="hook.sendEMAIL-validate <b>email</b>" terms={["email"]} /></p>);
    expect([...container.querySelectorAll("mark")].map((m) => m.textContent)).toEqual(["EMAIL", "email"]);
    expect(container.querySelector("b")).toBeNull();
    expect(container.textContent).toBe("hook.sendEMAIL-validate <b>email</b>");
  });
  it("marks the match in a session search and shows a process path that matched alone", async () => {
    const byTarget = { ...fake.event, seq: 900, target: "git -c hook.sendemail-validate.enabled=false status" };
    const byProcess = { ...fake.event, seq: 901, target: "/tmp/out.txt", processPath: "/opt/example/email-tool" };
    fake.install({
      ...base,
      "GET /sessions/s-b1": { status: 200, body: fake.timeline },
      "GET /events": { status: 200, body: { ...fake.search, items: [byTarget, byProcess] } },
    });
    window.location.hash = "#/sessions/s-b1";
    render(<App />);
    fireEvent.change(await screen.findByRole("searchbox", { name: "Search this session" }), { target: { value: "email" } });
    await waitFor(() => { expect(document.querySelectorAll("mark")).toHaveLength(2); });
    expect([...document.querySelectorAll("mark")].map((m) => m.textContent)).toEqual(["email", "email"]);
    expect(screen.getByText((_, el) => el?.className === "detail mono" && el.textContent === "process /opt/example/email-tool")).toBeTruthy();
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
    fake.install(coverageRoute([gap("not_running", "stopped"), gap("not_running", "crashed"), gap("machine_off"), gap("before_start"), gap("dropped", "os", 2), gap("dropped", "network", 3), gap("dropped", "agent", 4), gap("paused", null, 9)]));
    render(<App />);
    const pill = await screen.findByText("Not watching: 14 min");
    expect(pill.className).toBe("pill flag");
    expect(pill.title).toContain("not running: 2");
    expect(await screen.findByText("Show 7 gaps")).toBeTruthy();
    const rows = screen.getAllByRole("row").map((r) => r.textContent);
    for (const label of ["Thadam not running (stopped)", "Thadam not running (crashed)", "Mac off · Starting after boot", "2 events dropped by macOS", "3 events dropped by the network extension", "4 events dropped by the hook socket", "Writing paused: disk low (9 events not written)"]) {
      expect(rows.some((r) => r.includes(label)), label).toBe(true);
    }
    expect(screen.getByText("Show 7 gaps")).toBeTruthy();
  });
  it("groups a restart loop and a reboot into single timeline rows", () => {
    const at = (min: number, sec = 0) => new Date(Date.UTC(2026, 10, 15, 2, min, sec)).toISOString();
    const g = (from: string, to: string, reason: string, detail: string | null = null) => ({ from, to, reason, detail, missed: null });
    const loop = Array.from({ length: 10 }, (_, i) => g(at(32, i * 10), at(32, i * 10 + 1), "not_running", "stopped"));
    const groups = groupGaps([g(at(46), at(47), "machine_off"), g(at(47), at(51), "before_start"), ...loop, g(at(18), at(19), "not_running", "crashed")]);
    expect(groups.map((x) => [x.label, x.count, x.from, x.to])).toEqual([
      ["Thadam not running (crashed)", 1, at(18), at(19)],
      ["Thadam not running (stopped)", 10, at(32), at(33, 31)],
      ["Mac off · Starting after boot", 1, at(46), at(51)],
    ]);
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
    expect((await screen.findByText("OS only")).title).toBe("The tool's hooks sent no prompts for this session: it started before the hooks were installed, the tool has no hooks, or no prompt was typed.");
    act(() => { window.location.hash = "#/sessions/s-b1"; window.dispatchEvent(new HashChangeEvent("hashchange")); });
    expect(await screen.findByText("and 2 more")).toBeTruthy();
    expect(screen.getAllByText(/activity in that window is missing/)).toHaveLength(5);
    expect(screen.getByText("OS only: no prompts recorded")).toBeTruthy();
  });
});
