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

  it("a rejected search names the field, not the text typed", async () => {
    fake.install({ ...base, "GET /events": { status: 400, body: { errors: ["q.tool"] } } });
    window.location.hash = `#/search?q=${encodeURIComponent("tool:secret_name")}`;
    render(<App />);
    const alert = await screen.findByText("Check the tool: value.");
    expect(alert.textContent).not.toContain("secret_name");
  });
});
