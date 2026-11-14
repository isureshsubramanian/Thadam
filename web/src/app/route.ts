// Hash routes (ADR-008 Decision 13: no router library). #/overview, #/flagged,
// #/sessions, #/sessions/<id>, #/search?q=<text>.
import { useEffect, useState } from "react";

export type Route =
  | { view: "overview" }
  | { view: "flagged" }
  | { view: "sessions"; sessionId?: string | undefined }
  | { view: "search"; q?: string | undefined };

export function parse(hash: string): Route {
  const [path = "", search = ""] = hash.replace(/^#\/?/, "").split("?", 2);
  const [view, id] = path.split("/", 2);
  switch (view) {
    case "flagged":
      return { view: "flagged" };
    case "sessions":
      return { view: "sessions", sessionId: id ? decodeURIComponent(id) : undefined };
    case "search":
      return { view: "search", q: new URLSearchParams(search).get("q") ?? undefined };
    default:
      return { view: "overview" };
  }
}

export function href(r: Route): string {
  switch (r.view) {
    case "overview":
    case "flagged":
      return `#/${r.view}`;
    case "sessions":
      return r.sessionId ? `#/sessions/${encodeURIComponent(r.sessionId)}` : "#/sessions";
    case "search":
      return r.q ? `#/search?${new URLSearchParams({ q: r.q }).toString()}` : "#/search";
  }
}

export function go(r: Route): void {
  window.location.hash = href(r);
}

export function useRoute(): Route {
  const [route, setRoute] = useState(() => parse(window.location.hash));
  useEffect(() => {
    const on = () => { setRoute(parse(window.location.hash)); };
    window.addEventListener("hashchange", on);
    return () => { window.removeEventListener("hashchange", on); };
  }, []);
  return route;
}
