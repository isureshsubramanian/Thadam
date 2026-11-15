// The shell: header (range, chain status, theme, user), navigation, and one view at a
// time, each in its own Error Boundary (ADR-008 Decision 13).
import { Clock, Flag, LayoutGrid, ListTree, LogOut, Moon, Search as SearchIcon, ShieldAlert, ShieldCheck, Sun } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, SignedOut } from "../api/client";
import type { Chain, Meta } from "../api/schemas";
import { Flagged } from "../views/Flagged";
import { Overview } from "../views/Overview";
import { Search } from "../views/Search";
import { Sessions } from "../views/Sessions";
import { HeaderCoverage } from "./coverage";
import { ErrorBoundary } from "./ErrorBoundary";
import { num } from "./format";
import { ranges, resolve, type RangeKey } from "./range";
import { href, useRoute, type Route } from "./route";
import { SignedOutContext } from "./session";
import { SignIn } from "./SignIn";
import { IconButton } from "./ui";


type Theme = "light" | "dark";

export function storedTheme(): Theme | undefined {
  try {
    const t = window.localStorage.getItem("thadam.theme");
    return t === "light" || t === "dark" ? t : undefined;
  } catch {
    return undefined;
  }
}

function useTheme(): [Theme, () => void] {
  const system = (): Theme => (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const [theme, setTheme] = useState<Theme>(() => storedTheme() ?? system());
  useEffect(() => {
    document.documentElement.dataset["theme"] = theme;
  }, [theme]);
  const toggle = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    try {
      window.localStorage.setItem("thadam.theme", next);
    } catch {
      // Private window: the choice lasts for this page only.
    }
  };
  return [theme, toggle];
}

function ChainBadge({ chain }: { chain: Chain }) {
  switch (chain.state) {
    case "verified":
      return (
        <span className="pill ok" title="Hash chain walked end to end over the kept rows">
          <ShieldCheck className="ic" aria-hidden="true" />
          Chain verified{chain.firstSeq !== null && chain.lastSeq !== null ? ` · seq ${num(chain.firstSeq)}–${num(chain.lastSeq)}` : ""}
        </span>
      );
    case "broken":
      return (
        <span className="pill high" role="status">
          <ShieldAlert className="ic" aria-hidden="true" />
          Chain broken{chain.seq !== null ? ` at seq ${num(chain.seq)}` : ""}
        </span>
      );
    case "unreadable":
      return <span className="pill high" role="status"><ShieldAlert className="ic" aria-hidden="true" />Store unreadable</span>;
    case "pending":
      return <span className="pill">Checking chain…</span>;
  }
}

const views: { route: Route; label: string; icon: ReactNode }[] = [
  { route: { view: "overview" }, label: "Overview", icon: <LayoutGrid className="ic" aria-hidden="true" /> },
  { route: { view: "flagged" }, label: "Flagged", icon: <Flag className="ic" aria-hidden="true" /> },
  { route: { view: "sessions" }, label: "Session timeline", icon: <ListTree className="ic" aria-hidden="true" /> },
  { route: { view: "search" }, label: "Search", icon: <SearchIcon className="ic" aria-hidden="true" /> },
];

/** Back on the tab after this long, the range moves to the present. */
const STALE_MS = 60_000;

function Shell({ meta, onSignOut, onChanged }: { meta: Meta; onSignOut: () => void; onChanged: () => void }) {
  const route = useRoute();
  const [theme, toggleTheme] = useTheme();
  const [rangeKey, setRangeKey] = useState<RangeKey>("7d");
  // The range ends at `at.now`. It holds still while you work in a view, so a grid's pages
  // do not shift under you, and moves to the present when you pick a range, open another
  // view, or come back to the tab after a while; otherwise an open dashboard would never
  // show newer activity.
  const [at, setAt] = useState(() => ({ view: route.view, now: new Date() }));
  if (at.view !== route.view) setAt({ view: route.view, now: new Date() });
  useEffect(() => {
    const back = () => {
      if (document.visibilityState === "visible") {
        setAt((a) => (Date.now() - a.now.getTime() > STALE_MS ? { ...a, now: new Date() } : a));
      }
    };
    document.addEventListener("visibilitychange", back);
    return () => { document.removeEventListener("visibilitychange", back); };
  }, []);
  const range = useMemo(() => resolve(rangeKey, at.now), [rangeKey, at.now]);

  const body = (() => {
    switch (route.view) {
      case "overview":
        return <Overview range={range} />;
      case "flagged":
        return <Flagged range={range} onChanged={onChanged} />;
      case "sessions":
        return <Sessions range={range} sessionId={route.sessionId} />;
      case "search":
        return <Search key={route.q ?? ""} q={route.q} />;
    }
  })();

  return (
    <div className="app">
      <header className="top">
        <div className="row brand">
          <img className="logo" src="/favicon.svg" alt="" width={34} height={34} />
          <div>
            <span className="name">Thadam</span>
            <span className="muted small">AI tool audit · this Mac</span>
          </div>
        </div>
        <span className="spacer" />
        <label className="row rangepick">
          <Clock className="ic" aria-hidden="true" />
          <span className="vh">Time range</span>
          <select value={rangeKey} onChange={(e) => { setRangeKey(e.target.value as RangeKey); setAt((a) => ({ ...a, now: new Date() })); }}>
            {ranges.map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}
          </select>
        </label>
        <ChainBadge chain={meta.chain} />
        <ErrorBoundary key={`${range.from}${range.to}`} area="coverage"><HeaderCoverage range={range} /></ErrorBoundary>
        <IconButton label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"} onClick={toggleTheme}>
          {theme === "dark" ? <Sun className="ic" aria-hidden="true" /> : <Moon className="ic" aria-hidden="true" />}
        </IconButton>
        {meta.user !== null && <span className="muted">{meta.user}</span>}
        <IconButton label="Sign out" onClick={onSignOut}>
          <LogOut className="ic" aria-hidden="true" />
        </IconButton>
      </header>
      <div className="layout">
        <nav aria-label="Views" className="side">
          {views.map((v) => (
            <a key={v.label} className={`nav${v.route.view === route.view ? " on" : ""}`} href={href(v.route)}
              aria-current={v.route.view === route.view ? "page" : undefined}>
              {v.icon}<span>{v.label}</span>
            </a>
          ))}
          <div className="tools">
            <span className="kl">Registered tools</span>
            {meta.tools.map((t) => <span key={t.key} className="tool">{t.displayName}</span>)}
            <span className="muted small">Matched by code-signing identity. Display names come from the registry.</span>
          </div>
          <a className="muted small" href="/notices" target="_blank" rel="noreferrer">Third-party notices</a>
        </nav>
        <main className="main">
          <ErrorBoundary key={route.view} area={route.view}>
            {body}
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}

export function App() {
  const [meta, setMeta] = useState<Meta | null>();
  const [failed, setFailed] = useState(false);
  const load = useCallback(() => {
    api.meta().then(
      (m) => { setMeta(m); },
      (e: unknown) => {
        if (e instanceof SignedOut) setMeta(null);
        else setFailed(true);
      },
    );
  }, []);
  useEffect(load, [load]);
  const signedOut = useCallback(() => { setMeta(null); }, []);
  const signOut = () => {
    api.signOut().then(signedOut, signedOut);
  };

  if (failed) {
    return <main className="signin"><p className="card pad" role="alert">Thadam's API is not answering. Is it running?</p></main>;
  }
  if (meta === undefined) return null;
  if (meta === null) return <SignIn onSignedIn={load} />;
  return (
    <SignedOutContext.Provider value={signedOut}>
      <Shell meta={meta} onSignOut={signOut} onChanged={load} />
    </SignedOutContext.Provider>
  );
}
