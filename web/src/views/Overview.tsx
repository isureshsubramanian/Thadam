// Overview (mock-up view 1): KPI tiles, activity by tool, outside project by folder, hosts.
import { api } from "../api/client";
import type { Overview as Data } from "../api/schemas";
import { bytes, categoryName, count, num, words } from "../app/format";
import type { TimeRange } from "../app/range";
import { go, type Route } from "../app/route";
import { Empty, Loading, PageHead } from "../app/ui";
import { useApi } from "../app/useApi";

interface Kpi {
  label: string;
  value: string;
  sub: string;
  to: Route;
}

function kpis(d: Data): Kpi[] {
  const k = d.kpis;
  const open = k.flaggedOpen.high + k.flaggedOpen.medium + k.flaggedOpen.low;
  const sensitive = Object.entries(k.sensitive);
  return [
    { label: "Sessions", value: num(k.sessions), sub: `${count(d.byTool.length, "tool")} active`, to: { view: "sessions" } },
    {
      label: "Outside project",
      value: num(k.outsideProject.records),
      sub: `records in ${count(k.outsideProject.folders, "folder")}`,
      to: { view: "search", q: "flag:outside-project" },
    },
    {
      label: "Flagged, open",
      value: num(open),
      sub: `${num(k.flaggedOpen.high)} high · ${num(k.flaggedOpen.medium)} medium · ${num(k.flaggedOpen.low)} low`,
      to: { view: "flagged" },
    },
    {
      label: "Denied",
      value: num(k.denied.byAgent + k.denied.byUser + k.denied.byOs),
      sub: `${num(k.denied.byAgent)} by agent · ${num(k.denied.byUser)} by user · ${num(k.denied.byOs)} by OS`,
      to: { view: "search", q: "outcome:denied" },
    },
    {
      label: "Hosts contacted",
      value: num(k.hosts.total),
      sub: `${num(k.hosts.unknown)} unknown · ${num(k.hosts.networkVolume)} network volume`,
      to: { view: "search", q: "category:network-external" },
    },
    {
      label: "Sensitive data",
      value: num(sensitive.reduce((n, [, v]) => n + v, 0)),
      sub: sensitive.length === 0 ? "none detected" : sensitive.map(([kind, n]) => `${num(n)} ${kind.toLowerCase()}`).join(" · "),
      to: { view: "search", q: "flag:secret-pattern" },
    },
  ];
}

export function Overview({ range }: { range: TimeRange }) {
  const { data, loading } = useApi((signal) => api.overview(range, signal), [range.from, range.to]);
  if (data === undefined) return loading ? <Loading /> : null;
  const maxFolder = Math.max(1, ...data.outsideFolders.map((f) => f.records));
  return (
    <div className="stack">
      <PageHead title="Overview" sub="All registered AI tools · rows kept after filtering to AI tool process trees" />
      <div className="kpis">
        {kpis(data).map((k) => (
          <button key={k.label} type="button" className="card kpi" onClick={() => { go(k.to); }} aria-label={`${k.label}: ${k.value}, ${k.sub}`}>
            <span className="kl">{k.label}</span>
            <span className="kv">{k.value}</span>
            <span className="ks">{k.sub}</span>
          </button>
        ))}
      </div>

      <section className="card" aria-labelledby="bytool">
        <div className="cardhead">
          <h2 id="bytool" className="h2">Activity by tool</h2>
        </div>
        <div className="scroll">
          <table className="tbl">
            <thead>
              <tr>
                <th>Tool</th><th className="num">Sessions</th><th className="num">Files read</th><th className="num">Files written</th>
                <th className="num">Commands</th><th className="num">Denied</th><th className="num">Outside project</th>
                <th className="num">Hosts</th><th className="num">Flagged</th>
              </tr>
            </thead>
            <tbody>
              {data.byTool.map((t) => (
                <tr key={t.tool}>
                  <td>{t.displayName}</td><td className="num">{num(t.sessions)}</td><td className="num">{num(t.filesRead)}</td>
                  <td className="num">{num(t.filesWritten)}</td><td className="num">{num(t.commands)}</td><td className="num">{num(t.denied)}</td>
                  <td className="num">{num(t.outside)}</td><td className="num">{num(t.hosts)}</td><td className="num">{num(t.flagged)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {data.byTool.length === 0 && <Empty>No activity in this range.</Empty>}
        </div>
      </section>

      <div className="two">
        <section className="card pad" aria-labelledby="byfolder">
          <h2 id="byfolder" className="h2">Outside project, by folder</h2>
          <p className="sub">
            {count(data.kpis.outsideProject.records, "record")} in {count(data.kpis.outsideProject.folders, "folder")} · repeated opens collapsed per session
          </p>
          {data.outsideFolders.length === 0 && <Empty>Nothing outside the project.</Empty>}
          <ul className="bars">
            {data.outsideFolders.map((f) => (
              <li key={f.folder}>
                <div className="barhead">
                  <span className="mono clip">{f.folder}</span>
                  {f.flags.map((fl) => <span key={fl} className="pill flag">{words(fl)}</span>)}
                  <span className="muted">{count(f.tools.length, "tool")}</span>
                  <span className="numv">{num(f.records)}</span>
                </div>
                <div className="bar" aria-hidden="true">
                  <div style={{ width: `${String(Math.max(2, (f.records / maxFolder) * 100))}%` }} />
                </div>
              </li>
            ))}
          </ul>
        </section>

        <section className="card pad" aria-labelledby="bydest">
          <h2 id="bydest" className="h2">Where tools connected</h2>
          <p className="sub">{count(data.hosts.length, "host")} · host, port and bytes only, no URLs</p>
          {data.hosts.length === 0 && <Empty>No network activity recorded.</Empty>}
          <ul className="hosts">
            {data.hosts.map((h) => (
              <li key={`${h.target} ${h.category}`}>
                <span className="mono clip">{h.target}</span>
                <span className="pill">{categoryName[h.category] ?? words(h.category)}</span>
                {h.unknown && <span className="pill flag">unknown host</span>}
                <span className="muted numv">↑ {bytes(h.bytesOut)} · ↓ {bytes(h.bytesIn)}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}
