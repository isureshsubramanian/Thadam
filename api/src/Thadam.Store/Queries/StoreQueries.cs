using Microsoft.Data.Sqlite;

namespace Thadam.Store.Queries;

/// <summary>
/// The dashboard's read queries (ADR-008 Decision 4) over the kept segments. Each query
/// opens only the segments whose rows overlap its time range, runs the same parameterised
/// SQL in each, and merges the results by seq. Values are never put into SQL text.
/// </summary>
public sealed class StoreQueries(SegmentIndex index)
{
    /// <summary>Rows a page holds (ADR-008 Decision 4: one screen and a scroll, an estimate).</summary>
    public const int PageSize = 200;
    private const int MaxListed = 100;
    private const int MaxSessionTree = 1000;

    private const string BaseColumns = """
        seq, event_id, ts_us, tool, session_id, parent_session_id, pid, process_path, category, action,
        target, outcome, size_bytes, bytes_out, bytes_in, project, flags, count, detections, source
        """;

    internal static string Columns(int version) => BaseColumns + (version == 3
        ? ", agent_session_id, transcript"
        : ", NULL AS agent_session_id, NULL AS transcript");

    /// <summary>The row columns plus the chain hash, last (ADR-012 Decision 2).</summary>
    internal static string ExportColumns(int version) => Columns(version) + ", hash";

    internal static ExportRow ReadExportRow(SqliteDataReader r) =>
        new(ReadEvent(r), Convert.ToHexStringLower(r.GetFieldValue<byte[]>(r.FieldCount - 1)));

    private const string NotInternal =
        " AND instr(',' || flags || ',', ',tool_internal,') = 0 AND instr(',' || flags || ',', ',internal,') = 0";

    internal const string FlaggedCondition =
        "(flags != '' OR detections != '' OR outcome IN ('denied_by_agent', 'denied_by_user', 'denied_by_os', 'never_ran'))";

    public SegmentIndex Index => index;

    public async Task<Overview> OverviewAsync(Filter filter, IReadOnlySet<string> reviewed, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(filter);
        var tools = new Dictionary<string, ToolAcc>(StringComparer.Ordinal);
        ToolAcc Tool(string t) => tools.TryGetValue(t, out var a) ? a : tools[t] = new ToolAcc();
        var outside = new Dictionary<string, (long Records, SortedSet<string> Tools, SortedSet<string> Flags)>(StringComparer.Ordinal);
        long outsideRecords = 0;
        var hosts = new Dictionary<(string Target, string Category), HostTally>();
        var sensitive = new SortedDictionary<string, long>(StringComparer.Ordinal);
        long deniedAgent = 0, deniedUser = 0, deniedOs = 0;

        foreach (var span in await index.OverlappingAsync(filter.Range, ct).ConfigureAwait(false))
        {
            await using var conn = await index.OpenAsync(span, ct).ConfigureAwait(false);
            await foreach (var r in QueryAsync(conn, filter, """
                SELECT tool,
                    sum(CASE WHEN category = 'file' AND action = 'read' THEN count ELSE 0 END),
                    sum(CASE WHEN category = 'file' AND action IN ('write', 'create', 'rename', 'delete') THEN count ELSE 0 END),
                    sum(CASE WHEN category = 'command' THEN count ELSE 0 END),
                    sum(CASE WHEN outcome = 'denied_by_agent' THEN count ELSE 0 END),
                    sum(CASE WHEN outcome = 'denied_by_user' THEN count ELSE 0 END),
                    sum(CASE WHEN outcome = 'denied_by_os' THEN count ELSE 0 END)
                FROM events WHERE {filter} GROUP BY tool
                """, null, ct).ConfigureAwait(false))
            {
                var a = Tool(r.GetString(0));
                a.FilesRead += r.GetInt64(1);
                a.FilesWritten += r.GetInt64(2);
                a.Commands += r.GetInt64(3);
                a.Denied += r.GetInt64(4) + r.GetInt64(5) + r.GetInt64(6);
                deniedAgent += r.GetInt64(4);
                deniedUser += r.GetInt64(5);
                deniedOs += r.GetInt64(6);
            }
            await foreach (var r in QueryAsync(conn, filter,
                "SELECT DISTINCT tool, session_id FROM events WHERE {filter} AND session_id IS NOT NULL", null, ct).ConfigureAwait(false))
            {
                Tool(r.GetString(0)).Sessions.Add(r.GetString(1));
            }
            await foreach (var r in QueryAsync(conn, filter,
                "SELECT tool, target, flags FROM events WHERE {filter} AND instr(',' || flags || ',', ',outside_project,') > 0", null, ct).ConfigureAwait(false))
            {
                var tool = r.GetString(0);
                Tool(tool).Outside++;
                outsideRecords++;
                var key = Values.OutsideFolder(r.GetString(1));
                if (!outside.TryGetValue(key, out var o))
                {
                    o = (0, new SortedSet<string>(StringComparer.Ordinal), new SortedSet<string>(StringComparer.Ordinal));
                }
                o.Tools.Add(tool);
                foreach (var f in Values.Flags(r.GetString(2)).Where(f => f != "outside_project"))
                {
                    o.Flags.Add(f);
                }
                outside[key] = (o.Records + 1, o.Tools, o.Flags);
            }
            await foreach (var r in QueryAsync(conn, filter,
                "SELECT tool, target, category, " + HostTally.Columns
                    + " FROM events WHERE {filter} AND category LIKE 'network%' GROUP BY tool, target, category",
                null, ct).ConfigureAwait(false))
            {
                var key = (r.GetString(1), r.GetString(2));
                Tool(r.GetString(0)).Hosts.Add(key.Item1);
                var h = hosts.TryGetValue(key, out var x) ? x : hosts[key] = new HostTally();
                h.Add(r, 3);
            }
            await foreach (var r in QueryAsync(conn, filter,
                "SELECT detections FROM events WHERE {filter} AND detections != ''", null, ct).ConfigureAwait(false))
            {
                foreach (var (kind, n) in Values.Detections(r.GetString(0)))
                {
                    sensitive[kind] = sensitive.GetValueOrDefault(kind) + n;
                }
            }
        }

        var items = await FlagItemsAsync(filter, reviewed, ct).ConfigureAwait(false);
        var open = items.Where(i => !i.Reviewed).ToList();
        foreach (var i in open)
        {
            Tool(i.Tool).FlaggedOpen++;
        }
        return new Overview(
            tools.Values.SelectMany(t => t.Sessions).Distinct(StringComparer.Ordinal).Count(),
            outsideRecords,
            outside.Count,
            Enum.GetValues<Severity>().ToDictionary(s => s, s => open.Count(i => i.Severity == s)),
            deniedAgent,
            deniedUser,
            deniedOs,
            hosts.Keys.Select(k => k.Target).Distinct(StringComparer.Ordinal).Count(),
            hosts.Where(h => h.Value.Unknown).Select(h => h.Key.Target).Distinct(StringComparer.Ordinal).Count(),
            hosts.Keys.Where(k => k.Category == "network_volume").Select(k => k.Target).Distinct(StringComparer.Ordinal).Count(),
            sensitive,
            [.. tools.OrderBy(t => t.Key, StringComparer.Ordinal).Select(t => new ToolStats(
                t.Key, t.Value.Sessions.Count, t.Value.FilesRead, t.Value.FilesWritten, t.Value.Commands,
                t.Value.Denied, t.Value.Outside, t.Value.Hosts.Count, t.Value.FlaggedOpen))],
            [.. outside.OrderByDescending(o => o.Value.Records).ThenBy(o => o.Key, StringComparer.Ordinal).Take(MaxListed)
                .Select(o => new OutsideFolder(o.Key, o.Value.Records, [.. o.Value.Tools], [.. o.Value.Flags]))],
            [.. hosts.OrderByDescending(h => h.Value.BytesOut).ThenBy(h => h.Key.Target, StringComparer.Ordinal).Take(MaxListed)
                .Select(h => h.Value.ToStats(h.Key.Target, h.Key.Category))]);
    }

    /// <summary>Every flagged-queue item in the range, newest first.</summary>
    public async Task<IReadOnlyList<FlagItem>> FlagItemsAsync(Filter filter, IReadOnlySet<string> reviewed, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(filter);
        ArgumentNullException.ThrowIfNull(reviewed);
        var groups = new Dictionary<(string Rule, string Target, string? Session), FlagAcc>();
        foreach (var span in await index.OverlappingAsync(filter.Range, ct).ConfigureAwait(false))
        {
            await using var conn = await index.OpenAsync(span, ct).ConfigureAwait(false);
            await foreach (var r in QueryAsync(conn, filter, $"""
                SELECT seq, event_id, ts_us, tool, session_id, target, flags, outcome, action, detections, count
                FROM events WHERE {"{filter}"} AND {FlaggedCondition}
                """, null, ct).ConfigureAwait(false))
            {
                if (SeverityRule.Classify(Values.Flags(r.GetString(6)), r.GetString(7), r.GetString(8), r.GetString(9))
                    is not { } c)
                {
                    continue;
                }
                var session = r.IsDBNull(4) ? null : r.GetString(4);
                var key = (c.Rule, r.GetString(5), session);
                var seq = r.GetInt64(0);
                var ts = r.GetInt64(2);
                if (!groups.TryGetValue(key, out var g))
                {
                    g = groups[key] = new FlagAcc(c.Severity, r.GetString(3), ts);
                }
                g.Rows++;
                g.Count += r.GetInt64(10);
                g.FirstTs = Math.Min(g.FirstTs, ts);
                g.LastTs = Math.Max(g.LastTs, ts);
                if (seq > g.LastSeq)
                {
                    g.LastSeq = seq;
                    g.LastEventId = r.GetString(1);
                }
            }
        }
        return [.. groups
            .Select(kv => new FlagItem(kv.Key.Rule, kv.Value.Severity, kv.Key.Target, kv.Key.Session, kv.Value.Tool,
                kv.Value.Rows, kv.Value.Count, kv.Value.FirstTs, kv.Value.LastTs, kv.Value.LastSeq, kv.Value.LastEventId,
                reviewed.Contains(kv.Value.LastEventId)))
            .OrderByDescending(i => i.LastSeq)];
    }

    /// <summary>Sessions with rows in the range, most recently active first.</summary>
    public async Task<IReadOnlyList<SessionSummary>> SessionsAsync(Filter filter, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(filter);
        var spans = await index.OverlappingAsync(filter.Range, ct).ConfigureAwait(false);
        return await SummariseAsync(spans, filter, null, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// A session and the sessions delegated from it (and from those, recursively), as
    /// summaries, root first; empty when the session is unknown.
    /// </summary>
    public async Task<IReadOnlyList<SessionSummary>> SessionTreeAsync(string sessionId, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(sessionId);
        var spans = await index.ListAsync(ct).ConfigureAwait(false);
        var ids = new List<string> { sessionId };
        var frontier = new List<string> { sessionId };
        while (frontier.Count > 0 && ids.Count < MaxSessionTree)
        {
            var next = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var span in spans)
            {
                await using var conn = await index.OpenAsync(span, ct).ConfigureAwait(false);
                await foreach (var r in QueryAsync(conn, null,
                    $"SELECT DISTINCT session_id FROM events WHERE parent_session_id IN ({InList(frontier.Count)}) AND session_id IS NOT NULL",
                    frontier, ct).ConfigureAwait(false))
                {
                    next.Add(r.GetString(0));
                }
            }
            frontier = [.. next.Where(s => !ids.Contains(s))];
            ids.AddRange(frontier);
        }
        var all = await SummariseAsync(spans, null, ids, ct).ConfigureAwait(false);
        return [.. all.OrderBy(s => s.SessionId == sessionId ? 0 : 1).ThenBy(s => s.FirstTsUs)];
    }

    /// <summary>Rows of the given sessions after <paramref name="afterSeq"/>, in seq order.</summary>
    public async Task<Page<EventView>> TimelineAsync(
        IReadOnlyList<string> sessionIds, bool includeInternal, long afterSeq, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(sessionIds);
        var rows = new List<EventView>();
        if (sessionIds.Count == 0)
        {
            return new Page<EventView>(rows, null);
        }
        var internalClause = includeInternal ? "" : NotInternal;
        foreach (var span in (await index.ListAsync(ct).ConfigureAwait(false)).OrderBy(s => s.FirstSeq))
        {
            await using var conn = await index.OpenAsync(span, ct).ConfigureAwait(false);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = $"""
                SELECT {Columns(await StoreFolder.SegmentVersionAsync(conn, ct).ConfigureAwait(false))} FROM events
                WHERE session_id IN ({InList(sessionIds.Count)}) AND seq > $after{internalClause}
                ORDER BY seq LIMIT $limit
                """;
            AddList(cmd, sessionIds);
            cmd.Parameters.AddWithValue("$after", afterSeq);
            cmd.Parameters.AddWithValue("$limit", PageSize + 1 - rows.Count);
            await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                rows.Add(ReadEvent(r));
            }
            if (rows.Count > PageSize)
            {
                break;
            }
        }
        return rows.Count > PageSize
            ? new Page<EventView>(rows[..PageSize], rows[PageSize - 1].Seq)
            : new Page<EventView>(rows, null);
    }

    /// <summary>The newest kept row's seq, or 0 for an empty store: what an export is "as of".</summary>
    public async Task<long> NewestSeqAsync(CancellationToken ct)
    {
        long newest = 0;
        foreach (var span in await index.ListAsync(ct).ConfigureAwait(false))
        {
            await using var conn = await index.OpenAsync(span, ct).ConfigureAwait(false);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT coalesce(max(seq), 0) FROM events";
            newest = Math.Max(newest, (long)(await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L));
        }
        return newest;
    }

    /// <summary>How many rows a timeline export as of <paramref name="upToSeq"/> holds (ADR-012).</summary>
    public async Task<long> TimelineCountAsync(
        IReadOnlyList<string> sessionIds, bool includeInternal, long upToSeq, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(sessionIds);
        long total = 0;
        if (sessionIds.Count == 0)
        {
            return total;
        }
        foreach (var span in await index.ListAsync(ct).ConfigureAwait(false))
        {
            await using var conn = await index.OpenAsync(span, ct).ConfigureAwait(false);
            await using var cmd = TimelineCommand(conn, "count(*)", sessionIds, includeInternal, upToSeq);
            total += (long)(await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L);
        }
        return total;
    }

    /// <summary>The rows <see cref="TimelineCountAsync"/> counted, oldest first, with chain hashes.</summary>
    public async IAsyncEnumerable<ExportRow> TimelineRowsAsync(
        IReadOnlyList<string> sessionIds, bool includeInternal, long upToSeq,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(sessionIds);
        if (sessionIds.Count == 0)
        {
            yield break;
        }
        foreach (var span in (await index.ListAsync(ct).ConfigureAwait(false)).OrderBy(s => s.FirstSeq))
        {
            await using var conn = await index.OpenAsync(span, ct).ConfigureAwait(false);
            var columns = ExportColumns(await StoreFolder.SegmentVersionAsync(conn, ct).ConfigureAwait(false));
            await using var cmd = TimelineCommand(conn, columns, sessionIds, includeInternal, upToSeq);
            cmd.CommandText += " ORDER BY seq";
            await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                yield return ReadExportRow(r);
            }
        }
    }

    private static SqliteCommand TimelineCommand(
        SqliteConnection conn, string select, IReadOnlyList<string> sessionIds, bool includeInternal, long upToSeq)
    {
        var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {select} FROM events WHERE session_id IN ({InList(sessionIds.Count)}) AND seq <= $upTo"
            + (includeInternal ? "" : NotInternal);
        AddList(cmd, sessionIds);
        cmd.Parameters.AddWithValue("$upTo", upToSeq);
        return cmd;
    }

    /// <summary>The row with this event ID, from any kept segment.</summary>
    public async Task<EventView?> FindEventAsync(string eventId, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(eventId);
        foreach (var span in await index.ListAsync(ct).ConfigureAwait(false))
        {
            await using var conn = await index.OpenAsync(span, ct).ConfigureAwait(false);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = $"SELECT {Columns(await StoreFolder.SegmentVersionAsync(conn, ct).ConfigureAwait(false))} FROM events WHERE event_id = $id";
            cmd.Parameters.AddWithValue("$id", eventId);
            await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            if (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                return ReadEvent(r);
            }
        }
        return null;
    }

    private async Task<IReadOnlyList<SessionSummary>> SummariseAsync(
        IReadOnlyList<SegmentSpan> spans, Filter? filter, List<string>? ids, CancellationToken ct)
    {
        var merged = new Dictionary<string, SessionSummary>(StringComparer.Ordinal);
        var idClause = ids is null ? "" : $" AND session_id IN ({InList(ids.Count)})";
        foreach (var span in spans)
        {
            await using var conn = await index.OpenAsync(span, ct).ConfigureAwait(false);
            await foreach (var r in QueryAsync(conn, filter, $"""
                SELECT session_id, tool, max(parent_session_id), max(project), min(ts_us), max(ts_us), count(*), sum(count), max(seq), sum(source = 'agent' AND category = 'prompt')
                FROM events WHERE {(filter is null ? "1" : "{filter}")} AND session_id IS NOT NULL{idClause}
                GROUP BY session_id, tool
                """, ids, ct).ConfigureAwait(false))
            {
                var s = new SessionSummary(
                    r.GetString(0), r.GetString(1), r.IsDBNull(2) ? null : r.GetString(2), r.IsDBNull(3) ? null : r.GetString(3),
                    r.GetInt64(4), r.GetInt64(5), r.GetInt64(6), r.GetInt64(7), r.GetInt64(8), r.GetInt64(9));
                merged[s.SessionId] = merged.TryGetValue(s.SessionId, out var m)
                    ? m with
                    {
                        ParentSessionId = m.ParentSessionId ?? s.ParentSessionId,
                        Project = m.Project ?? s.Project,
                        FirstTsUs = Math.Min(m.FirstTsUs, s.FirstTsUs),
                        LastTsUs = Math.Max(m.LastTsUs, s.LastTsUs),
                        Rows = m.Rows + s.Rows,
                        Events = m.Events + s.Events,
                        Prompts = m.Prompts + s.Prompts,
                        LastSeq = Math.Max(m.LastSeq, s.LastSeq),
                    }
                    : s;
            }
        }
        return [.. merged.Values.OrderByDescending(s => s.LastSeq)];
    }

    /// <summary>
    /// Runs <paramref name="sql"/> with <c>{filter}</c> replaced by the time (and tool)
    /// condition, and <c>$p0..$pN</c> bound to <paramref name="list"/>.
    /// </summary>
    private static async IAsyncEnumerable<SqliteDataReader> QueryAsync(
        SqliteConnection conn, Filter? filter, string sql, IReadOnlyList<string>? list,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        var condition = filter is null
            ? "1"
            : filter.Tool is null ? "ts_us BETWEEN $from AND $to" : "ts_us BETWEEN $from AND $to AND tool = $tool";
        cmd.CommandText = sql.Replace("{filter}", condition, StringComparison.Ordinal);
        if (filter is not null)
        {
            cmd.Parameters.AddWithValue("$from", filter.Range.FromUs);
            cmd.Parameters.AddWithValue("$to", filter.Range.ToUs);
            if (filter.Tool is not null)
            {
                cmd.Parameters.AddWithValue("$tool", filter.Tool);
            }
        }
        if (list is not null)
        {
            AddList(cmd, list);
        }
        await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await r.ReadAsync(ct).ConfigureAwait(false))
        {
            yield return r;
        }
    }

    private static string InList(int n) => string.Join(", ", Enumerable.Range(0, n).Select(i => $"$p{i}"));

    private static void AddList(SqliteCommand cmd, IReadOnlyList<string> list)
    {
        for (var i = 0; i < list.Count; i++)
        {
            cmd.Parameters.AddWithValue($"$p{i}", list[i]);
        }
    }

    internal static EventView ReadEvent(SqliteDataReader r)
    {
        var row = ChainVerifier.ReadRow(r);
        var flags = Values.Flags(row.Flags);
        var c = SeverityRule.Classify(flags, row.Outcome, row.Action, row.Detections);
        return new EventView(row.Seq, row.EventId, row.TsUs, row.Tool, row.SessionId, row.ParentSessionId, row.Pid,
            row.ProcessPath, row.Category, row.Action, row.Target, row.Outcome, row.SizeBytes, row.BytesOut, row.BytesIn,
            row.Project, flags, row.Count, Values.Detections(row.Detections), row.Source, c?.Severity, c?.Rule, row.AgentSessionId, row.Transcript);
    }

    private sealed class ToolAcc
    {
        public HashSet<string> Sessions { get; } = new(StringComparer.Ordinal);
        public HashSet<string> Hosts { get; } = new(StringComparer.Ordinal);
        public long FilesRead { get; set; }
        public long FilesWritten { get; set; }
        public long Commands { get; set; }
        public long Denied { get; set; }
        public long Outside { get; set; }
        public int FlaggedOpen { get; set; }
    }

    private sealed class FlagAcc(Severity severity, string tool, long ts)
    {
        public Severity Severity { get; } = severity;
        public string Tool { get; } = tool;
        public long Rows { get; set; }
        public long Count { get; set; }
        public long FirstTs { get; set; } = ts;
        public long LastTs { get; set; } = ts;
        public long LastSeq { get; set; } = long.MinValue;
        public string LastEventId { get; set; } = "";
    }
}
