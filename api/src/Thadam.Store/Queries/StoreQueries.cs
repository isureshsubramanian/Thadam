using Microsoft.Data.Sqlite;

namespace Thadam.Store.Queries;

/// <summary>
/// The dashboard's read queries (ADR-008 Decision 4) over the kept segments. Each query
/// opens only the segments whose rows overlap its time range, runs the same parameterised
/// SQL in each, and merges the results by seq. Values are never put into SQL text.
/// </summary>
public sealed class StoreQueries(SegmentIndex index, TimeProvider time, int keepUpTo)
{
    private readonly ListCache<FlagGroups> _flags = new(time, keepUpTo);
    private readonly ListCache<SessionGroups> _sessions = new(time, keepUpTo);

    public StoreQueries(SegmentIndex index, TimeProvider time) : this(index, time, ListCache<object>.MaxGroups) { }

    public StoreQueries(SegmentIndex index) : this(index, TimeProvider.System) { }

    /// <summary>Lists kept now, both kinds (for tests).</summary>
    internal int KeptLists => _flags.Count + _sessions.Count;

    /// <summary>Rows a page holds when the caller names no size (ADR-014 Decision 1).</summary>
    public const int DefaultPageSize = 50;
    /// <summary>The most rows one page may hold (ADR-008 Decision 4; ADR-014 Decision 1).</summary>
    public const int MaxPageSize = 200;
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

        // Every scan of every segment runs at once, each on its own connection, beside the
        // flagged-queue scan. Each fold below is a sum, a set or a newest-by-seq, so the order
        // rows arrive in does not matter. One lock.
        var gate = new Lock();
        var flagged = FlagItemsAsync(filter, reviewed, ct);
        Func<SqliteConnection, CancellationToken, Task>[] scans =
        [
            // Totals and sessions in one pass: per tool and session, added up per tool here.
            async (conn, ct) =>
            {
                await foreach (var r in QueryAsync(conn, filter, """
                    SELECT tool, session_id,
                        sum(CASE WHEN category = 'file' AND action = 'read' THEN count ELSE 0 END),
                        sum(CASE WHEN category = 'file' AND action IN ('write', 'create', 'rename', 'delete') THEN count ELSE 0 END),
                        sum(CASE WHEN category = 'command' THEN count ELSE 0 END),
                        sum(CASE WHEN outcome = 'denied_by_agent' THEN count ELSE 0 END),
                        sum(CASE WHEN outcome = 'denied_by_user' THEN count ELSE 0 END),
                        sum(CASE WHEN outcome = 'denied_by_os' THEN count ELSE 0 END)
                    FROM events WHERE {filter} GROUP BY tool, session_id
                    """, null, ct).ConfigureAwait(false))
                {
                    lock (gate)
                    {
                        var a = Tool(r.GetString(0));
                        if (!r.IsDBNull(1))
                        {
                            a.Sessions.Add(r.GetString(1));
                        }
                        a.FilesRead += r.GetInt64(2);
                        a.FilesWritten += r.GetInt64(3);
                        a.Commands += r.GetInt64(4);
                        a.Denied += r.GetInt64(5) + r.GetInt64(6) + r.GetInt64(7);
                        deniedAgent += r.GetInt64(5);
                        deniedUser += r.GetInt64(6);
                        deniedOs += r.GetInt64(7);
                    }
                }
            },
            // Counted by folder in SQL, with the same folder rule, instead of a row each into here.
            async (conn, ct) =>
            {
                conn.CreateFunction("outside_folder", (string path) => Values.OutsideFolder(path), isDeterministic: true);
                await foreach (var r in QueryAsync(conn, filter, """
                    SELECT tool, outside_folder(target), flags, count(*) FROM events
                    WHERE {filter} AND instr(',' || flags || ',', ',outside_project,') > 0
                    GROUP BY 1, 2, 3
                    """, null, ct).ConfigureAwait(false))
                {
                    lock (gate)
                    {
                        var tool = r.GetString(0);
                        var n = r.GetInt64(3);
                        Tool(tool).Outside += n;
                        outsideRecords += n;
                        var key = r.GetString(1);
                        if (!outside.TryGetValue(key, out var o))
                        {
                            o = (0, new SortedSet<string>(StringComparer.Ordinal), new SortedSet<string>(StringComparer.Ordinal));
                        }
                        o.Tools.Add(tool);
                        foreach (var f in Values.Flags(r.GetString(2)).Where(f => f != "outside_project"))
                        {
                            o.Flags.Add(f);
                        }
                        outside[key] = (o.Records + n, o.Tools, o.Flags);
                    }
                }
            },
            async (conn, ct) =>
            {
                await foreach (var r in QueryAsync(conn, filter,
                    "SELECT tool, target, category, " + HostTally.Columns
                        + " FROM events WHERE {filter} AND category LIKE 'network%' GROUP BY tool, target, category",
                    null, ct).ConfigureAwait(false))
                {
                    lock (gate)
                    {
                        var key = (r.GetString(1), r.GetString(2));
                        Tool(r.GetString(0)).Hosts.Add(key.Item1);
                        var h = hosts.TryGetValue(key, out var x) ? x : hosts[key] = new HostTally();
                        h.Add(r, 3);
                    }
                }
            },
            async (conn, ct) =>
            {
                await foreach (var r in QueryAsync(conn, filter,
                    "SELECT detections, count(*) FROM events WHERE {filter} AND detections != '' GROUP BY detections", null, ct).ConfigureAwait(false))
                {
                    lock (gate)
                    {
                        var rows = r.GetInt64(1);
                        foreach (var (kind, n) in Values.Detections(r.GetString(0)))
                        {
                            sensitive[kind] = sensitive.GetValueOrDefault(kind) + n * rows;
                        }
                    }
                }
            },
        ];
        var spans = await index.OverlappingAsync(filter.Range, ct).ConfigureAwait(false);
        await Parallel.ForEachAsync(spans.SelectMany(span => scans.Select(scan => (span, scan))), ct, async (work, ct) =>
        {
            await using var conn = await index.OpenAsync(work.span, ct).ConfigureAwait(false);
            await work.scan(conn, ct).ConfigureAwait(false);
        }).ConfigureAwait(false);

        var items = await flagged.ConfigureAwait(false);
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
        var items = await CachedAsync(_flags, filter, static () => new FlagGroups(), FoldFlagsAsync,
            static g => g.Groups.Count, static g => g.Sorted(), ct).ConfigureAwait(false);
        // Review state is never cached (ADR-016 Decision 1): audit.db is read on every request.
        return [.. items.Select(i => reviewed.Contains(i.LastEventId) ? i with { Reviewed = true } : i)];
    }

    /// <summary>Adds one segment's flagged rows with seq in (<paramref name="above"/>, <paramref name="upTo"/>].</summary>
    private static async Task FoldFlagsAsync(
        SqliteConnection conn, Filter filter, long above, long upTo, FlagGroups into, Lock gate, CancellationToken ct)
    {
        await foreach (var r in QueryAsync(conn, filter, $"""
            SELECT seq, event_id, ts_us, tool, session_id, target, flags, outcome, action, detections, count
            FROM events WHERE {"{filter}"} AND {FlaggedCondition} AND {SeqBetween(above, upTo)}
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
            var tool = r.GetString(3);
            var count = r.GetInt64(10);
            var eventId = r.GetString(1);
            lock (gate)
            {
                into.Changed();
                if (!into.Groups.TryGetValue(key, out var g))
                {
                    g = into.Groups[key] = new FlagAcc(c.Severity, tool, ts);
                }
                g.Rows++;
                g.Count += count;
                g.FirstTs = Math.Min(g.FirstTs, ts);
                g.LastTs = Math.Max(g.LastTs, ts);
                if (seq > g.LastSeq)
                {
                    g.LastSeq = seq;
                    g.LastEventId = eventId;
                }
            }
        }
    }

    /// <summary>Sessions with rows in the range, most recently active first.</summary>
    public async Task<IReadOnlyList<SessionSummary>> SessionsAsync(Filter filter, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(filter);
        var sessions = await CachedAsync(_sessions, filter, static () => new SessionGroups(),
            (conn, f, above, upTo, into, gate, ct) => SummariseIntoAsync(conn, f, null, above, upTo, into, gate, ct),
            static g => g.Merged.Count, static g => g.Sorted(), ct).ConfigureAwait(false);
        return sessions;
    }

    /// <summary>Forgets the kept lists (ADR-016 Decision 3: on sign-out).</summary>
    public void ClearLists()
    {
        _flags.Clear();
        _sessions.Clear();
    }

    /// <summary>
    /// <paramref name="filter"/>'s list from <paramref name="cache"/>, brought up to the newest row
    /// (ADR-016 Decision 1). A new or invalid entry is built from the segments in the range, up
    /// to the newest seq read before their spans were (so no row below it is missed); a kept one
    /// folds in only the rows above its seq, all in the newest segment. Equal to a full rebuild
    /// because rows are append-only and seq only grows (see <see cref="ListCache{TState}"/>).
    /// </summary>
    private async Task<TList> CachedAsync<TState, TList>(
        ListCache<TState> cache, Filter filter, Func<TState> empty,
        Func<SqliteConnection, Filter, long, long, TState, Lock, CancellationToken, Task> fold,
        Func<TState, int> size, Func<TState, TList> snapshot, CancellationToken ct) where TState : class
    {
        var entry = cache.Get(filter);
        await entry.Turn.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var kept = await index.ListAsync(ct).ConfigureAwait(false);
            if (kept.Count == 0)
            {
                cache.Drop(filter, entry);
                return snapshot(empty());
            }
            var gate = new Lock();
            var names = string.Join('/', kept.Select(k => k.Name));
            if (entry.State is { } state && entry.Segments == names)
            {
                var newest = kept[^1];
                await using var conn = await index.OpenAsync(newest, ct).ConfigureAwait(false);
                var upTo = await MaxSeqAsync(conn, ct).ConfigureAwait(false);
                if (upTo > entry.UpTo)
                {
                    await fold(conn, filter, entry.UpTo, upTo, state, gate, ct).ConfigureAwait(false);
                    entry.UpTo = upTo;
                }
                // Taken while this entry is held: a later fold never changes what is returned.
                return snapshot(state);
            }
            long top;
            await using (var conn = await index.OpenAsync(kept[^1], ct).ConfigureAwait(false))
            {
                top = await MaxSeqAsync(conn, ct).ConfigureAwait(false);
            }
            // Spans read after `top`, so they cover every row at or below it.
            kept = await index.ListAsync(ct).ConfigureAwait(false);
            var built = empty();
            await Parallel.ForEachAsync(kept.Where(k => filter.Range.Overlaps(k.MinTsUs, k.MaxTsUs)), ct, async (span, ct) =>
            {
                await using var conn = await index.OpenAsync(span, ct).ConfigureAwait(false);
                await fold(conn, filter, long.MinValue, top, built, gate, ct).ConfigureAwait(false);
            }).ConfigureAwait(false);
            if (size(built) > cache.KeepUpTo)
            {
                cache.Drop(filter, entry);
            }
            else
            {
                (entry.State, entry.UpTo, entry.Segments) = (built, top, string.Join('/', kept.Select(k => k.Name)));
            }
            return snapshot(built);
        }
        finally
        {
            entry.Turn.Release();
        }
    }

    private static async Task<long> MaxSeqAsync(SqliteConnection conn, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT coalesce(max(seq), 0) FROM events";
        return (long)(await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L);
    }

    /// <summary>Seq bounds as SQL; both are numbers the store gave, never request values.</summary>
    private static string SeqBetween(long above, long upTo) => above == long.MinValue
        ? FormattableString.Invariant($"seq <= {upTo}")
        : FormattableString.Invariant($"seq > {above} AND seq <= {upTo}");

    /// <summary>
    /// A session and the sessions delegated from it (and from those, recursively), as
    /// summaries, root first; empty when the session is unknown.
    /// </summary>
    public async Task<IReadOnlyList<SessionSummary>> SessionTreeAsync(string sessionId, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(sessionId);
        var spans = await index.ListAsync(ct).ConfigureAwait(false);
        // Each segment is opened once for the whole walk: a child's rows may sit in a later
        // segment than its parent's, so every level asks every segment.
        var conns = new List<SqliteConnection>(spans.Count);
        try
        {
            foreach (var span in spans)
            {
                conns.Add(await index.OpenAsync(span, ct).ConfigureAwait(false));
            }
            var ids = new List<string> { sessionId };
            var seen = new HashSet<string>(StringComparer.Ordinal) { sessionId };
            var frontier = new List<string> { sessionId };
            while (frontier.Count > 0 && ids.Count < MaxSessionTree)
            {
                var next = new SortedSet<string>(StringComparer.Ordinal);
                foreach (var conn in conns)
                {
                    await foreach (var r in QueryAsync(conn, null,
                        $"SELECT DISTINCT session_id FROM events WHERE parent_session_id IN ({InList(frontier.Count)}) AND session_id IS NOT NULL",
                        frontier, ct).ConfigureAwait(false))
                    {
                        next.Add(r.GetString(0));
                    }
                }
                frontier = [.. next.Where(seen.Add).Take(MaxSessionTree - ids.Count)];
                ids.AddRange(frontier);
            }
            var all = await SummariseAsync(spans, null, ids, ct).ConfigureAwait(false);
            return [.. all.OrderBy(s => s.SessionId == sessionId ? 0 : 1).ThenBy(s => s.FirstTsUs)];
        }
        finally
        {
            foreach (var conn in conns)
            {
                await conn.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>Rows of the given sessions after <paramref name="afterSeq"/>, in seq order.</summary>
    public async Task<Page<EventView>> TimelineAsync(
        IReadOnlyList<string> sessionIds, bool includeInternal, long afterSeq, int limit, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(sessionIds);
        ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(limit, MaxPageSize);
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
            cmd.Parameters.AddWithValue("$limit", limit + 1 - rows.Count);
            await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                rows.Add(ReadEvent(r));
            }
            if (rows.Count > limit)
            {
                break;
            }
        }
        return rows.Count > limit
            ? new Page<EventView>(rows[..limit], rows[limit - 1].Seq)
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

    /// <summary>
    /// The events with these ids, found with one query per segment and stopping once all are
    /// found; ids not in the store are left out.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, EventView>> FindEventsAsync(IReadOnlyList<string> eventIds, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(eventIds);
        var found = new Dictionary<string, EventView>(StringComparer.Ordinal);
        var wanted = eventIds.Distinct(StringComparer.Ordinal).ToList();
        foreach (var span in await index.ListAsync(ct).ConfigureAwait(false))
        {
            if (wanted.Count == 0)
            {
                break;
            }
            await using var conn = await index.OpenAsync(span, ct).ConfigureAwait(false);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = $"SELECT {Columns(await StoreFolder.SegmentVersionAsync(conn, ct).ConfigureAwait(false))} FROM events WHERE event_id IN ({InList(wanted.Count)})";
            AddList(cmd, wanted);
            await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                var e = ReadEvent(r);
                found[e.EventId] = e;
            }
            wanted.RemoveAll(found.ContainsKey);
        }
        return found;
    }

    private async Task<IReadOnlyList<SessionSummary>> SummariseAsync(
        IReadOnlyList<SegmentSpan> spans, Filter? filter, List<string>? ids, CancellationToken ct)
    {
        var groups = new SessionGroups();
        var gate = new Lock();
        await Parallel.ForEachAsync(spans, ct, async (span, ct) =>
        {
            await using var conn = await index.OpenAsync(span, ct).ConfigureAwait(false);
            await SummariseIntoAsync(conn, filter, ids, long.MinValue, long.MaxValue, groups, gate, ct).ConfigureAwait(false);
        }).ConfigureAwait(false);
        return groups.Sorted();
    }

    /// <summary>
    /// Adds one segment's sessions (rows with seq in (<paramref name="above"/>, <paramref name="upTo"/>]).
    /// Every merge is a min, max or sum, so segments may be added in any order.
    /// </summary>
    private static async Task SummariseIntoAsync(
        SqliteConnection conn, Filter? filter, List<string>? ids, long above, long upTo, SessionGroups into, Lock gate,
        CancellationToken ct)
    {
        var idClause = ids is null ? "" : $" AND session_id IN ({InList(ids.Count)})";
        await foreach (var r in QueryAsync(conn, filter, $"""
            SELECT session_id, tool, max(parent_session_id), max(project), min(ts_us), max(ts_us), count(*), sum(count), max(seq), sum(source = 'agent' AND category = 'prompt')
            FROM events WHERE {(filter is null ? "1" : "{filter}")} AND session_id IS NOT NULL AND {SeqBetween(above, upTo)}{idClause}
            GROUP BY session_id, tool
            """, ids, ct).ConfigureAwait(false))
        {
            var s = new SessionSummary(
                r.GetString(0), r.GetString(1), r.IsDBNull(2) ? null : r.GetString(2), r.IsDBNull(3) ? null : r.GetString(3),
                r.GetInt64(4), r.GetInt64(5), r.GetInt64(6), r.GetInt64(7), r.GetInt64(8), r.GetInt64(9));
            lock (gate)
            {
                into.Add(s);
            }
        }
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

    /// <summary>Flag groups, and their sorted list until the next change.</summary>
    private sealed class FlagGroups
    {
        private FlagItem[]? _sorted;

        public Dictionary<(string Rule, string Target, string? Session), FlagAcc> Groups { get; } = [];

        public void Changed() => _sorted = null;

        /// <summary>Newest first, unreviewed; a new array after each change, never changed itself.</summary>
        public FlagItem[] Sorted() => _sorted ??= [.. Groups
            .Select(kv => new FlagItem(kv.Key.Rule, kv.Value.Severity, kv.Key.Target, kv.Key.Session, kv.Value.Tool,
                kv.Value.Rows, kv.Value.Count, kv.Value.FirstTs, kv.Value.LastTs, kv.Value.LastSeq, kv.Value.LastEventId,
                false))
            .OrderByDescending(i => i.LastSeq)];
    }

    /// <summary>Sessions merged across segments, and their sorted list until the next change.</summary>
    private sealed class SessionGroups
    {
        private SessionSummary[]? _sorted;

        public Dictionary<string, SessionSummary> Merged { get; } = new(StringComparer.Ordinal);

        public void Add(SessionSummary s)
        {
            _sorted = null;
            Merged[s.SessionId] = Merged.TryGetValue(s.SessionId, out var m)
                ? m with
                {
                    // The larger value, as SQL's max() within a segment: the same in any order.
                    ParentSessionId = Larger(m.ParentSessionId, s.ParentSessionId),
                    Project = Larger(m.Project, s.Project),
                    FirstTsUs = Math.Min(m.FirstTsUs, s.FirstTsUs),
                    LastTsUs = Math.Max(m.LastTsUs, s.LastTsUs),
                    Rows = m.Rows + s.Rows,
                    Events = m.Events + s.Events,
                    Prompts = m.Prompts + s.Prompts,
                    LastSeq = Math.Max(m.LastSeq, s.LastSeq),
                }
                : s;
        }

        /// <summary>Most recently active first; a new array after each change, never changed itself.</summary>
        public SessionSummary[] Sorted() => _sorted ??= [.. Merged.Values.OrderByDescending(s => s.LastSeq)];

        private static string? Larger(string? a, string? b) =>
            a is null ? b : b is null ? a : string.CompareOrdinal(a, b) >= 0 ? a : b;
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
