using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.Data.Sqlite;
using Thadam.Store.Queries;

namespace Thadam.Store.Search;

/// <summary>
/// The full-text index the runner asks for candidate rows (ADR-008 Decision 5, option C).
/// Contract: every kept row with <c>seq &lt;= IndexedSeq</c> is in the index; rows above it
/// are not yet, so the runner scans them instead. Kept in the store library as an
/// interface so the index file (the API's, user-owned) stays outside it.
/// </summary>
public interface ITextIndex
{
    long IndexedSeq { get; }

    /// <summary>Seqs below <paramref name="belowSeq"/> matching <paramref name="ftsQuery"/>, newest first, at most <paramref name="cap"/>.</summary>
    Task<IReadOnlyList<long>> MatchAsync(string ftsQuery, long belowSeq, int cap, CancellationToken ct);
}

public sealed record SearchSummary(
    long Rows, long Records, IReadOnlyDictionary<string, long> ByCategory, long Flagged, IReadOnlyList<OutsideFolder> Folders);

/// <summary>
/// A page of matching rows, newest first. <see cref="Summary"/> and <see cref="Hosts"/> come
/// with the first page only. <see cref="Partial"/>: the free text matched more rows than one
/// request examines, so the summary covers the newest of them; <c>Page.Next</c> continues.
/// </summary>
public sealed record SearchResult(Page<EventView> Page, SearchSummary? Summary, IReadOnlyList<HostStats>? Hosts, bool Partial);

/// <summary>
/// Runs a <see cref="SearchQuery"/> over the kept segments. Free text of three or more
/// characters takes candidates from the index for rows it holds and a substring scan for
/// newer rows; shorter text is a scan within the query's time range.
/// </summary>
public sealed class SearchRunner(SegmentIndex segments, ITextIndex index)
{
    /// <summary>Most index candidates one request examines (estimate: about a second of lookups).</summary>
    public const int CandidateCap = 100_000;
    private const int MaxFolders = 100;

    public async Task<SearchResult> RunAsync(SearchQuery q, long? afterSeq, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(q);
        var below = afterSeq ?? long.MaxValue;
        var spans = q.Range is { } range
            ? await segments.OverlappingAsync(range, ct).ConfigureAwait(false)
            : await segments.ListAsync(ct).ConfigureAwait(false);
        var newestFirst = spans.OrderByDescending(s => s.FirstSeq).ToList();

        var indexedSeq = index.IndexedSeq;
        var indexedText = q.IndexedText.ToList();
        IReadOnlyList<long>? candidates = null;
        var capped = false;
        if (indexedText.Count > 0 && indexedSeq > 0)
        {
            candidates = await index.MatchAsync(SearchParser.FtsQuery(indexedText), Math.Min(below, indexedSeq + 1), CandidateCap, ct)
                .ConfigureAwait(false);
            capped = candidates.Count >= CandidateCap;
        }
        // Below the oldest candidate examined, rows were not looked at: stop there.
        var floor = capped ? candidates![^1] : long.MinValue;

        var rows = new List<EventView>();
        var acc = afterSeq is null ? new SummaryAcc() : null;
        for (var i = 0; i < newestFirst.Count; i++)
        {
            var span = newestFirst[i];
            var spanEnd = i == 0 ? long.MaxValue : newestFirst[i - 1].FirstSeq - 1;
            if (spanEnd < floor)
            {
                break;
            }
            var where = SegmentWhere(q, indexedText, candidates, indexedSeq, span.FirstSeq, spanEnd, floor);
            if (where is null)
            {
                continue; // no candidates in this segment and nothing unindexed
            }
            await using var conn = await segments.OpenAsync(span, ct).ConfigureAwait(false);
            if (rows.Count <= StoreQueries.PageSize)
            {
                await ReadPageAsync(conn, where, below, rows, ct).ConfigureAwait(false);
            }
            if (acc is not null)
            {
                await acc.AddAsync(conn, where, ct).ConfigureAwait(false);
            }
            else if (rows.Count > StoreQueries.PageSize)
            {
                break;
            }
        }

        long? next = rows.Count > StoreQueries.PageSize
            ? rows[StoreQueries.PageSize - 1].Seq
            : capped ? floor : null;
        var page = new Page<EventView>(rows.Count > StoreQueries.PageSize ? rows[..StoreQueries.PageSize] : rows, next);
        var hosts = acc is null ? null : await HostsAsync(q, spans, ct).ConfigureAwait(false);
        return new SearchResult(page, acc?.Build(), hosts, capped);
    }

    /// <summary>
    /// How many rows an export of <paramref name="q"/> as of <paramref name="upToSeq"/> holds
    /// (ADR-012 Decision 4), or null when the free text matched more index candidates than one
    /// request examines, so no complete count exists.
    /// </summary>
    public async Task<long?> CountAsync(SearchQuery q, long upToSeq, CancellationToken ct)
    {
        if (await PlanAsync(q, upToSeq, ct).ConfigureAwait(false) is not { } plan)
        {
            return null;
        }
        long total = 0;
        foreach (var (span, where) in plan)
        {
            await using var conn = await segments.OpenAsync(span, ct).ConfigureAwait(false);
            await using var cmd = where.Command(conn, "SELECT count(*) FROM events WHERE {where}");
            total += (long)(await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L);
        }
        return total;
    }

    /// <summary>
    /// The rows <see cref="CountAsync"/> counted, oldest first, each with its chain hash.
    /// Empty when no complete count exists; callers count first.
    /// </summary>
    public async IAsyncEnumerable<ExportRow> RowsAsync(
        SearchQuery q, long upToSeq, [EnumeratorCancellation] CancellationToken ct)
    {
        if (await PlanAsync(q, upToSeq, ct).ConfigureAwait(false) is not { } plan)
        {
            yield break;
        }
        foreach (var (span, where) in plan)
        {
            await using var conn = await segments.OpenAsync(span, ct).ConfigureAwait(false);
            var columns = StoreQueries.ExportColumns(await StoreFolder.SegmentVersionAsync(conn, ct).ConfigureAwait(false));
            await using var cmd = where.Command(conn, $"SELECT {columns} FROM events WHERE {{where}} ORDER BY seq");
            await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                yield return StoreQueries.ReadExportRow(r);
            }
        }
    }

    /// <summary>Each segment that can hold matches, oldest first, with its condition; null when capped.</summary>
    private async Task<List<(SegmentSpan Span, Where Where)>?> PlanAsync(SearchQuery q, long upToSeq, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(q);
        var spans = q.Range is { } range
            ? await segments.OverlappingAsync(range, ct).ConfigureAwait(false)
            : await segments.ListAsync(ct).ConfigureAwait(false);
        var oldestFirst = spans.OrderBy(s => s.FirstSeq).ToList();
        var indexedSeq = index.IndexedSeq;
        var indexedText = q.IndexedText.ToList();
        IReadOnlyList<long>? candidates = null;
        if (indexedText.Count > 0 && indexedSeq > 0)
        {
            candidates = await index.MatchAsync(
                SearchParser.FtsQuery(indexedText), Math.Min(upToSeq + 1, indexedSeq + 1), CandidateCap, ct).ConfigureAwait(false);
            if (candidates.Count >= CandidateCap)
            {
                return null;
            }
        }
        var plan = new List<(SegmentSpan, Where)>();
        for (var i = 0; i < oldestFirst.Count; i++)
        {
            var span = oldestFirst[i];
            if (span.FirstSeq > upToSeq)
            {
                break;
            }
            var spanEnd = i + 1 < oldestFirst.Count ? oldestFirst[i + 1].FirstSeq - 1 : long.MaxValue;
            if (SegmentWhere(q, indexedText, candidates, indexedSeq, span.FirstSeq, spanEnd, long.MinValue) is { } where)
            {
                where.Add($"seq <= {where.Param(upToSeq)}");
                plan.Add((span, where));
            }
        }
        return plan;
    }

    /// <summary>
    /// Network rows for the same tool, session, project and time as the search: "where did
    /// it connect" beside "what did it touch" (the mock-up's search view).
    /// </summary>
    private async Task<IReadOnlyList<HostStats>> HostsAsync(
        SearchQuery q, IReadOnlyList<SegmentSpan> spans, CancellationToken ct)
    {
        var context = new SearchQuery
        {
            Tool = q.Tool,
            Session = q.Session,
            Project = q.Project ?? q.Outside,
            Host = q.Host,
            Range = q.Range,
        };
        var hosts = new Dictionary<(string, string), HostTally>();
        foreach (var span in spans)
        {
            var where = Fields(context);
            where.Add("category LIKE 'network%'");
            await using var conn = await segments.OpenAsync(span, ct).ConfigureAwait(false);
            await using var cmd = where.Command(conn,
                "SELECT target, category, " + HostTally.Columns + " FROM events WHERE {where} GROUP BY target, category");
            await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                var key = (r.GetString(0), r.GetString(1));
                var h = hosts.TryGetValue(key, out var x) ? x : hosts[key] = new HostTally();
                h.Add(r, 2);
            }
        }
        return [.. hosts.OrderByDescending(h => h.Value.BytesOut).ThenBy(h => h.Key.Item1, StringComparer.Ordinal).Take(MaxFolders)
            .Select(h => h.Value.ToStats(h.Key.Item1, h.Key.Item2))];
    }

    private static async Task ReadPageAsync(SqliteConnection conn, Where where, long below, List<EventView> rows, CancellationToken ct)
    {
        await using var cmd = where.Command(conn,
            $"SELECT {StoreQueries.Columns(await StoreFolder.SegmentVersionAsync(conn, ct).ConfigureAwait(false))} FROM events WHERE {{where}} AND seq < $below ORDER BY seq DESC LIMIT $limit");
        cmd.Parameters.AddWithValue("$below", below);
        cmd.Parameters.AddWithValue("$limit", StoreQueries.PageSize + 1 - rows.Count);
        await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await r.ReadAsync(ct).ConfigureAwait(false))
        {
            rows.Add(StoreQueries.ReadEvent(r));
        }
    }

    /// <summary>
    /// The row condition for one segment holding seqs <paramref name="first"/> to
    /// <paramref name="last"/>, or null when it cannot match.
    /// </summary>
    private static Where? SegmentWhere(
        SearchQuery q, List<string> indexedText, IReadOnlyList<long>? candidates, long indexedSeq, long first, long last, long floor)
    {
        var where = Fields(q);
        foreach (var t in q.ScannedText)
        {
            where.TextLike(t);
        }
        if (indexedText.Count > 0)
        {
            var ids = candidates?.Where(s => s >= first && s <= last).ToList() ?? [];
            var unindexed = last > indexedSeq;
            if (ids.Count == 0 && !unindexed)
            {
                return null;
            }
            var parts = new List<string>();
            if (ids.Count > 0)
            {
                parts.Add($"seq IN (SELECT value FROM json_each({where.Param(Json(ids))}))");
            }
            if (unindexed)
            {
                var scan = new StringBuilder($"seq > {where.Param(indexedSeq)}");
                foreach (var t in indexedText)
                {
                    scan.Append(" AND ").Append(where.LikeClause(t));
                }
                parts.Add($"({scan})");
            }
            where.Add($"({string.Join(" OR ", parts)})");
        }
        if (floor != long.MinValue)
        {
            where.Add($"seq >= {where.Param(floor)}");
        }
        return where;
    }

    /// <summary>The conditions for every field except free text.</summary>
    private static Where Fields(SearchQuery q)
    {
        var w = new Where();
        if (q.Range is { } r)
        {
            w.Add($"ts_us BETWEEN {w.Param(r.FromUs)} AND {w.Param(r.ToUs)}");
        }
        if (q.Tool is not null)
        {
            w.Add($"tool = {w.Param(q.Tool)}");
        }
        if (q.Session is not null)
        {
            w.Add($"session_id = {w.Param(q.Session)}");
        }
        if ((q.Project ?? q.Outside) is { } project)
        {
            // A full path, or a project's folder name (`sample-app`).
            w.Add($"(project = {w.Param(project)} OR project LIKE {w.Param("%/" + SearchParser.LikeEscape(project))} ESCAPE '\\')");
        }
        if (q.Outside is not null)
        {
            w.Add(HasFlag("outside_project"));
        }
        if (q.Category is not null)
        {
            w.Add($"category = {w.Param(q.Category)}");
        }
        if (q.Action is not null)
        {
            w.Add($"action = {w.Param(q.Action)}");
        }
        if (q.Outcomes.Count > 0)
        {
            w.Add($"outcome IN ({string.Join(", ", q.Outcomes.Select(o => w.Param(o)))})");
        }
        foreach (var f in q.Flags)
        {
            // From the parser's fixed set, so safe as text; bound anyway.
            w.Add($"instr(',' || flags || ',', {w.Param("," + f + ",")}) > 0");
        }
        if (q.Host is not null)
        {
            w.Add($"category LIKE 'network%' AND target LIKE {w.Param(SearchParser.LikeContains(q.Host))} ESCAPE '\\'");
        }
        return w;
    }

    private static string HasFlag(string flag) => $"instr(',' || flags || ',', ',{flag},') > 0";

    private static string Json(List<long> ids) =>
        "[" + string.Join(',', ids.Select(i => i.ToString(CultureInfo.InvariantCulture))) + "]";

    /// <summary>Conditions joined by AND, with their values as numbered parameters.</summary>
    private sealed class Where
    {
        private readonly List<string> _clauses = [];
        private readonly List<object> _values = [];

        public void Add(string clause) => _clauses.Add(clause);

        public string Param(object value)
        {
            _values.Add(value);
            return $"$w{_values.Count - 1}";
        }

        public string LikeClause(string text)
        {
            var p = Param(SearchParser.LikeContains(text));
            return $"(target LIKE {p} ESCAPE '\\' OR process_path LIKE {p} ESCAPE '\\')";
        }

        public void TextLike(string text) => Add(LikeClause(text));

        /// <summary>A command for <paramref name="sql"/> with <c>{where}</c> replaced by the conditions.</summary>
        public SqliteCommand Command(SqliteConnection conn, string sql)
        {
            var cmd = conn.CreateCommand();
            cmd.CommandText = sql.Replace("{where}", _clauses.Count == 0 ? "1" : string.Join(" AND ", _clauses), StringComparison.Ordinal);
            for (var i = 0; i < _values.Count; i++)
            {
                cmd.Parameters.AddWithValue($"$w{i}", _values[i]);
            }
            return cmd;
        }
    }

    private sealed class SummaryAcc
    {
        private readonly SortedDictionary<string, long> _byCategory = new(StringComparer.Ordinal);
        private readonly Dictionary<string, long> _folders = new(StringComparer.Ordinal);
        private long _rows;
        private long _records;
        private long _flagged;

        public async Task AddAsync(SqliteConnection conn, Where where, CancellationToken ct)
        {
            await using (var cmd = where.Command(conn, "SELECT category, count(*), sum(count) FROM events WHERE {where} GROUP BY category"))
            await using (var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false))
            {
                while (await r.ReadAsync(ct).ConfigureAwait(false))
                {
                    _byCategory[r.GetString(0)] = _byCategory.GetValueOrDefault(r.GetString(0)) + r.GetInt64(1);
                    _rows += r.GetInt64(1);
                    _records += r.GetInt64(2);
                }
            }
            await using (var cmd = where.Command(conn, """
                SELECT flags, outcome, action, detections, count(*) FROM events
                WHERE {where} AND
                """ + StoreQueries.FlaggedCondition + " GROUP BY flags, outcome, action, detections"))
            await using (var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false))
            {
                while (await r.ReadAsync(ct).ConfigureAwait(false))
                {
                    if (SeverityRule.Classify(Values.Flags(r.GetString(0)), r.GetString(1), r.GetString(2), r.GetString(3)) is not null)
                    {
                        _flagged += r.GetInt64(4);
                    }
                }
            }
            await using (var cmd = where.Command(conn,
                $"SELECT target, count(*) FROM events WHERE {{where}} AND category = 'file' AND {HasFlag("outside_project")} GROUP BY target"))
            await using (var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false))
            {
                while (await r.ReadAsync(ct).ConfigureAwait(false))
                {
                    var folder = Values.OutsideFolder(r.GetString(0));
                    _folders[folder] = _folders.GetValueOrDefault(folder) + r.GetInt64(1);
                }
            }
        }

        public SearchSummary Build() => new(
            _rows, _records, _byCategory, _flagged,
            [.. _folders.OrderByDescending(f => f.Value).ThenBy(f => f.Key, StringComparer.Ordinal).Take(MaxFolders)
                .Select(f => new OutsideFolder(f.Key, f.Value, [], []))]);
    }
}
