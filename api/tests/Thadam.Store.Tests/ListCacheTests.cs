using Microsoft.Data.Sqlite;
using Thadam.Store.Queries;

namespace Thadam.Store.Tests;

/// <summary>
/// The kept Sessions and Flagged lists (ADR-016) always equal a list built from scratch: after
/// new rows, after a late row with an early time, and after a segment is retired.
/// </summary>
public sealed class ListCacheTests : IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly Filter Week = new(new TimeRange(100, 199), null);
    private readonly ListStore store = new();

    [Fact]
    public async Task NewRowsAndALateRowAreFoldedInExactly()
    {
        await store.CreateAsync(Ct);
        var queries = new StoreQueries(new SegmentIndex(store.Folder));
        await AssertSameAsFreshAsync(queries);

        // In range: a new session, more rows for a kept one, and a new denial.
        await store.AddAsync(ListStore.Active, Row(20, 150, "session-c", "allowed"), Ct);
        await store.AddAsync(ListStore.Active, Row(21, 160, "session-a", "denied_by_user"), Ct);
        // Out of range, then a late row whose time falls inside it: the active segment's rows
        // were all outside the range when the list was built.
        await store.AddAsync(ListStore.Active, Row(22, 900, "session-a", "allowed"), Ct);
        await store.AddAsync(ListStore.Active, Row(23, 101, "session-b", "denied_by_os"), Ct);
        await AssertSameAsFreshAsync(queries);
        Assert.Equal(2, queries.KeptLists);
    }

    [Fact]
    public async Task ConcurrentReadsWhileRowsArriveStayWhole()
    {
        await store.CreateAsync(Ct);
        var queries = new StoreQueries(new SegmentIndex(store.Folder));
        var none = new HashSet<string>();
        var writer = Task.Run(async () =>
        {
            for (var seq = 30; seq < 130; seq++)
            {
                await store.AddAsync(ListStore.Active, Row(seq, 100 + (seq % 90), $"session-{seq % 7}", seq % 3 == 0 ? "denied_by_os" : "allowed"), Ct);
            }
        }, Ct);
        var readers = Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
        {
            while (!writer.IsCompleted)
            {
                await queries.SessionsAsync(Week, Ct);
                await queries.FlagItemsAsync(Week, none, Ct);
            }
        }, Ct)).ToList();
        await Task.WhenAll([writer, .. readers]);
        await AssertSameAsFreshAsync(queries);
    }

    [Fact]
    public async Task ARetiredSegmentMeansARebuild()
    {
        await store.CreateAsync(Ct);
        var queries = new StoreQueries(new SegmentIndex(store.Folder));
        Assert.NotEmpty(await queries.SessionsAsync(Week, Ct));
        await store.RetireClosedAsync(Ct);
        await AssertSameAsFreshAsync(queries);
        Assert.Empty(await queries.SessionsAsync(Week, Ct));
    }

    [Fact]
    public async Task ReviewStateIsReadOnEveryRequest()
    {
        await store.CreateAsync(Ct);
        var queries = new StoreQueries(new SegmentIndex(store.Folder));
        var open = Assert.Single(await queries.FlagItemsAsync(Week, new HashSet<string>(), Ct));
        Assert.False(open.Reviewed);
        var reviewed = Assert.Single(await queries.FlagItemsAsync(Week, new HashSet<string> { open.LastEventId }, Ct));
        Assert.True(reviewed.Reviewed);
        Assert.False(Assert.Single(await queries.FlagItemsAsync(Week, new HashSet<string>(), Ct)).Reviewed);
    }

    [Fact]
    public async Task AListOverTheBoundIsNotKept()
    {
        await store.CreateAsync(Ct);
        var queries = new StoreQueries(new SegmentIndex(store.Folder), TimeProvider.System, keepUpTo: 1);
        Assert.Equal(2, (await queries.SessionsAsync(Week, Ct)).Count);
        Assert.Single(await queries.FlagItemsAsync(Week, new HashSet<string>(), Ct));
        Assert.Equal(1, queries.KeptLists); // the one flag group fits, the two sessions do not
    }

    [Fact]
    public async Task SignOutForgetsTheLists()
    {
        await store.CreateAsync(Ct);
        var queries = new StoreQueries(new SegmentIndex(store.Folder));
        await queries.SessionsAsync(Week, Ct);
        await queries.FlagItemsAsync(Week, new HashSet<string>(), Ct);
        Assert.Equal(2, queries.KeptLists);
        queries.ClearLists();
        Assert.Equal(0, queries.KeptLists);
    }

    [Fact]
    public void TheLeastRecentlyUsedAndIdleListsAreDropped()
    {
        var time = new StepTime();
        var cache = new ListCache<object>(time);
        var keys = Enumerable.Range(0, ListCache<object>.MaxEntries + 1)
            .Select(i => new Filter(new TimeRange(i, i + 10), null)).ToList();
        foreach (var key in keys)
        {
            cache.Get(key).State = new object();
            time.Now += TimeSpan.FromSeconds(1);
        }
        Assert.Equal(ListCache<object>.MaxEntries, cache.Count);
        Assert.Null(cache.Get(keys[0]).State); // dropped as the oldest, so a new empty entry
        time.Now += ListCache<object>.Idle + TimeSpan.FromSeconds(1);
        Assert.Null(cache.Get(keys[^1]).State);
        Assert.Equal(1, cache.Count);
    }

    /// <summary>The cached lists equal those of a store opened fresh.</summary>
    private async Task AssertSameAsFreshAsync(StoreQueries cached)
    {
        var fresh = new StoreQueries(new SegmentIndex(new StoreFolder(store.Folder.Path)));
        var none = new HashSet<string>();
        Assert.Equal(await fresh.SessionsAsync(Week, Ct), await cached.SessionsAsync(Week, Ct));
        Assert.Equal(await fresh.FlagItemsAsync(Week, none, Ct), await cached.FlagItemsAsync(Week, none, Ct));
    }

    private static (long Seq, long Ts, string Session, string Outcome) Row(long seq, long ts, string session, string outcome) =>
        (seq, ts, session, outcome);

    public void Dispose() => store.Dispose();

    private sealed class StepTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 11, 16, 0, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => Now;
    }

    /// <summary>A synthetic store: a closed segment and an active one, rows written directly.</summary>
    private sealed class ListStore : IDisposable
    {
        public const string Closed = "events-2026-W45.db";
        public const string Active = "events-2026-W46.db";
        private readonly string _path = Path.Combine(Path.GetTempPath(), $"thadam-lists-{Guid.NewGuid():N}");
        private readonly List<CatalogEntry> _entries = [];

        public StoreFolder Folder => new(_path);

        public async Task CreateAsync(CancellationToken ct)
        {
            Directory.CreateDirectory(_path);
            foreach (var name in new[] { Closed, Active })
            {
                await ExecAsync(name, """
                    PRAGMA user_version = 2;
                    CREATE TABLE events (seq INTEGER PRIMARY KEY, event_id TEXT, ts_us INTEGER, tool TEXT, session_id TEXT,
                        parent_session_id TEXT, pid INTEGER, process_path TEXT, category TEXT, action TEXT,
                        target TEXT, outcome TEXT, size_bytes INTEGER, bytes_out INTEGER, bytes_in INTEGER,
                        project TEXT, flags TEXT, count INTEGER, detections TEXT, source TEXT, prev_hash BLOB, hash BLOB);
                    """, ct);
            }
            // Two sessions in range, one of them with a denial; one row out of range.
            await AddAsync(Closed, (1, 110, "session-a", "allowed"), ct);
            await AddAsync(Closed, (2, 120, "session-a", "denied_by_agent"), ct);
            await AddAsync(Closed, (3, 130, "session-b", "allowed"), ct);
            await AddAsync(Active, (10, 500, "session-b", "allowed"), ct);
            var genesis = Chain.ToHex(Chain.Genesis.Span);
            _entries.Add(new CatalogEntry(1, 1, "opened", Closed, 1, null, genesis, null, null, null, null, null, null, null, null, null));
            _entries.Add(new CatalogEntry(2, 2, "closed", Closed, 1, 3, genesis, genesis, 130, 3, null, null, null, null, null, null));
            _entries.Add(new CatalogEntry(3, 3, "opened", Active, 10, null, genesis, null, null, null, null, null, null, null, null, null));
            await WriteCatalogAsync(ct);
        }

        public async Task RetireClosedAsync(CancellationToken ct)
        {
            var genesis = Chain.ToHex(Chain.Genesis.Span);
            _entries.Add(new CatalogEntry(4, 4, "retired", Closed, 1, 3, genesis, genesis, 130, 3, null, null, null, null, null, null));
            await WriteCatalogAsync(ct);
        }

        public async Task AddAsync(string segment, (long Seq, long Ts, string Session, string Outcome) row, CancellationToken ct)
        {
            await using var conn = await OpenAsync(segment, ct);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO events VALUES ($seq, $id, $ts, 'tool-a', $session, NULL, 1, '/bin/tool-a', 'command', 'exec',
                    'build', $outcome, NULL, NULL, NULL, '/Users/dev/sample-app', '', 1, '', 'os', zeroblob(32), zeroblob(32))
                """;
            cmd.Parameters.AddWithValue("$seq", row.Seq);
            cmd.Parameters.AddWithValue("$id", $"event-{row.Seq}");
            cmd.Parameters.AddWithValue("$ts", row.Ts);
            cmd.Parameters.AddWithValue("$session", row.Session);
            cmd.Parameters.AddWithValue("$outcome", row.Outcome);
            await cmd.ExecuteNonQueryAsync(ct);
        }

        /// <summary>The whole catalog written again, so its chain stays whole.</summary>
        private async Task WriteCatalogAsync(CancellationToken ct)
        {
            File.Delete(Path.Combine(_path, StoreFolder.CatalogFile));
            await ExecAsync(StoreFolder.CatalogFile, """
                PRAGMA user_version = 1;
                CREATE TABLE catalog (seq INTEGER, at_us INTEGER, kind TEXT, segment TEXT, first_seq INTEGER,
                    last_seq INTEGER, first_prev_hash TEXT, last_hash TEXT, last_ts_us INTEGER, rows INTEGER,
                    bytes INTEGER, reason TEXT, detail TEXT, from_us INTEGER, to_us INTEGER, missed INTEGER,
                    prev_hash BLOB, hash BLOB);
                """, ct);
            await using var conn = await OpenAsync(StoreFolder.CatalogFile, ct);
            var prev = Chain.Genesis.ToArray();
            foreach (var e in _entries)
            {
                await using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    INSERT INTO catalog VALUES ($seq, $at, $kind, $segment, $first, $last, $firstPrev, $lastHash, $lastTs,
                        $rows, NULL, NULL, NULL, NULL, NULL, NULL, $prev, $hash)
                    """;
                cmd.Parameters.AddWithValue("$seq", e.Seq);
                cmd.Parameters.AddWithValue("$at", e.AtUs);
                cmd.Parameters.AddWithValue("$kind", e.Kind);
                cmd.Parameters.AddWithValue("$segment", e.Segment!);
                cmd.Parameters.AddWithValue("$first", e.FirstSeq!);
                cmd.Parameters.AddWithValue("$last", (object?)e.LastSeq ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$firstPrev", e.FirstPrevHash!);
                cmd.Parameters.AddWithValue("$lastHash", (object?)e.LastHash ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$lastTs", (object?)e.LastTsUs ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$rows", (object?)e.Rows ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$prev", prev);
                var hash = Chain.CatalogHash(prev, e);
                cmd.Parameters.AddWithValue("$hash", hash);
                await cmd.ExecuteNonQueryAsync(ct);
                prev = hash;
            }
        }

        private async Task ExecAsync(string file, string sql, CancellationToken ct)
        {
            await using var conn = await OpenAsync(file, ct);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            await cmd.ExecuteNonQueryAsync(ct);
        }

        private async Task<SqliteConnection> OpenAsync(string file, CancellationToken ct)
        {
            var conn = new SqliteConnection($"Data Source={Path.Combine(_path, file)};Pooling=False");
            await conn.OpenAsync(ct);
            return conn;
        }

        public void Dispose()
        {
            if (Directory.Exists(_path))
            {
                Directory.Delete(_path, recursive: true);
            }
        }
    }
}
