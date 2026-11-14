using Microsoft.Data.Sqlite;
using Thadam.Store.Queries;
using Thadam.Store.Search;

namespace Thadam.Store.Tests;

public sealed class MixedVersionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task MixedSegmentsVerifyAndTranscriptTamperingBreaksTheChain()
    {
        using var store = await SyntheticStore.CreateAsync(Ct);
        var status = await new ChainVerifier(store.Folder).VerifyAsync(Ct);
        Assert.True(status.Verified, status.Broken?.ToString());
        Assert.Equal(2, status.VerifiedRows);
        await using var conn = new SqliteConnection($"Data Source={Path.Combine(store.Folder.Path, "events-2026-W47.db")};Pooling=False");
        await conn.OpenAsync(Ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE events SET transcript = $text WHERE seq = 2";
        cmd.Parameters.AddWithValue("$text", "changed");
        await cmd.ExecuteNonQueryAsync(Ct);
        status = await new ChainVerifier(store.Folder).VerifyAsync(Ct);
        Assert.Equal(new ChainBreak(ChainBreakKind.Hash, "events-2026-W47.db", 2), status.Broken);
    }

    [Fact]
    public async Task SearchAndTimelineReturnBothVersionsAndAgentFields()
    {
        using var store = await SyntheticStore.CreateAsync(Ct);
        var index = new SegmentIndex(store.Folder);
        var queries = new StoreQueries(index);
        var timeline = await queries.TimelineAsync(["session-1"], true, 0, Ct);
        Assert.Equal([1L, 2L], timeline.Items.Select(e => e.Seq));
        Assert.Null(timeline.Items[0].AgentSessionId);
        Assert.Null(timeline.Items[0].Transcript);
        Assert.Equal("agent-1", timeline.Items[1].AgentSessionId);
        Assert.Equal("/Users/dev/sessions/session-1.jsonl", timeline.Items[1].Transcript);
        var result = await new SearchRunner(index, new EmptyIndex()).RunAsync(new SearchQuery { Session = "session-1" }, null, Ct);
        Assert.Equal([2L, 1L], result.Page.Items.Select(e => e.Seq));
        Assert.Equal("agent-1", result.Page.Items[0].AgentSessionId);
        Assert.Equal(timeline.Items[1].Transcript, result.Page.Items[0].Transcript);
        Assert.Equal(1, result.Summary!.Flagged);
        var hidden = await queries.TimelineAsync(["session-1"], false, 0, Ct);
        Assert.Single(hidden.Items);
        var flags = await queries.FlagItemsAsync(new Filter(new TimeRange(0, 10), null), new HashSet<string>(), Ct);
        Assert.Equal("denied", Assert.Single(flags).Rule);
        var (parsed, error) = SearchParser.Parse("outcome:never_ran flag:internal", t => t, DateTimeOffset.UtcNow);
        Assert.Null(error);
        Assert.Contains("never_ran", parsed!.Outcomes);
        Assert.Contains("internal", parsed.Flags);
    }

    private sealed class EmptyIndex : ITextIndex
    {
        public long IndexedSeq => 0;
        public Task<IReadOnlyList<long>> MatchAsync(string ftsQuery, long belowSeq, int cap, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<long>>([]);
    }

    private sealed class SyntheticStore(string path) : IDisposable
    {
        public StoreFolder Folder { get; } = new(path);

        public static async Task<SyntheticStore> CreateAsync(CancellationToken ct)
        {
            var path = Path.Combine(Path.GetTempPath(), $"thadam-mixed-{Guid.NewGuid():N}");
            Directory.CreateDirectory(path);
            var store = new SyntheticStore(path);
            var prev = Chain.Genesis.ToArray();
            var entries = new List<CatalogEntry>();
            for (var version = 2; version <= 3; version++)
            {
                var seq = version - 1;
                var name = $"events-2026-W{44 + version}.db";
                var row = new EventRow(seq, $"event-{seq}", seq, "tool-a", "session-1", null, 1,
                    "/bin/tool-a", "command", "exec", "build", version == 3 ? "never_ran" : "allowed",
                    null, null, null, null, version == 3 ? "internal" : "", 1, "", "agent",
                    version == 3 ? "agent-1" : null, version == 3 ? "/Users/dev/sessions/session-1.jsonl" : null);
                var hash = Chain.EventHash(prev, row, version);
                await using var conn = new SqliteConnection($"Data Source={Path.Combine(path, name)};Pooling=False");
                await conn.OpenAsync(ct);
                await using var cmd = conn.CreateCommand();
                var extra = version == 3 ? ", agent_session_id TEXT, transcript TEXT" : "";
                cmd.CommandText = $"""
                    PRAGMA user_version = {version};
                    CREATE TABLE events (seq INTEGER, event_id TEXT, ts_us INTEGER, tool TEXT, session_id TEXT,
                        parent_session_id TEXT, pid INTEGER, process_path TEXT, category TEXT, action TEXT,
                        target TEXT, outcome TEXT, size_bytes INTEGER, bytes_out INTEGER, bytes_in INTEGER,
                        project TEXT, flags TEXT, count INTEGER, detections TEXT, source TEXT{extra}, prev_hash BLOB, hash BLOB);
                    INSERT INTO events VALUES ($seq, $id, $seq, 'tool-a', 'session-1', NULL, 1, '/bin/tool-a',
                        'command', 'exec', 'build', $outcome, NULL, NULL, NULL, NULL, $flags, 1, '', 'agent'
                        {(version == 3 ? ", $agent, $transcript" : "")}, $prev, $hash);
                    """;
                cmd.Parameters.AddWithValue("$seq", seq);
                cmd.Parameters.AddWithValue("$id", row.EventId);
                cmd.Parameters.AddWithValue("$outcome", row.Outcome);
                cmd.Parameters.AddWithValue("$flags", row.Flags);
                if (version == 3)
                {
                    cmd.Parameters.AddWithValue("$agent", row.AgentSessionId!);
                    cmd.Parameters.AddWithValue("$transcript", row.Transcript!);
                }
                cmd.Parameters.AddWithValue("$prev", prev);
                cmd.Parameters.AddWithValue("$hash", hash);
                await cmd.ExecuteNonQueryAsync(ct);
                entries.Add(new CatalogEntry(seq, seq, version == 2 ? "closed" : "opened", name, seq,
                    version == 2 ? seq : null, Chain.ToHex(prev), version == 2 ? Chain.ToHex(hash) : null,
                    version == 2 ? seq : null, version == 2 ? 1 : null, null, null, null, null, null, null));
                prev = hash;
            }
            await using var catalog = new SqliteConnection($"Data Source={Path.Combine(path, StoreFolder.CatalogFile)};Pooling=False");
            await catalog.OpenAsync(ct);
            await using var schema = catalog.CreateCommand();
            schema.CommandText = """
                PRAGMA user_version = 1;
                CREATE TABLE catalog (seq INTEGER, at_us INTEGER, kind TEXT, segment TEXT, first_seq INTEGER,
                    last_seq INTEGER, first_prev_hash TEXT, last_hash TEXT, last_ts_us INTEGER, rows INTEGER,
                    bytes INTEGER, reason TEXT, detail TEXT, from_us INTEGER, to_us INTEGER, missed INTEGER,
                    prev_hash BLOB, hash BLOB);
                """;
            await schema.ExecuteNonQueryAsync(ct);
            prev = Chain.Genesis.ToArray();
            foreach (var entry in entries)
            {
                await using var cmd = catalog.CreateCommand();
                cmd.CommandText = "INSERT INTO catalog VALUES ($seq, $seq, $kind, $segment, $seq, $last, $firstPrev, $lastHash, $last, $rows, NULL, NULL, NULL, NULL, NULL, NULL, $prev, $hash)";
                cmd.Parameters.AddWithValue("$seq", entry.Seq);
                cmd.Parameters.AddWithValue("$kind", entry.Kind);
                cmd.Parameters.AddWithValue("$segment", entry.Segment!);
                cmd.Parameters.AddWithValue("$last", (object?)entry.LastSeq ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$firstPrev", entry.FirstPrevHash!);
                cmd.Parameters.AddWithValue("$lastHash", (object?)entry.LastHash ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$rows", (object?)entry.Rows ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$prev", prev);
                var hash = Chain.CatalogHash(prev, entry);
                cmd.Parameters.AddWithValue("$hash", hash);
                await cmd.ExecuteNonQueryAsync(ct);
                prev = hash;
            }
            return store;
        }

        public void Dispose() => Directory.Delete(Folder.Path, recursive: true);
    }
}
