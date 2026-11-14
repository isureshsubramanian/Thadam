using System.Net;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Thadam.Api.Search;
using Thadam.Store;
using Thadam.Store.Queries;
using Thadam.Store.Search;
using Thadam.Store.Tests;

namespace Thadam.Api.Tests;

/// <summary>
/// ADR-008 acceptance tests 4, 5 and 6 (index part) for search, over the Rust fixture (kept
/// rows seq 5-33; see <see cref="QueryTests"/>).
/// </summary>
[Collection(ApiFixtureDefinition.Name)]
public sealed class SearchTests(StoreFixture store)
{
    private const string Range = "from:2026-10-01 to:2026-11-30";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<JsonElement> SearchAsync(HttpClient client, string q, string? after = null)
    {
        var url = $"/api/v1/events?q={Uri.EscapeDataString(q)}" + (after is null ? "" : $"&after={after}");
        using var r = await client.GetAsync(url, Ct);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return JsonElement.Parse(await r.Content.ReadAsStringAsync(Ct));
    }

    private static long[] Seqs(JsonElement result) =>
        [.. result.GetProperty("items").EnumerateArray().Select(e => e.GetProperty("seq").GetInt64())];

    private static async Task<long[]> Match(SearchIndex index, string term) =>
        [.. await index.MatchAsync(SearchParser.FtsQuery([term]), long.MaxValue, 10, Ct)];

    private static async Task<long[]> SeqsOf(SearchRunner runner, SearchQuery q) =>
        [.. (await runner.RunAsync(q, null, Ct)).Page.Items.Select(e => e.Seq)];

    /// <summary>An index path in a new private folder of its own.</summary>
    private static string TempIndex() => Path.Combine(Path.GetTempPath(), $"thadam-search-{Guid.NewGuid():N}", "search.db");

    private static void Remove(string indexPath) => Directory.Delete(Path.GetDirectoryName(indexPath)!, recursive: true);

    [Fact]
    public async Task FreeTextUsesTheIndexAndFindsEveryKeptMatch()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        var r = await SearchAsync(client, "main.rs");
        Assert.Equal([10L, 5L], Seqs(r)); // newest first; the W44 match is retired
        Assert.Equal("CLI agent", r.GetProperty("items")[0].GetProperty("displayName").GetString());
        Assert.Equal(JsonValueKind.Null, r.GetProperty("range").ValueKind);
        Assert.Equal(2, r.GetProperty("summary").GetProperty("rows").GetInt64());
    }

    [Fact]
    public async Task TheMockUpQueryShowsWhatItTouchedAndWhereItConnected()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        var r = await SearchAsync(client, $"tool:\"CLI agent\" outside:sample-app {Range}");
        Assert.Equal([6L], Seqs(r));
        var s = r.GetProperty("summary");
        Assert.Equal((1, 12), (s.GetProperty("rows").GetInt64(), s.GetProperty("records").GetInt64()));
        Assert.Equal("~/.cargo/registry", s.GetProperty("outsideFolders")[0].GetProperty("folder").GetString());
        Assert.Equal(1, s.GetProperty("flagged").GetInt64());
        var hosts = r.GetProperty("hosts");
        Assert.Equal("203.0.113.7:443", hosts[0].GetProperty("target").GetString());
        Assert.True(hosts[0].GetProperty("unknown").GetBoolean());
    }

    [Theory]
    [InlineData("md", new long[] { 9, 8 })]
    [InlineData("outcome:denied", new long[] { 13 })]
    [InlineData("tool:desktop_assistant", new long[] { 9, 8 })]
    [InlineData("host:203.0.113", new long[] { 12 })]
    [InlineData("session:s-b1", new long[] { 7, 6, 5 })]
    [InlineData("flag:outside-project action:write", new long[] { 9 })]
    public async Task ShortTextScansAndFieldsFilter(string q, long[] expected)
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        var r = await SearchAsync(client, $"{q} {Range}");
        Assert.Equal(expected, Seqs(r));
    }

    [Fact]
    public async Task StoredValuesAreReturnedRedacted()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        var secret = await SearchAsync(client, $"flag:secret-pattern {Range}");
        Assert.Equal([7L], Seqs(secret));
        Assert.DoesNotContain("ghp_", secret.GetProperty("items")[0].GetProperty("target").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task PagesContinueBelowTheLastSeqAndSkipTheSummary()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        var r = await SearchAsync(client, $"category:file {Range}", after: "10");
        Assert.Equal([9L, 8L, 6L, 5L], Seqs(r));
        Assert.Equal(JsonValueKind.Null, r.GetProperty("summary").ValueKind);
    }

    [Theory]
    [InlineData("colour:blue", "q.unknown", "blue")]
    [InlineData("tool:secret_tool_name", "q.tool", "secret_tool_name")]
    [InlineData("since:999d", "q.since", "999d")]
    [InlineData("\"unclosed phrase", "q", "unclosed")]
    public async Task BadSearchesNameTheFieldAndAreAudited(string q, string field, string value)
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        using var r = await client.GetAsync($"/api/v1/events?q={Uri.EscapeDataString(q)}", Ct);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        var body = await r.Content.ReadAsStringAsync(Ct);
        Assert.Equal([field], JsonElement.Parse(body).GetProperty("errors").EnumerateArray().Select(e => e.GetString()));
        Assert.DoesNotContain(value, body, StringComparison.Ordinal);
        var last = (await host.Service<Thadam.Audit.AuditLog>().EntriesAsync(Ct))[^1];
        Assert.Equal(("search", "failed", ""), (last.Action, last.Outcome, last.TargetId));
    }

    [Fact]
    public async Task OverLongQueryMissingQueryAndBadAfterAre400()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        foreach (var (url, field) in new[]
        {
            ($"/api/v1/events?q={new string('a', 513)}", "q"),
            ("/api/v1/events", "q"),
            ("/api/v1/events?q=main.rs&after=abc", "after"),
        })
        {
            using var r = await client.GetAsync(url, Ct);
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
            Assert.Contains($"\"{field}\"", await r.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task SearchesAreAuditedWithoutTheQuery()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        await SearchAsync(client, "main.rs");
        var last = (await host.Service<Thadam.Audit.AuditLog>().EntriesAsync(Ct))[^1];
        Assert.Equal(("search", "succeeded", ""), (last.Action, last.Outcome, last.TargetId));
    }

    [Fact]
    public async Task RowsNotYetIndexedAreStillFound()
    {
        var path = TempIndex();
        var segments = new SegmentIndex(new StoreFolder(store.Folder));
        await using (var index = await SearchIndex.OpenAsync(path, Ct))
        {
            await index.TailAsync(segments, Ct, upToSeq: 20);
            Assert.Equal(20, index.IndexedSeq);
            var runner = new SearchRunner(segments, index);
            var (q, _) = SearchParser.Parse("mod15.rs", _ => null, DateTimeOffset.UtcNow);
            // mod15.rs is seq 29: above the indexed seq, found by the scan.
            Assert.Equal(new long[] { 29 }, await SeqsOf(runner, q!));
            await index.TailAsync(segments, Ct);
            Assert.Equal(33, index.IndexedSeq);
            Assert.Equal(new long[] { 29 }, await Match(index, "mod15.rs"));
            Assert.Equal(new long[] { 29 }, await SeqsOf(runner, q!));
        }
        Remove(path);
    }

    [Fact]
    public async Task RetiredRowsAreDroppedFromTheIndex()
    {
        var path = TempIndex();
        await using (var index = await SearchIndex.OpenAsync(path, Ct))
        {
            // A leftover entry for seq 2, which the fixture's catalog retired.
            await using (var conn = new SqliteConnection($"Data Source={path};Pooling=False"))
            {
                await conn.OpenAsync(Ct);
                await using var cmd = conn.CreateCommand();
                cmd.CommandText = "INSERT INTO terms (rowid, target, process_path) VALUES (2, 'retired-marker', '/bin/cat')";
                await cmd.ExecuteNonQueryAsync(Ct);
            }
            Assert.Equal(new long[] { 2 }, await Match(index, "retired-marker"));
            await index.TailAsync(new SegmentIndex(new StoreFolder(store.Folder)), Ct);
            Assert.Empty(await Match(index, "retired-marker"));
        }
        Remove(path);
    }

    [Fact]
    public async Task AnIndexAheadOfTheStoreIsRebuilt()
    {
        var path = TempIndex();
        var segments = new SegmentIndex(new StoreFolder(store.Folder));
        await using (var index = await SearchIndex.OpenAsync(path, Ct))
        {
            await index.TailAsync(segments, Ct);
        }
        await using (var conn = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            await conn.OpenAsync(Ct);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE meta SET value = 999 WHERE key = 'last_seq'";
            await cmd.ExecuteNonQueryAsync(Ct);
        }
        await using (var index = await SearchIndex.OpenAsync(path, Ct))
        {
            Assert.Equal(999, index.IndexedSeq);
            await index.TailAsync(segments, Ct);
            Assert.Equal(33, index.IndexedSeq);
            Assert.Equal(new long[] { 29 }, await Match(index, "mod15.rs"));
        }
        Remove(path);
    }

    [Fact]
    public async Task AMissingIndexIsBuiltAtStartAndIsPrivate()
    {
        // Each test host starts with no search.db: the indexer's first pass builds it.
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var index = host.Service<SearchIndex>();
        var waited = TimeSpan.Zero;
        while (index.IndexedSeq < 33 && waited < TimeSpan.FromSeconds(10))
        {
            await Task.Delay(50, Ct);
            waited += TimeSpan.FromMilliseconds(50);
        }
        Assert.Equal(33, index.IndexedSeq);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(host.Options.SearchPath));
    }
}
