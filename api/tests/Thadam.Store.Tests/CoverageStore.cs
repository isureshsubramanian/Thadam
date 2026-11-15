using Microsoft.Data.Sqlite;

namespace Thadam.Store.Tests;

/// <summary>A catalog-only synthetic store; windows use microseconds after the epoch.</summary>
public sealed class CoverageStore : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"thadam-coverage-{Guid.NewGuid():N}");
    public StoreFolder Folder => new(Path);

    public async Task CreateAsync(int version, CancellationToken ct)
    {
        Directory.CreateDirectory(Path);
        await using var conn = new SqliteConnection($"Data Source={System.IO.Path.Combine(Path, StoreFolder.CatalogFile)};Pooling=False");
        await conn.OpenAsync(ct);
        await using var schema = conn.CreateCommand();
        schema.CommandText = $"""
            PRAGMA user_version = {version};
            CREATE TABLE catalog (seq INTEGER, at_us INTEGER, kind TEXT, segment TEXT, first_seq INTEGER,
                last_seq INTEGER, first_prev_hash TEXT, last_hash TEXT, last_ts_us INTEGER, rows INTEGER,
                bytes INTEGER, reason TEXT, detail TEXT, from_us INTEGER, to_us INTEGER, missed INTEGER,
                prev_hash BLOB, hash BLOB);
            """;
        await schema.ExecuteNonQueryAsync(ct);
        var windows = new (string Kind, string Reason, string? Detail, long From, long To, long? Missed)[]
        {
            ("gap", "dropped", "network", 25, 40, 7),
            ("gap", "not_running", "crashed", 0, 15, null),
            ("gap", "machine_off", null, 12, 35, null),
            ("gap", "before_start", null, 14, 20, null),
            ("paused", "disk_low", null, 18, 25, 9),
            ("gap", "future_reason", null, 26, 27, null),
        };
        foreach (var w in windows)
        {
            await AppendAsync(w.Kind, w.Reason, w.Detail, w.From, w.To, w.Missed, ct);
        }
    }

    private byte[] _prev = Chain.Genesis.ToArray();
    private long _seq;

    /// <summary>Appends one chained entry, as the collector does.</summary>
    public async Task AppendAsync(string kind, string reason, string? detail, long from, long to, long? missed, CancellationToken ct)
    {
        await using var conn = new SqliteConnection($"Data Source={System.IO.Path.Combine(Path, StoreFolder.CatalogFile)};Pooling=False");
        await conn.OpenAsync(ct);
        var seq = ++_seq;
        var e = new CatalogEntry(seq, seq, kind, null, null, null, null, null, null, null, null,
            reason, detail, from * 1_000_000, to * 1_000_000, missed);
        var hash = Chain.CatalogHash(_prev, e);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO catalog VALUES ($seq, $seq, $kind, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, $reason, $detail, $from, $to, $missed, $prev, $hash)";
        cmd.Parameters.AddWithValue("$seq", seq);
        cmd.Parameters.AddWithValue("$kind", kind);
        cmd.Parameters.AddWithValue("$reason", reason);
        cmd.Parameters.AddWithValue("$detail", (object?)detail ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$from", e.FromUs!);
        cmd.Parameters.AddWithValue("$to", e.ToUs!);
        cmd.Parameters.AddWithValue("$missed", (object?)missed ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$prev", _prev);
        cmd.Parameters.AddWithValue("$hash", hash);
        await cmd.ExecuteNonQueryAsync(ct);
        _prev = hash;
    }

    /// <summary>Runs SQL against the catalog, as tampering would.</summary>
    public async Task ExecAsync(string sql, CancellationToken ct)
    {
        await using var conn = new SqliteConnection($"Data Source={System.IO.Path.Combine(Path, StoreFolder.CatalogFile)};Pooling=False");
        await conn.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public void Dispose() => Directory.Delete(Path, true);
}

public sealed class CoverageCatalogTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task ReadsCatalogAndIgnoresSegmentlessEntries(int version)
    {
        using var store = new CoverageStore();
        var ct = TestContext.Current.CancellationToken;
        await store.CreateAsync(version, ct);
        var catalog = await store.Folder.ReadCatalogAsync(ct);
        Assert.Null(catalog.BrokenAt);
        Assert.Empty(StoreFolder.Segments(catalog.Entries));
        Assert.Equal(5, StoreFolder.Gaps(catalog.Entries).Count);
        Assert.Contains(StoreFolder.Gaps(catalog.Entries), g => g.Reason == "future_reason");
        Assert.Equal(9, Assert.Single(StoreFolder.Pauses(catalog.Entries)).Missed);
    }
}
