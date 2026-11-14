using Microsoft.Data.Sqlite;
using Thadam.Store.Queries;

namespace Thadam.Store.Tests;

/// <summary>A host's unknown state follows its newest row, across segments (synthetic rows).</summary>
public sealed class HostTallyTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>One in-memory "segment" holding (seq, count, flags) rows for one host.</summary>
    private static async Task AddSegmentAsync(HostTally tally, (long Seq, long Count, string Flags)[] rows)
    {
        await using var conn = new SqliteConnection("Data Source=:memory:");
        await conn.OpenAsync(Ct);
        await using (var create = conn.CreateCommand())
        {
            create.CommandText = """
                CREATE TABLE events (seq INTEGER, target TEXT, category TEXT, count INTEGER,
                                     bytes_out INTEGER, bytes_in INTEGER, flags TEXT)
                """;
            await create.ExecuteNonQueryAsync(Ct);
        }
        foreach (var (seq, count, flags) in rows)
        {
            await using var insert = conn.CreateCommand();
            insert.CommandText = "INSERT INTO events VALUES ($s, 'host.example.test:443', 'network_external', $c, 10, 20, $f)";
            insert.Parameters.AddWithValue("$s", seq);
            insert.Parameters.AddWithValue("$c", count);
            insert.Parameters.AddWithValue("$f", flags);
            await insert.ExecuteNonQueryAsync(Ct);
        }
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT target, category, " + HostTally.Columns + " FROM events GROUP BY target, category";
        await using var r = await cmd.ExecuteReaderAsync(Ct);
        while (await r.ReadAsync(Ct))
        {
            tally.Add(r, 2);
        }
    }

    [Fact]
    public async Task AHostListedLaterIsNotUnknownButKeepsItsCount()
    {
        var tally = new HostTally();
        // Inserted out of seq order: the newest row decides, not the last one stored.
        await AddSegmentAsync(tally, [(3, 1, "continued"), (1, 2, "unknown_host"), (2, 1, "continued,unknown_host")]);
        var s = tally.ToStats("host.example.test:443", "network_external");
        Assert.False(s.Unknown);
        Assert.Equal(3, s.FlaggedFlows);
        Assert.Equal(4, s.Flows);
        Assert.Equal(30, s.BytesOut); // bytes add up per row, not per count
    }

    [Fact]
    public async Task TheNewestSegmentDecidesAcrossSegments()
    {
        var tally = new HostTally();
        await AddSegmentAsync(tally, [(10, 1, "unknown_host")]);
        await AddSegmentAsync(tally, [(4, 1, "")]);
        Assert.True(tally.Unknown);
        Assert.Equal(1, tally.Flagged);
    }
}
