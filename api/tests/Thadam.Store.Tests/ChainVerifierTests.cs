using Microsoft.Data.Sqlite;

namespace Thadam.Store.Tests;

[Collection(StoreFixtureDefinition.Name)]
public sealed class ChainVerifierTests(StoreFixture fixture)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static SqliteConnection Writable(string file)
    {
        var c = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = file, Pooling = false }.ToString());
        c.Open();
        return c;
    }

    [Fact]
    public async Task TheRustWrittenStoreVerifiesAcrossSegments()
    {
        var status = await new ChainVerifier(new StoreFolder(fixture.Folder)).VerifyAsync(Ct);
        Assert.True(status.Verified, status.Broken?.ToString());
        Assert.Equal(29, status.VerifiedRows);
        Assert.Equal(5, status.FirstSeq);
        Assert.Equal(33, status.LastSeq);
        Assert.Equal(
            [("events-2026-W44.db", 1L, 2L, "age"), ("events-2026-W45.db", 3L, 4L, "age")],
            status.Retired.Select(r => (r.Segment, r.FirstSeq, r.LastSeq, r.Reason)));
        Assert.All(status.Retired, r => Assert.False(r.Archived));
    }

    [Fact]
    public async Task LaterCallsReadOnlyNewRows()
    {
        var dir = fixture.Copy("incremental");
        var verifier = new ChainVerifier(new StoreFolder(dir));
        var before = await verifier.VerifyAsync(Ct);
        Assert.True(before.Verified);

        // Append a valid row to the active segment, chained with the C# hash: the next call
        // must verify it, which also shows the C# hash matches what Rust would chain.
        var active = Path.Combine(dir, "events-2026-W47.db");
        using (var c = Writable(active))
        {
            using var schema = c.CreateCommand();
            schema.CommandText = "PRAGMA user_version";
            var version = checked((int)(long)(await schema.ExecuteScalarAsync(Ct))!);
            using var last = c.CreateCommand();
            last.CommandText = "SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1";
            using var r = last.ExecuteReader();
            r.Read();
            var seq = r.GetInt64(0) + 1;
            var prev = r.GetFieldValue<byte[]>(1);
            r.Close();
            var row = new EventRow(seq, "0193a6f2-0000-7000-8000-00000000abcd", 1_795_400_000_000_000,
                "cli_agent", "s-c1", null, 41000, "/bin/cat", "file", "read",
                "/Users/dev/projects/sample-app/src/new.rs", "allowed", 1024, null, null,
                "/Users/dev/projects/sample-app", "", 1, "", "os");
            using var ins = c.CreateCommand();
            ins.CommandText = """
                INSERT INTO events (seq, event_id, ts_us, tool, session_id, pid, process_path, category,
                    action, target, outcome, size_bytes, project, flags, count, detections, source, prev_hash, hash)
                VALUES ($seq, $id, $ts, $tool, $s, $pid, $pp, $cat, $act, $t, $o, $size, $proj, '', 1, '', 'os', $prev, $hash)
                """;
            ins.Parameters.AddWithValue("$seq", row.Seq);
            ins.Parameters.AddWithValue("$id", row.EventId);
            ins.Parameters.AddWithValue("$ts", row.TsUs);
            ins.Parameters.AddWithValue("$tool", row.Tool);
            ins.Parameters.AddWithValue("$s", row.SessionId);
            ins.Parameters.AddWithValue("$pid", row.Pid);
            ins.Parameters.AddWithValue("$pp", row.ProcessPath);
            ins.Parameters.AddWithValue("$cat", row.Category);
            ins.Parameters.AddWithValue("$act", row.Action);
            ins.Parameters.AddWithValue("$t", row.Target);
            ins.Parameters.AddWithValue("$o", row.Outcome);
            ins.Parameters.AddWithValue("$size", row.SizeBytes);
            ins.Parameters.AddWithValue("$proj", row.Project);
            ins.Parameters.AddWithValue("$prev", prev);
            ins.Parameters.AddWithValue("$hash", Chain.EventHash(prev, row, version));
            ins.ExecuteNonQuery();
        }
        var after = await verifier.VerifyAsync(Ct);
        Assert.True(after.Verified, after.Broken?.ToString());
        Assert.Equal(before.VerifiedRows + 1, after.VerifiedRows);
        Assert.Equal(before.LastSeq + 1, after.LastSeq);
    }

    [Fact]
    public async Task AnEditedRowBreaksTheChainAtThatSeq()
    {
        var dir = fixture.Copy("edited");
        using (var c = Writable(Path.Combine(dir, "events-2026-W46.db")))
        {
            using var cmd = c.CreateCommand();
            cmd.CommandText = "DROP TRIGGER events_no_update; UPDATE events SET target = '/tmp/x' WHERE seq = 7;";
            cmd.ExecuteNonQuery();
        }
        var status = await new ChainVerifier(new StoreFolder(dir)).VerifyAsync(Ct);
        Assert.Equal(new ChainBreak(ChainBreakKind.Hash, "events-2026-W46.db", 7), status.Broken);
    }

    [Fact]
    public async Task ADeletedSegmentIsMissing()
    {
        var dir = fixture.Copy("deleted");
        File.Delete(Path.Combine(dir, "events-2026-W46.db"));
        var status = await new ChainVerifier(new StoreFolder(dir)).VerifyAsync(Ct);
        Assert.Equal(ChainBreakKind.Missing, status.Broken?.Kind);
    }

    [Fact]
    public async Task AChangedCatalogEntryBreaksTheCatalogChain()
    {
        var dir = fixture.Copy("catalog");
        using (var c = Writable(Path.Combine(dir, StoreFolder.CatalogFile)))
        {
            using var cmd = c.CreateCommand();
            cmd.CommandText = "DROP TRIGGER catalog_no_update; UPDATE catalog SET reason = 'size' WHERE seq = 3;";
            cmd.ExecuteNonQuery();
        }
        var status = await new ChainVerifier(new StoreFolder(dir)).VerifyAsync(Ct);
        Assert.Equal(new ChainBreak(ChainBreakKind.Catalog, null, 3), status.Broken);
    }

    [Fact]
    public async Task TheStoreConnectionCannotWrite()
    {
        await using var conn = await new StoreFolder(fixture.Folder).OpenSegmentAsync("events-2026-W47.db", Ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "CREATE TABLE x (a INTEGER)";
        await Assert.ThrowsAsync<SqliteException>(() => cmd.ExecuteNonQueryAsync(Ct));
    }

    /// <summary>The live finding of 15 Nov: a stopped store in a root-owned folder.</summary>
    [Fact]
    public async Task AStoppedStoreIsReadableFromAFolderTheReaderCannotWrite()
    {
        var dir = fixture.Copy("readonly");
        File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserExecute);
        try
        {
            var status = await new ChainVerifier(new StoreFolder(dir)).VerifyAsync(Ct);
            Assert.True(status.Verified, status.Broken?.ToString());
        }
        finally
        {
            File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    [Fact]
    public async Task BundledSqliteSupportsWhatTheApiNeeds()
    {
        // 3.22: read-only WAL readers (ADR-008 Decision 11); 3.43: contentless_delete (ADR-009).
        await using var conn = await new StoreFolder(fixture.Folder).OpenSegmentAsync("events-2026-W47.db", Ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT sqlite_version()";
        var version = Version.Parse((string)(await cmd.ExecuteScalarAsync(Ct))!);
        Assert.True(version >= new Version(3, 43), version.ToString());
    }
}
