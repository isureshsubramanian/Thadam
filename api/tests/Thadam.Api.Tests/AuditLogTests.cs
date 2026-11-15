using System.Text.Json;
using Microsoft.Data.Sqlite;
using Thadam.Api.Security;
using Thadam.Audit;

namespace Thadam.Api.Tests;

/// <summary>ADR-008 acceptance test 7 (audit part) and the password store.</summary>
public sealed class AuditLogTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"ta-{Guid.NewGuid():N}");

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private string AuditPath => Path.Combine(_dir, "audit.db");

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    [Fact]
    public async Task CollectorRejectsOtherSchemasWithoutMigratingOrChangingPermissions()
    {
        Directory.CreateDirectory(_dir);
        await using (var conn = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = AuditPath, Pooling = false }.ToString()))
        {
            await conn.OpenAsync(Ct);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "PRAGMA user_version = 2";
            await cmd.ExecuteNonQueryAsync(Ct);
        }
        File.SetUnixFileMode(AuditPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        var mode = File.GetUnixFileMode(AuditPath);
        await Assert.ThrowsAsync<InvalidOperationException>(() => AuditLog.OpenCollectorAsync(AuditPath, Path.Combine(_dir, "a.sock"), "dev", TimeProvider.System, Ct));
        Assert.Equal(mode, File.GetUnixFileMode(AuditPath));
        await using var check = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = AuditPath, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        await check.OpenAsync(Ct);
        await using var version = check.CreateCommand();
        version.CommandText = "PRAGMA user_version";
        Assert.Equal(2L, await version.ExecuteScalarAsync(Ct));
    }

    [Fact]
    public async Task CollectorReadsMissingFileThenAppendsAndRefreshesReviews()
    {
        Directory.CreateDirectory(_dir);
        var socket = Path.Combine(_dir, "a.sock");
        await using var log = await AuditLog.OpenCollectorAsync(AuditPath, socket, "dev", TimeProvider.System, Ct);
        Assert.Empty(await log.EntriesAsync(Ct));
        Assert.Empty(await log.ReviewedEventsAsync(Ct));
        Assert.Equal(new AuditVerifyReport(0, null), await log.VerifyAsync(Ct));
        Assert.False(File.Exists(AuditPath));
        await using var collector = new FakeCollector(socket, AuditPath);
        await log.CheckAvailableAsync(null, Ct);
        // Without a session the collector accepts nothing (ADR-015 Decision 1).
        await Assert.ThrowsAsync<AuditSessionEndedException>(() => log.AppendAsync(AuditAction.Search, "", AuditOutcome.Succeeded, null, Ct));
        var signedIn = await log.SignInThroughCollectorAsync(ApiTestHost.Password, Ct);
        Assert.Equal(SignInStatus.SignedIn, signedIn.Status);
        var session = signedIn.Session;
        var entry = await log.AppendAsync(AuditAction.Search, "", AuditOutcome.Succeeded, session, Ct);
        Assert.Equal(entry, (await log.EntriesAsync(Ct))[^1]);
        Assert.Equal(2, entry.Seq);
        Assert.Equal(7, Guid.Parse(entry.AuditId).Version);
        Assert.True(entry.TsUs > 0);
        Assert.True(await log.SetReviewedAsync("e-1", true, session, Ct));
        Assert.False(await log.SetReviewedAsync("e-1", true, session, Ct));
        Assert.Equal("dev", Assert.Single(await log.ReviewsAsync(["e-1", "e-2"], Ct)).Value.ActorId);
        Assert.True(await log.SetReviewedAsync("e-1", false, session, Ct));
        Assert.False(await log.SetReviewedAsync("e-1", false, session, Ct));
        Assert.Empty(await log.ReviewsAsync(["e-1"], Ct));
        await log.SignOutAsync(session, Ct);
        await Assert.ThrowsAsync<AuditSessionEndedException>(() => log.AppendAsync(AuditAction.Search, "", AuditOutcome.Succeeded, session, Ct));
        Assert.Equal(["sign_in", "search", "flag_reviewed", "flag_reopened", "sign_out"], (await log.EntriesAsync(Ct)).Select(e => e.Action));
        Assert.True((await log.VerifyAsync(Ct)).Ok);
    }

    [Fact]
    public async Task AbsentCollectorAndRefusedSenderAreUnavailable()
    {
        Directory.CreateDirectory(_dir);
        var socket = Path.Combine(_dir, "a.sock");
        await using var log = await AuditLog.OpenCollectorAsync(AuditPath, socket, "dev", TimeProvider.System, Ct);
        await Assert.ThrowsAsync<AuditUnavailableException>(() => log.CheckAvailableAsync(null, Ct));
        await using var collector = new FakeCollector(socket, AuditPath) { Error = "refused" };
        var error = await Assert.ThrowsAsync<AuditUnavailableException>(() => log.SignInThroughCollectorAsync(ApiTestHost.Password, Ct));
        Assert.Contains("refused", error.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(AuditPath));
    }

    [Fact]
    public void VectorsMatchTheIndependentImplementation()
    {
        var f = JsonElement.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "golden-chain.json"))).GetProperty("audit_v1");
        Assert.Equal(AuditLog.Domain, f.GetProperty("domain").GetString());
        var prev = Thadam.Store.Chain.Genesis.ToArray();
        foreach (var v in f.GetProperty("rows").EnumerateArray())
        {
            var e = new AuditEntry(v.GetProperty("seq").GetInt64(), v.GetProperty("audit_id").GetString()!,
                v.GetProperty("ts_us").GetInt64(), v.GetProperty("actor_id").GetString()!,
                v.GetProperty("action").GetString()!, v.GetProperty("target_id").GetString()!,
                v.GetProperty("outcome").GetString()!);
            var h = AuditLog.Hash(prev, e);
            Assert.Equal(v.GetProperty("hash").GetString(), Thadam.Store.Chain.ToHex(h));
            prev = h;
        }
    }

    [Fact]
    public async Task ReviewingTwiceWritesOnceAndReopenRestores()
    {
        await using var log = await AuditLog.OpenAsync(AuditPath, "dev", TimeProvider.System, Ct);
        Assert.True(await log.SetReviewedAsync("e-1", reviewed: true, null, Ct));
        Assert.False(await log.SetReviewedAsync("e-1", reviewed: true, null, Ct));
        Assert.Equal(["e-1"], await log.ReviewedEventsAsync(Ct));
        Assert.True(await log.SetReviewedAsync("e-1", reviewed: false, null, Ct));
        Assert.Empty(await log.ReviewedEventsAsync(Ct));
        Assert.False(await log.SetReviewedAsync("e-2", reviewed: false, null, Ct));
        Assert.Equal(["flag_reviewed", "flag_reopened"], (await log.EntriesAsync(Ct)).Select(e => e.Action));
        Assert.True((await log.VerifyAsync(Ct)).Ok);
    }

    [Fact]
    public async Task UpdateAndDeleteAreRejectedAndATamperedEntryFailsVerify()
    {
        await using (var log = await AuditLog.OpenAsync(AuditPath, "dev", TimeProvider.System, Ct))
        {
            await log.AppendAsync(AuditAction.SignIn, "", AuditOutcome.Failed, null, Ct);
            await log.AppendAsync(AuditAction.SignIn, "", AuditOutcome.Succeeded, null, Ct);
            await log.AppendAsync(AuditAction.Search, "", AuditOutcome.Succeeded, null, Ct);
        }
        using (var c = new SqliteConnection($"Data Source={AuditPath};Pooling=False"))
        {
            c.Open();
            using var upd = c.CreateCommand();
            upd.CommandText = "UPDATE audit SET outcome = 'succeeded' WHERE seq = 1";
            Assert.Throws<SqliteException>(() => upd.ExecuteNonQuery());
            upd.CommandText = "DELETE FROM audit WHERE seq = 1";
            Assert.Throws<SqliteException>(() => upd.ExecuteNonQuery());
            upd.CommandText = "DROP TRIGGER audit_no_update; UPDATE audit SET outcome = 'succeeded' WHERE seq = 1";
            upd.ExecuteNonQuery();
        }
        await using var reopened = await AuditLog.OpenAsync(AuditPath, "dev", TimeProvider.System, Ct);
        Assert.Equal(new AuditVerifyReport(0, 1), await reopened.VerifyAsync(Ct));
    }

    [Fact]
    public async Task PasswordsAreHashedAndCheckedNotStored()
    {
        var path = Path.Combine(_dir, "credentials.json");
        await Credentials.SaveAsync(path, Credentials.Create("a long enough test password"), Ct);
        var text = await File.ReadAllTextAsync(path, Ct);
        Assert.DoesNotContain("enough", text, StringComparison.Ordinal);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
        var stored = await Credentials.LoadAsync(path, Ct);
        Assert.NotNull(stored);
        Assert.Equal(600_000, stored.Iterations);
        Assert.True(Credentials.Verify("a long enough test password", stored));
        Assert.False(Credentials.Verify("a long enough test passworD", stored));
        Assert.NotNull(Credentials.Problem("short"));
        Assert.Null(Credentials.Problem("fifteen chars!!"));
    }
}
