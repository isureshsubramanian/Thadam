using System.Text.Json;
using Microsoft.Data.Sqlite;
using Thadam.Api.Security;
using Thadam.Audit;

namespace Thadam.Api.Tests;

/// <summary>ADR-008 acceptance test 7 (audit part) and the password store.</summary>
public sealed class AuditLogTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"thadam-audit-test-{Guid.NewGuid():N}");

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
        Assert.True(await log.SetReviewedAsync("e-1", reviewed: true, Ct));
        Assert.False(await log.SetReviewedAsync("e-1", reviewed: true, Ct));
        Assert.Equal(["e-1"], await log.ReviewedEventsAsync(Ct));
        Assert.True(await log.SetReviewedAsync("e-1", reviewed: false, Ct));
        Assert.Empty(await log.ReviewedEventsAsync(Ct));
        Assert.False(await log.SetReviewedAsync("e-2", reviewed: false, Ct));
        Assert.Equal(["flag_reviewed", "flag_reopened"], (await log.EntriesAsync(Ct)).Select(e => e.Action));
        Assert.True((await log.VerifyAsync(Ct)).Ok);
    }

    [Fact]
    public async Task UpdateAndDeleteAreRejectedAndATamperedEntryFailsVerify()
    {
        await using (var log = await AuditLog.OpenAsync(AuditPath, "dev", TimeProvider.System, Ct))
        {
            await log.AppendAsync(AuditAction.SignIn, "", AuditOutcome.Failed, Ct);
            await log.AppendAsync(AuditAction.SignIn, "", AuditOutcome.Succeeded, Ct);
            await log.AppendAsync(AuditAction.Search, "", AuditOutcome.Succeeded, Ct);
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
