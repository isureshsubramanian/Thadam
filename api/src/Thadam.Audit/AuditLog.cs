using Microsoft.Data.Sqlite;
using Thadam.Store;

namespace Thadam.Audit;

public enum AuditAction
{
    SignIn,
    SignOut,
    Search,
    Export,
    FlagReviewed,
    FlagReopened,
}

public enum AuditOutcome
{
    Succeeded,
    Failed,
    Denied,
}

/// <summary>One audit entry: IDs only, never queries, values or results (ADR-008 Decision 6).</summary>
public sealed record AuditEntry(
    long Seq, string AuditId, long TsUs, string ActorId, string Action, string TargetId, string Outcome);

public sealed record AuditVerifyReport(long Verified, long? BrokenAt)
{
    public bool Ok => BrokenAt is null;
}

/// <summary>
/// <c>audit.db</c>: append-only (triggers reject UPDATE and DELETE), hash-chained with domain
/// tag <c>thadam.audit.v1</c> using the event chain's encoding (ADR-002 Decision 5). The file
/// and its folder are private in local mode; collector mode reads root-owned files.
/// Calls from this API are serialised.
/// </summary>
public sealed class AuditLog : IAsyncDisposable
{
    public const string Domain = "thadam.audit.v1";
    private const long SchemaVersion = 1;

    private SqliteConnection? _connection;
    private SqliteConnection _conn => _connection!;
    private string? _readPath;
    private CollectorWriter? _collector;
    private readonly TimeProvider _time;
    private readonly string _actor;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private AuditLog(SqliteConnection? conn, TimeProvider time, string actor)
    {
        _connection = conn;
        _time = time;
        _actor = actor;
    }

    public static string WireName(AuditAction a) => a switch
    {
        AuditAction.SignIn => "sign_in",
        AuditAction.SignOut => "sign_out",
        AuditAction.Search => "search",
        AuditAction.Export => "export",
        AuditAction.FlagReviewed => "flag_reviewed",
        AuditAction.FlagReopened => "flag_reopened",
        _ => throw new ArgumentOutOfRangeException(nameof(a)),
    };

    public static string WireName(AuditOutcome o) => o switch
    {
        AuditOutcome.Succeeded => "succeeded",
        AuditOutcome.Failed => "failed",
        AuditOutcome.Denied => "denied",
        _ => throw new ArgumentOutOfRangeException(nameof(o)),
    };

    /// <summary>Opens or creates the log at <paramref name="path"/>.</summary>
    public static async Task<AuditLog> OpenAsync(string path, string actor, TimeProvider time, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentException.ThrowIfNullOrEmpty(actor);
        ArgumentNullException.ThrowIfNull(time);
        PrivateFiles.EnsureFile(path);
        var conn = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
        }.ToString());
        try
        {
            await conn.OpenAsync(ct).ConfigureAwait(false);
            await ApplySchemaAsync(conn, ct).ConfigureAwait(false);
            return new AuditLog(conn, time, actor);
        }
        catch
        {
            await conn.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public static async Task<AuditLog> OpenCollectorAsync(
        string path, string socketPath, string actor, TimeProvider time, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentException.ThrowIfNullOrEmpty(socketPath);
        ArgumentException.ThrowIfNullOrEmpty(actor);
        ArgumentNullException.ThrowIfNull(time);
        var log = new AuditLog(null, time, actor)
        {
            _readPath = path,
            _collector = new CollectorWriter(socketPath, actor),
        };
        try
        {
            await log.RefreshReaderAsync(ct).ConfigureAwait(false);
            return log;
        }
        catch
        {
            await log.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public Task CheckAvailableAsync(CancellationToken ct) => _collector?.PingAsync(ct) ?? Task.CompletedTask;

    private async Task RefreshReaderAsync(CancellationToken ct)
    {
        if (_readPath is null) return;
        if (_connection is not null) await _connection.DisposeAsync().ConfigureAwait(false);
        _connection = null;
        if (!File.Exists(_readPath)) return;
        var conn = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _readPath,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        try
        {
            await conn.OpenAsync(ct).ConfigureAwait(false);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "PRAGMA query_only = ON; PRAGMA user_version;";
            if ((long)(await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L) != SchemaVersion)
                throw new InvalidOperationException("audit.db schema version is not supported");
            _connection = conn;
        }
        catch
        {
            await conn.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async Task<AuditEntry> AppendAsync(
        AuditAction action, string targetId, AuditOutcome outcome, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(targetId);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return await AppendLockedAsync(action, targetId, outcome, ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Marks a flagged event reviewed or reopens it. Review state is derived from the latest
    /// review entry for the event; a call that would not change it writes nothing.
    /// Returns true when an entry was written.
    /// </summary>
    public async Task<bool> SetReviewedAsync(string eventId, bool reviewed, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(eventId);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await RefreshReaderAsync(ct).ConfigureAwait(false);
            var current = await IsReviewedLockedAsync(eventId, ct).ConfigureAwait(false);
            if (current == reviewed)
            {
                return false;
            }
            var action = reviewed ? AuditAction.FlagReviewed : AuditAction.FlagReopened;
            await AppendLockedAsync(action, eventId, AuditOutcome.Succeeded, ct).ConfigureAwait(false);
            return true;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Event IDs whose latest review entry is <c>flag_reviewed</c>.</summary>
    public async Task<IReadOnlySet<string>> ReviewedEventsAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await RefreshReaderAsync(ct).ConfigureAwait(false);
            if (_connection is null) return new HashSet<string>(StringComparer.Ordinal);
            await using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                SELECT target_id FROM audit a
                WHERE action IN ('flag_reviewed', 'flag_reopened') AND outcome = 'succeeded'
                  AND seq = (SELECT max(seq) FROM audit b
                             WHERE b.target_id = a.target_id
                               AND b.action IN ('flag_reviewed', 'flag_reopened') AND b.outcome = 'succeeded')
                  AND action = 'flag_reviewed'
                """;
            var set = new HashSet<string>(StringComparer.Ordinal);
            await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                set.Add(r.GetString(0));
            }
            return set;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<AuditEntry>> EntriesAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await RefreshReaderAsync(ct).ConfigureAwait(false);
            if (_connection is null) return Array.Empty<AuditEntry>();
            var list = new List<AuditEntry>();
            await using var cmd = _conn.CreateCommand();
            cmd.CommandText = "SELECT seq, audit_id, ts_us, actor_id, action, target_id, outcome FROM audit ORDER BY seq";
            await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                list.Add(Read(r));
            }
            return list;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Walks the chain; reports the first entry that does not verify.</summary>
    public async Task<AuditVerifyReport> VerifyAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await RefreshReaderAsync(ct).ConfigureAwait(false);
            if (_connection is null) return new AuditVerifyReport(0, null);
            await using var cmd = _conn.CreateCommand();
            cmd.CommandText = "SELECT seq, audit_id, ts_us, actor_id, action, target_id, outcome, prev_hash, hash FROM audit ORDER BY seq";
            await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            var prev = Chain.Genesis.ToArray();
            long expected = 1;
            long verified = 0;
            while (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                var e = Read(r);
                var storedPrev = r.GetFieldValue<byte[]>(7);
                var stored = r.GetFieldValue<byte[]>(8);
                if (e.Seq != expected || !storedPrev.AsSpan().SequenceEqual(prev)
                    || !Hash(prev, e).AsSpan().SequenceEqual(stored))
                {
                    return new AuditVerifyReport(verified, e.Seq);
                }
                prev = stored;
                expected++;
                verified++;
            }
            return new AuditVerifyReport(verified, null);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>CONTRACT: the audit chain's encoding; golden vectors in golden-chain.json.</summary>
    public static byte[] Hash(ReadOnlySpan<byte> prevHash, AuditEntry e)
    {
        ArgumentNullException.ThrowIfNull(e);
        return new Wire()
            .Text(Domain)
            .Int(e.Seq)
            .Text(e.AuditId)
            .Int(e.TsUs)
            .Text(e.ActorId)
            .Text(e.Action)
            .Text(e.TargetId)
            .Text(e.Outcome)
            .Hash(prevHash);
    }

    public async ValueTask DisposeAsync()
    {
        if (_connection is not null) await _connection.DisposeAsync().ConfigureAwait(false);
        _gate.Dispose();
    }

    private async Task<AuditEntry> AppendLockedAsync(
        AuditAction action, string targetId, AuditOutcome outcome, CancellationToken ct)
    {
        if (_collector is not null)
            return await _collector.AppendAsync(action, targetId, outcome, ct).ConfigureAwait(false);
        await using var tx = (SqliteTransaction)await _conn.BeginTransactionAsync(ct).ConfigureAwait(false);
        await using var last = _conn.CreateCommand();
        last.Transaction = tx;
        last.CommandText = "SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1";
        long seq = 1;
        var prev = Chain.Genesis.ToArray();
        await using (var r = await last.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            if (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                seq = r.GetInt64(0) + 1;
                prev = r.GetFieldValue<byte[]>(1);
            }
        }
        var entry = new AuditEntry(
            seq,
            Guid.CreateVersion7(_time.GetUtcNow()).ToString(),
            _time.GetUtcNow().ToUnixTimeMilliseconds() * 1000,
            _actor,
            WireName(action),
            targetId,
            WireName(outcome));
        await using var ins = _conn.CreateCommand();
        ins.Transaction = tx;
        ins.CommandText = """
            INSERT INTO audit (seq, audit_id, ts_us, actor_id, action, target_id, outcome, prev_hash, hash)
            VALUES ($seq, $id, $ts, $actor, $action, $target, $outcome, $prev, $hash)
            """;
        ins.Parameters.AddWithValue("$seq", entry.Seq);
        ins.Parameters.AddWithValue("$id", entry.AuditId);
        ins.Parameters.AddWithValue("$ts", entry.TsUs);
        ins.Parameters.AddWithValue("$actor", entry.ActorId);
        ins.Parameters.AddWithValue("$action", entry.Action);
        ins.Parameters.AddWithValue("$target", entry.TargetId);
        ins.Parameters.AddWithValue("$outcome", entry.Outcome);
        ins.Parameters.AddWithValue("$prev", prev);
        ins.Parameters.AddWithValue("$hash", Hash(prev, entry));
        await ins.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        await tx.CommitAsync(ct).ConfigureAwait(false);
        return entry;
    }

    private async Task<bool> IsReviewedLockedAsync(string eventId, CancellationToken ct)
    {
        if (_connection is null) return false;
        await using var cmd = _conn.CreateCommand();
        cmd.CommandText = """
            SELECT action FROM audit
            WHERE target_id = $id AND action IN ('flag_reviewed', 'flag_reopened') AND outcome = 'succeeded'
            ORDER BY seq DESC LIMIT 1
            """;
        cmd.Parameters.AddWithValue("$id", eventId);
        return (string?)await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) == "flag_reviewed";
    }

    private static AuditEntry Read(SqliteDataReader r) => new(
        r.GetInt64(0), r.GetString(1), r.GetInt64(2), r.GetString(3), r.GetString(4), r.GetString(5), r.GetString(6));

    private static async Task ApplySchemaAsync(SqliteConnection conn, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;";
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        cmd.CommandText = "PRAGMA user_version;";
        var version = (long)(await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L);
        if (version == SchemaVersion)
        {
            return;
        }
        if (version != 0)
        {
            throw new InvalidOperationException($"audit.db schema version {version} is not supported");
        }
        cmd.CommandText = """
            BEGIN;
            CREATE TABLE audit (
                seq       INTEGER PRIMARY KEY,
                audit_id  TEXT    NOT NULL UNIQUE,
                ts_us     INTEGER NOT NULL,
                actor_id  TEXT    NOT NULL,
                action    TEXT    NOT NULL CHECK (action IN ('sign_in', 'sign_out', 'search', 'export', 'flag_reviewed', 'flag_reopened')),
                target_id TEXT    NOT NULL DEFAULT '',
                outcome   TEXT    NOT NULL CHECK (outcome IN ('succeeded', 'failed', 'denied')),
                prev_hash BLOB    NOT NULL CHECK (length(prev_hash) = 32),
                hash      BLOB    NOT NULL CHECK (length(hash) = 32)
            ) STRICT;
            CREATE INDEX audit_target ON audit (target_id, seq);
            CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
                BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
            CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
                BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
            PRAGMA user_version = 1;
            COMMIT;
            """;
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }
}
