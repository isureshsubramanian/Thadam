using Microsoft.Data.Sqlite;
using Thadam.Audit;
using Thadam.Store.Queries;
using Thadam.Store.Search;

namespace Thadam.Api.Search;

/// <summary>
/// The API's full-text index, <c>search.db</c> (ADR-008 Decision 5, option C): a
/// contentless FTS5 trigram table over <c>target</c> and <c>process_path</c>, keyed by
/// <c>seq</c>, holding no copy of the text. Derived data, mode 0600: deleted or replaced
/// store means a rebuild, never a repair. Entries of retired segments are deleted
/// (ADR-009, effects on ADR-008), so the index shrinks with the store.
/// </summary>
public sealed class SearchIndex : ITextIndex, IAsyncDisposable
{
    /// <summary>Bumped when the table layout changes; a different version is rebuilt.</summary>
    private const long Version = 1;
    /// <summary>Rows per transaction while tailing (estimate: well under a second each).</summary>
    private const int Batch = 5_000;

    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private SqliteConnection _conn;
    private long _indexedSeq;
    private long _minSeq;

    private SearchIndex(string path, SqliteConnection conn, long indexedSeq, long minSeq)
    {
        _path = path;
        _conn = conn;
        _indexedSeq = indexedSeq;
        _minSeq = minSeq;
    }

    public long IndexedSeq => Interlocked.Read(ref _indexedSeq);

    /// <summary>Opens the index, creating it (0600) when missing or of another version.</summary>
    public static async Task<SearchIndex> OpenAsync(string path, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        var (conn, last, min) = await OpenFileAsync(path, ct).ConfigureAwait(false);
        return new SearchIndex(path, conn, last, min);
    }

    private static async Task<(SqliteConnection, long, long)> OpenFileAsync(string path, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
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
                await ExecAsync(conn, """
                    PRAGMA journal_mode = WAL;
                    CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
                    CREATE VIRTUAL TABLE IF NOT EXISTS terms USING fts5(
                        target, process_path, content = '', contentless_delete = 1, tokenize = 'trigram');
                    INSERT OR IGNORE INTO meta VALUES ('version', 1), ('last_seq', 0), ('min_seq', 0);
                    """, ct).ConfigureAwait(false);
                if (await MetaAsync(conn, "version", ct).ConfigureAwait(false) == Version)
                {
                    return (conn, await MetaAsync(conn, "last_seq", ct).ConfigureAwait(false),
                        await MetaAsync(conn, "min_seq", ct).ConfigureAwait(false));
                }
            }
            catch (SqliteException) when (attempt == 0)
            {
                // Not a usable index file: rebuilt below.
            }
            await conn.DisposeAsync().ConfigureAwait(false);
            if (attempt > 0)
            {
                throw new InvalidOperationException("search index cannot be created");
            }
            Delete(path);
        }
    }

    /// <summary>
    /// Brings the index up to the store: drops retired rows, adds new ones. Returns the rows
    /// added. <paramref name="upToSeq"/> stops early (tests).
    /// </summary>
    public async Task<long> TailAsync(SegmentIndex segments, CancellationToken ct, long upToSeq = long.MaxValue)
    {
        ArgumentNullException.ThrowIfNull(segments);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var spans = await segments.ListAsync(ct).ConfigureAwait(false);
            var head = spans.Count == 0 ? 0 : await HeadAsync(segments, spans[^1], ct).ConfigureAwait(false);
            if (_indexedSeq > head)
            {
                // The store is behind the index: replaced or restored. Start again.
                await ResetLockedAsync(ct).ConfigureAwait(false);
            }
            if (spans.Count > 0 && _minSeq < spans[0].FirstSeq)
            {
                await using var tx = (SqliteTransaction)await _conn.BeginTransactionAsync(ct).ConfigureAwait(false);
                await using (var del = Command("DELETE FROM terms WHERE rowid < $min", tx))
                {
                    del.Parameters.AddWithValue("$min", spans[0].FirstSeq);
                    await del.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                }
                await SetMetaAsync("min_seq", spans[0].FirstSeq, tx, ct).ConfigureAwait(false);
                await tx.CommitAsync(ct).ConfigureAwait(false);
                _minSeq = spans[0].FirstSeq;
            }

            long added = 0;
            foreach (var span in spans)
            {
                await using var store = await segments.OpenAsync(span, ct).ConfigureAwait(false);
                while (_indexedSeq < upToSeq)
                {
                    var n = await CopyBatchAsync(store, upToSeq, ct).ConfigureAwait(false);
                    added += n;
                    if (n < Batch)
                    {
                        break;
                    }
                }
            }
            return added;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Copies the next rows of one segment; seq order, one transaction.</summary>
    private async Task<int> CopyBatchAsync(SqliteConnection store, long upToSeq, CancellationToken ct)
    {
        await using var read = store.CreateCommand();
        read.CommandText = "SELECT seq, target, process_path FROM events WHERE seq > $last AND seq <= $upto ORDER BY seq LIMIT $n";
        read.Parameters.AddWithValue("$last", _indexedSeq);
        read.Parameters.AddWithValue("$upto", upToSeq);
        read.Parameters.AddWithValue("$n", Batch);
        await using var r = await read.ExecuteReaderAsync(ct).ConfigureAwait(false);

        await using var tx = (SqliteTransaction)await _conn.BeginTransactionAsync(ct).ConfigureAwait(false);
        await using var insert = Command("INSERT INTO terms (rowid, target, process_path) VALUES ($seq, $target, $process)", tx);
        var seq = insert.Parameters.Add("$seq", SqliteType.Integer);
        var target = insert.Parameters.Add("$target", SqliteType.Text);
        var process = insert.Parameters.Add("$process", SqliteType.Text);
        var n = 0;
        var last = _indexedSeq;
        while (await r.ReadAsync(ct).ConfigureAwait(false))
        {
            last = r.GetInt64(0);
            seq.Value = last;
            target.Value = r.GetString(1);
            process.Value = r.GetString(2);
            await insert.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            n++;
        }
        if (n > 0)
        {
            await SetMetaAsync("last_seq", last, tx, ct).ConfigureAwait(false);
            await tx.CommitAsync(ct).ConfigureAwait(false);
            Interlocked.Exchange(ref _indexedSeq, last);
        }
        return n;
    }

    /// <summary>
    /// Reads through its own read-only connection (the file is in WAL mode), so a search
    /// never waits for a tail in progress, however long the first build takes.
    /// </summary>
    public async Task<IReadOnlyList<long>> MatchAsync(string ftsQuery, long belowSeq, int cap, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrEmpty(ftsQuery);
        await using var conn = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _path,
            Mode = SqliteOpenMode.ReadOnly,
        }.ToString());
        await conn.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT rowid FROM terms WHERE terms MATCH $q AND rowid < $below ORDER BY rowid DESC LIMIT $cap";
        cmd.Parameters.AddWithValue("$q", ftsQuery);
        cmd.Parameters.AddWithValue("$below", belowSeq);
        cmd.Parameters.AddWithValue("$cap", cap);
        var seqs = new List<long>();
        await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await r.ReadAsync(ct).ConfigureAwait(false))
        {
            seqs.Add(r.GetInt64(0));
        }
        return seqs;
    }

    private async Task ResetLockedAsync(CancellationToken ct)
    {
        await _conn.DisposeAsync().ConfigureAwait(false);
        Delete(_path);
        var (conn, last, min) = await OpenFileAsync(_path, ct).ConfigureAwait(false);
        _conn = conn;
        Interlocked.Exchange(ref _indexedSeq, last);
        _minSeq = min;
    }

    private static async Task<long> HeadAsync(SegmentIndex segments, SegmentSpan newest, CancellationToken ct)
    {
        await using var conn = await segments.OpenAsync(newest, ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT coalesce(max(seq), 0) FROM events";
        return (long)(await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L);
    }

    private SqliteCommand Command(string sql, SqliteTransaction? tx)
    {
        var cmd = _conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.Transaction = tx;
        return cmd;
    }

    private async Task SetMetaAsync(string key, long value, SqliteTransaction tx, CancellationToken ct)
    {
        await using var cmd = Command("UPDATE meta SET value = $v WHERE key = $k", tx);
        cmd.Parameters.AddWithValue("$v", value);
        cmd.Parameters.AddWithValue("$k", key);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static async Task<long> MetaAsync(SqliteConnection conn, string key, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT value FROM meta WHERE key = $k";
        cmd.Parameters.AddWithValue("$k", key);
        return (long)(await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L);
    }

    private static async Task ExecAsync(SqliteConnection conn, string sql, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static void Delete(string path)
    {
        foreach (var f in new[] { path, path + "-wal", path + "-shm" })
        {
            File.Delete(f);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _conn.DisposeAsync().ConfigureAwait(false);
        _gate.Dispose();
    }
}
