using System.Runtime.CompilerServices;
using Microsoft.Data.Sqlite;

namespace Thadam.Store;

/// <summary>Why the store folder or a segment cannot be read as the catalog describes.</summary>
public sealed class StoreLayoutException(string message) : Exception(message);

public enum SegmentState
{
    Active,
    Closed,
    Retired,
    Archived,
}

/// <summary>Where a segment's part of the chain ends, as recorded when it closed.</summary>
public sealed record SegmentEnd(long LastSeq, ReadOnlyMemory<byte> LastHash, long LastTsUs, long Rows);

/// <summary>A segment as the catalog describes it (ADR-009 Decision 1).</summary>
public sealed record Segment(
    string Name,
    SegmentState State,
    long FirstSeq,
    ReadOnlyMemory<byte> FirstPrevHash,
    SegmentEnd? End,
    string? Reason)
{
    public bool IsKept => State is SegmentState.Active or SegmentState.Closed;
}

/// <summary>A window the collector did not watch (ADR-013 Decision 1): reason <c>not_running</c>,
/// <c>machine_off</c>, <c>before_start</c>, <c>dropped</c> or <c>hooks_silent</c> (ADR-017), kept as
/// written when unknown.</summary>
public sealed record Gap(long FromUs, long ToUs, string Reason, string? Detail, long? Missed);

/// <summary>A time when writing was paused for lack of disk space (ADR-009 Decision 4).</summary>
public sealed record Pause(long FromUs, long ToUs, long Missed);

/// <summary>The catalog read and checked: its entries, or where its own chain broke.</summary>
public sealed record CatalogRead(IReadOnlyList<CatalogEntry> Entries, long? BrokenAt);

/// <summary>
/// The collector's store folder, opened read-only: <c>catalog.db</c> and the weekly segment
/// files it lists. Nothing here can write: every connection is opened read-only and with
/// <c>query_only</c> set (ADR-001: the API never changes the event store).
/// </summary>
public sealed class StoreFolder
{
    public const string CatalogFile = "catalog.db";
    /// <summary>Segments written before ADR-011 are version 2; newer ones are version 3. Both are read.</summary>
    private static readonly long[] EventSchemaVersions = [2, 3];
    private static readonly long[] CatalogSchemaVersions = [1, 2];

    public StoreFolder(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        Path = path;
    }

    public string Path { get; }

    /// <summary>Opens a segment of this folder read-only and checks its schema version.</summary>
    public async Task<SqliteConnection> OpenSegmentAsync(string name, CancellationToken ct)
    {
        if (name.Contains('/', StringComparison.Ordinal) || !name.EndsWith(".db", StringComparison.Ordinal))
        {
            throw new StoreLayoutException("not a segment name");
        }
        return await OpenReadOnlyAsync(System.IO.Path.Combine(Path, name), EventSchemaVersions, ct)
            .ConfigureAwait(false);
    }

    /// <summary>Reads every catalog entry in order and walks the catalog's own chain.</summary>
    public async Task<CatalogRead> ReadCatalogAsync(CancellationToken ct)
    {
        await using var conn = await OpenCatalogAsync(ct).ConfigureAwait(false);
        return (await ReadFromAsync(conn, [], Chain.Genesis.ToArray(), ct).ConfigureAwait(false)).Read;
    }

    /// <summary>
    /// As <see cref="ReadCatalogAsync"/>, for queries: the catalog only grows, so once its last
    /// checked entry is found unchanged, only the entries after it are read and checked. A
    /// catalog that was replaced, shortened or broken is read in full again. The chain
    /// verifier still reads it in full (<see cref="ReadCatalogAsync"/>).
    /// </summary>
    public async Task<CatalogRead> CatalogAsync(CancellationToken ct)
    {
        // Concurrent calls may each read; the last to finish is kept. One reference, swapped whole.
        var known = _catalog;
        await using var conn = await OpenCatalogAsync(ct).ConfigureAwait(false);
        if (known is not null
            && await StillEndsWithAsync(conn, known.Read.Entries[^1].Seq, known.LastHash, ct).ConfigureAwait(false))
        {
            var more = await ReadFromAsync(conn, known.Read.Entries, known.LastHash, ct).ConfigureAwait(false);
            return more.Read.Entries.Count == known.Read.Entries.Count && more.Read.BrokenAt is null
                ? known.Read
                : Remember(more);
        }
        return Remember(await ReadFromAsync(conn, [], Chain.Genesis.ToArray(), ct).ConfigureAwait(false));
    }

    private CachedCatalog? _catalog;

    /// <summary>A checked catalog read and the stored hash of its last entry.</summary>
    private sealed record CachedCatalog(CatalogRead Read, byte[] LastHash);

    /// <summary>Keeps an unbroken read with entries for the next call; a broken one is read in full each time.</summary>
    private CatalogRead Remember(Checked read)
    {
        _catalog = read.Read is { BrokenAt: null, Entries.Count: > 0 } ? new CachedCatalog(read.Read, read.LastHash) : null;
        return read.Read;
    }

    private Task<SqliteConnection> OpenCatalogAsync(CancellationToken ct) =>
        OpenReadOnlyAsync(System.IO.Path.Combine(Path, CatalogFile), CatalogSchemaVersions, ct);

    private static async Task<bool> StillEndsWithAsync(SqliteConnection conn, long seq, byte[] hash, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT hash FROM catalog WHERE seq = $seq";
        cmd.Parameters.AddWithValue("$seq", seq);
        return await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) is byte[] stored && stored.AsSpan().SequenceEqual(hash);
    }

    /// <summary>A catalog read with the stored hash its last entry ends on.</summary>
    private sealed record Checked(CatalogRead Read, byte[] LastHash);

    /// <summary>Reads the entries after <paramref name="before"/>, continuing its chain from <paramref name="prev"/>.</summary>
    private static async Task<Checked> ReadFromAsync(
        SqliteConnection conn, IReadOnlyList<CatalogEntry> before, byte[] prev, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT seq, at_us, kind, segment, first_seq, last_seq, first_prev_hash, last_hash,
                   last_ts_us, rows, bytes, reason, detail, from_us, to_us, missed, prev_hash, hash
            FROM catalog WHERE seq > $after ORDER BY seq
            """;
        long expected = before.Count == 0 ? 1 : before[^1].Seq + 1;
        cmd.Parameters.AddWithValue("$after", expected - 1);
        await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        var entries = new List<CatalogEntry>(before);
        while (await r.ReadAsync(ct).ConfigureAwait(false))
        {
            var e = new CatalogEntry(
                r.GetInt64(0), r.GetInt64(1), r.GetString(2), Text(r, 3), Int(r, 4), Int(r, 5),
                Text(r, 6), Text(r, 7), Int(r, 8), Int(r, 9), Int(r, 10), Text(r, 11), Text(r, 12),
                Int(r, 13), Int(r, 14), Int(r, 15));
            var storedPrev = r.GetFieldValue<byte[]>(16);
            var stored = r.GetFieldValue<byte[]>(17);
            if (e.Seq != expected
                || !storedPrev.AsSpan().SequenceEqual(prev)
                || !Chain.CatalogHash(prev, e).AsSpan().SequenceEqual(stored))
            {
                return new Checked(new CatalogRead(entries, e.Seq), prev);
            }
            entries.Add(e);
            prev = stored;
            expected++;
        }
        return new Checked(new CatalogRead(entries, null), prev);
    }

    /// <summary>
    /// Folds catalog entries into segments, oldest first. CONTRACT: the same rules as
    /// <c>segments_from</c> in <c>crates/thadam-store/src/segments.rs</c>: a segment's start
    /// never changes, and its latest entry gives its state.
    /// </summary>
    public static IReadOnlyList<Segment> Segments(IEnumerable<CatalogEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var byName = new Dictionary<string, Segment>(StringComparer.Ordinal);
        foreach (var e in entries)
        {
            if (e.Segment is not { } name)
            {
                continue;
            }
            var incomplete = new StoreLayoutException($"{name}: catalog entry {e.Seq} is incomplete");
            var firstSeq = e.FirstSeq ?? throw incomplete;
            var firstPrev = Chain.FromHex(e.FirstPrevHash) ?? throw incomplete;
            var state = e.Kind switch
            {
                "opened" => SegmentState.Active,
                "closed" => SegmentState.Closed,
                "retired" => SegmentState.Retired,
                "archived" => SegmentState.Archived,
                _ => throw new StoreLayoutException($"{name}: unknown catalog kind"),
            };
            SegmentEnd? end = state == SegmentState.Active
                ? null
                : new SegmentEnd(
                    e.LastSeq ?? throw incomplete,
                    Chain.FromHex(e.LastHash) ?? throw incomplete,
                    e.LastTsUs ?? throw incomplete,
                    e.Rows ?? throw incomplete);
            if (byName.TryGetValue(name, out var seg))
            {
                if (seg.FirstSeq != firstSeq || !seg.FirstPrevHash.Span.SequenceEqual(firstPrev))
                {
                    throw new StoreLayoutException($"{name}: catalog start changed");
                }
                byName[name] = seg with { State = state, End = end ?? seg.End, Reason = e.Reason };
            }
            else
            {
                byName[name] = new Segment(name, state, firstSeq, firstPrev, end, e.Reason);
            }
        }
        return [.. byName.Values.OrderBy(s => s.FirstSeq)];
    }

    public static IReadOnlyList<Pause> Pauses(IEnumerable<CatalogEntry> entries) =>
        [.. entries.Where(e => e.Kind == "paused").Select(e => new Pause(e.FromUs ?? 0, e.ToUs ?? 0, e.Missed ?? 0))];

    public static IReadOnlyList<Gap> Gaps(IEnumerable<CatalogEntry> entries) =>
        [.. entries.Where(e => e.Kind == "gap").Select(e => new Gap(
            e.FromUs ?? 0, e.ToUs ?? 0, e.Reason ?? "", e.Detail, e.Missed))];

    private static async Task<SqliteConnection> OpenReadOnlyAsync(string file, long[] versions, CancellationToken ct)
    {
        if (!File.Exists(file))
        {
            throw new StoreLayoutException($"{System.IO.Path.GetFileName(file)}: not found");
        }
        var cs = new SqliteConnectionStringBuilder
        {
            DataSource = file,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString();
        var conn = new SqliteConnection(cs);
        try
        {
            await conn.OpenAsync(ct).ConfigureAwait(false);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "PRAGMA query_only = ON; PRAGMA user_version;";
            var found = (long)(await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L);
            if (!versions.Contains(found))
            {
                throw new StoreLayoutException(
                    $"{System.IO.Path.GetFileName(file)}: schema version {found}, expected {string.Join(" or ", versions)}");
            }
            OpenedVersions.AddOrUpdate(conn, new StrongBox<int>(checked((int)found)));
            return conn;
        }
        catch
        {
            await conn.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>The version each connection opened here was checked against; dropped with the connection.</summary>
    private static readonly ConditionalWeakTable<SqliteConnection, StrongBox<int>> OpenedVersions = new();

    /// <summary>The schema version of an open segment (2 or 3, as checked when it was opened).</summary>
    public static async Task<int> SegmentVersionAsync(SqliteConnection conn, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(conn);
        if (OpenedVersions.TryGetValue(conn, out var opened))
        {
            return opened.Value;
        }
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA user_version";
        return checked((int)(long)(await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? 0L));
    }

    internal static string? Text(SqliteDataReader r, int i) => r.IsDBNull(i) ? null : r.GetString(i);

    internal static long? Int(SqliteDataReader r, int i) => r.IsDBNull(i) ? null : r.GetInt64(i);
}
