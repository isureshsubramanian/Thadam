using Microsoft.Data.Sqlite;

namespace Thadam.Store;

public enum ChainBreakKind
{
    /// <summary>The catalog's own chain is broken at an entry.</summary>
    Catalog,
    /// <summary>A kept segment is not on disk and the catalog does not say it was retired.</summary>
    Missing,
    /// <summary>A segment does not start where the one before it ended.</summary>
    Continuity,
    /// <summary>A closed segment's rows don't match what the catalog recorded at closing.</summary>
    Mismatch,
    /// <summary>A row is missing or rows were reordered.</summary>
    SeqGap,
    /// <summary>A row's prev_hash does not match the row before it.</summary>
    PrevHash,
    /// <summary>A row's content no longer matches its stored hash.</summary>
    Hash,
    /// <summary>A file could not be read as a segment.</summary>
    Unreadable,
}

/// <summary>Where verification stopped. Segment names and sequence numbers only.</summary>
public sealed record ChainBreak(ChainBreakKind Kind, string? Segment, long? Seq);

public sealed record RetiredRange(string Segment, long FirstSeq, long LastSeq, bool Archived, string Reason);

/// <summary>The header's chain badge (ADR-008 Decision 8).</summary>
public sealed record ChainStatus(
    long VerifiedRows,
    long? FirstSeq,
    long? LastSeq,
    ChainBreak? Broken,
    IReadOnlyList<RetiredRange> Retired,
    IReadOnlyList<Pause> Pauses)
{
    public bool Verified => Broken is null;
}

/// <summary>
/// Verifies the event chain across the store's segments: the catalog's own chain, each kept
/// segment's rows, and the continuity between segments (kept or retired). CONTRACT: the same
/// checks as <c>verify_dir</c> in <c>crates/thadam-store/src/segments.rs</c>.
/// <para>
/// Incremental (ADR-008 Decision 8): the first call walks every row; later calls read only
/// rows added since, and skip closed segments already verified. Progress is kept in memory
/// only. Not thread-safe: one caller at a time.
/// </para>
/// </summary>
public sealed class ChainVerifier(StoreFolder folder)
{
    private readonly Dictionary<string, Progress> _progress = new(StringComparer.Ordinal);

    public async Task<ChainStatus> VerifyAsync(CancellationToken ct)
    {
        var catalog = await folder.ReadCatalogAsync(ct).ConfigureAwait(false);
        var pauses = StoreFolder.Pauses(catalog.Entries);
        var retired = new List<RetiredRange>();
        long verified = 0;
        long? first = null;
        long? last = null;
        ChainStatus Result(ChainBreak? broken) => new(verified, first, last, broken, retired, pauses);

        if (catalog.BrokenAt is { } at)
        {
            return Result(new ChainBreak(ChainBreakKind.Catalog, null, at));
        }
        IReadOnlyList<Segment> segments;
        try
        {
            segments = StoreFolder.Segments(catalog.Entries);
        }
        catch (StoreLayoutException)
        {
            return Result(new ChainBreak(ChainBreakKind.Catalog, null, null));
        }

        var expectedSeq = 1L;
        ReadOnlyMemory<byte> expectedPrev = Chain.Genesis;
        foreach (var seg in segments)
        {
            if (seg.FirstSeq != expectedSeq || !seg.FirstPrevHash.Span.SequenceEqual(expectedPrev.Span))
            {
                return Result(new ChainBreak(ChainBreakKind.Continuity, seg.Name, seg.FirstSeq));
            }
            if (!seg.IsKept)
            {
                var end = seg.End!;
                retired.Add(new RetiredRange(seg.Name, seg.FirstSeq, end.LastSeq,
                    seg.State == SegmentState.Archived, seg.Reason ?? ""));
                expectedSeq = end.LastSeq + 1;
                expectedPrev = end.LastHash;
                continue;
            }
            if (!File.Exists(System.IO.Path.Combine(folder.Path, seg.Name)))
            {
                return Result(new ChainBreak(ChainBreakKind.Missing, seg.Name, seg.FirstSeq));
            }
            if (!_progress.TryGetValue(seg.Name, out var p))
            {
                p = new Progress(seg.FirstSeq, seg.FirstPrevHash.ToArray());
                _progress[seg.Name] = p;
            }
            var broken = await WalkAsync(seg, p, ct).ConfigureAwait(false);
            verified += p.Rows;
            if (p.Rows > 0)
            {
                first ??= seg.FirstSeq;
                last = p.NextSeq - 1;
            }
            if (broken is not null)
            {
                return Result(broken);
            }
            if (seg.End is { } closed)
            {
                var matches = p.Rows == closed.Rows
                    && (p.Rows == 0 || (p.NextSeq - 1 == closed.LastSeq
                        && p.PrevHash.AsSpan().SequenceEqual(closed.LastHash.Span)));
                if (!matches)
                {
                    return Result(new ChainBreak(ChainBreakKind.Mismatch, seg.Name, null));
                }
                p.Complete = true;
                expectedSeq = closed.LastSeq + 1;
                expectedPrev = closed.LastHash;
            }
            else
            {
                expectedSeq = p.NextSeq;
                expectedPrev = p.PrevHash;
            }
        }
        foreach (var gone in _progress.Keys.Except(segments.Where(s => s.IsKept).Select(s => s.Name)).ToList())
        {
            _progress.Remove(gone);
        }
        return Result(null);
    }

    /// <summary>Verifies the rows added to a segment since the last walk.</summary>
    private async Task<ChainBreak?> WalkAsync(Segment seg, Progress p, CancellationToken ct)
    {
        if (p.Complete)
        {
            return null;
        }
        SqliteConnection conn;
        try
        {
            conn = await folder.OpenSegmentAsync(seg.Name, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is StoreLayoutException or SqliteException)
        {
            return new ChainBreak(ChainBreakKind.Unreadable, seg.Name, null);
        }
        await using (conn.ConfigureAwait(false))
        {
            await using var cmd = conn.CreateCommand();
            var version = await StoreFolder.SegmentVersionAsync(conn, ct).ConfigureAwait(false);
            cmd.CommandText = $"""
                SELECT {Queries.StoreQueries.Columns(version)}, prev_hash, hash
                FROM events WHERE seq >= $from ORDER BY seq
                """;
            // Rows before the start would show as a gap: read from the start on the first walk.
            cmd.Parameters.AddWithValue("$from", p.Rows == 0 ? long.MinValue : p.NextSeq);
            await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                var seq = r.GetInt64(0);
                if (seq != p.NextSeq)
                {
                    return new ChainBreak(ChainBreakKind.SeqGap, seg.Name, p.NextSeq);
                }
                EventRow row;
                byte[] storedPrev;
                byte[] stored;
                try
                {
                    row = ReadRow(r);
                    storedPrev = r.GetFieldValue<byte[]>(22);
                    stored = r.GetFieldValue<byte[]>(23);
                }
                catch (Exception e) when (e is InvalidCastException or SqliteException)
                {
                    return new ChainBreak(ChainBreakKind.Unreadable, seg.Name, seq);
                }
                if (!storedPrev.AsSpan().SequenceEqual(p.PrevHash))
                {
                    return new ChainBreak(ChainBreakKind.PrevHash, seg.Name, seq);
                }
                if (!Chain.EventHash(p.PrevHash, row, version).AsSpan().SequenceEqual(stored))
                {
                    return new ChainBreak(ChainBreakKind.Hash, seg.Name, seq);
                }
                p.PrevHash = stored;
                p.NextSeq++;
                p.Rows++;
            }
        }
        return null;
    }

    internal static EventRow ReadRow(SqliteDataReader r) => new(
        r.GetInt64(0), r.GetString(1), r.GetInt64(2), r.GetString(3), StoreFolder.Text(r, 4),
        StoreFolder.Text(r, 5), r.GetInt64(6), r.GetString(7), r.GetString(8), r.GetString(9),
        r.GetString(10), r.GetString(11), StoreFolder.Int(r, 12), StoreFolder.Int(r, 13),
        StoreFolder.Int(r, 14), StoreFolder.Text(r, 15), r.GetString(16), r.GetInt64(17),
        r.GetString(18), r.GetString(19), StoreFolder.Text(r, 20), StoreFolder.Text(r, 21));

    private sealed class Progress(long nextSeq, byte[] prevHash)
    {
        public long NextSeq { get; set; } = nextSeq;
        public byte[] PrevHash { get; set; } = prevHash;
        public long Rows { get; set; }
        public bool Complete { get; set; }
    }
}
