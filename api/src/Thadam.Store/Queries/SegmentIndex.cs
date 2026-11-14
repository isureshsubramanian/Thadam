using System.Collections.Concurrent;
using Microsoft.Data.Sqlite;

namespace Thadam.Store.Queries;

/// <summary>A kept segment and the time span of its rows.</summary>
public sealed record SegmentSpan(string Name, long FirstSeq, long MinTsUs, long MaxTsUs);

/// <summary>
/// Finds the segments a query needs (ADR-009, effects on ADR-008): each kept segment's time
/// span, from its own rows, so a late row in the active week is still found. Closed segments
/// never change, so their spans are cached. Queries open each segment on its own; no ATTACH.
/// </summary>
public sealed class SegmentIndex(StoreFolder folder)
{
    private readonly ConcurrentDictionary<string, SegmentSpan?> _closed = new(StringComparer.Ordinal);

    public StoreFolder Folder => folder;

    /// <summary>Kept segments that have rows, oldest first.</summary>
    public async Task<IReadOnlyList<SegmentSpan>> ListAsync(CancellationToken ct)
    {
        var catalog = await folder.ReadCatalogAsync(ct).ConfigureAwait(false);
        var spans = new List<SegmentSpan>();
        foreach (var seg in StoreFolder.Segments(catalog.Entries).Where(s => s.IsKept))
        {
            SegmentSpan? span;
            if (seg.State == SegmentState.Closed && _closed.TryGetValue(seg.Name, out var cached))
            {
                span = cached;
            }
            else
            {
                span = await SpanAsync(seg, ct).ConfigureAwait(false);
                if (seg.State == SegmentState.Closed)
                {
                    _closed[seg.Name] = span;
                }
            }
            if (span is not null)
            {
                spans.Add(span);
            }
        }
        return spans;
    }

    public async Task<IReadOnlyList<SegmentSpan>> OverlappingAsync(TimeRange range, CancellationToken ct) =>
        [.. (await ListAsync(ct).ConfigureAwait(false)).Where(s => range.Overlaps(s.MinTsUs, s.MaxTsUs))];

    public Task<SqliteConnection> OpenAsync(SegmentSpan span, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(span);
        return folder.OpenSegmentAsync(span.Name, ct);
    }

    private async Task<SegmentSpan?> SpanAsync(Segment seg, CancellationToken ct)
    {
        await using var conn = await folder.OpenSegmentAsync(seg.Name, ct).ConfigureAwait(false);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT min(ts_us), max(ts_us) FROM events";
        await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await r.ReadAsync(ct).ConfigureAwait(false) || r.IsDBNull(0))
        {
            return null;
        }
        return new SegmentSpan(seg.Name, seg.FirstSeq, r.GetInt64(0), r.GetInt64(1));
    }
}
