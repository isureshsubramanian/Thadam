using Thadam.Store;
using Thadam.Store.Queries;

namespace Thadam.Api.Endpoints;

/// <summary>The header's data (ADR-008 Decision 4): chain status, tools, data range, user.</summary>
public static class MetaEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        ArgumentNullException.ThrowIfNull(api);
        api.MapGet("/meta", MetaAsync).RequireAuthorization();
        api.MapGet("/coverage", CoverageAsync).RequireAuthorization();
    }

    private static async Task<IResult> CoverageAsync(
        [AsParameters] RangeArgs args, StoreFolder store, ToolRegistry registry, TimeProvider time, CancellationToken ct)
    {
        var tools = (await registry.ToolsAsync(ct).ConfigureAwait(false)).Select(t => t.Key).ToHashSet(StringComparer.Ordinal);
        if (await Validation.CheckAsync(new RangeArgsValidator(time, tools), args, ct).ConfigureAwait(false) is { } bad)
        {
            return bad;
        }
        var range = Args.Range(args.From, args.To, time);
        var catalog = await store.ReadCatalogAsync(ct).ConfigureAwait(false);
        var gaps = StoreFolder.Gaps(catalog.Entries)
            .Concat(StoreFolder.Pauses(catalog.Entries).Select(p => new Gap(p.FromUs, p.ToUs, "paused", null, p.Missed)))
            .Where(g => g.FromUs < range.ToUs && g.ToUs > range.FromUs)
            .Select(g => g with { FromUs = Math.Max(g.FromUs, range.FromUs), ToUs = Math.Min(g.ToUs, range.ToUs) })
            .Where(g => g.ToUs > g.FromUs)
            .OrderBy(g => g.FromUs).ThenBy(g => g.ToUs).ToList();
        long total = 0;
        long end = range.FromUs;
        foreach (var g in gaps.Where(g => g.Reason is "not_running" or "before_start" or "paused"))
        {
            total += Math.Max(0, g.ToUs - Math.Max(end, g.FromUs));
            end = Math.Max(end, g.ToUs);
        }
        return Results.Json(new
        {
            range = QueryEndpoints.Range(range),
            gaps = gaps.Select(g => new { from = Values.Time(g.FromUs), to = Values.Time(g.ToUs), g.Reason, g.Detail, g.Missed }),
            notWatchedSeconds = total / 1_000_000,
        });
    }

    private static async Task<IResult> MetaAsync(
        ChainMonitor chain, ToolRegistry registry, SegmentIndex index, HttpContext http, CancellationToken ct)
    {
        var spans = await index.ListAsync(ct).ConfigureAwait(false);
        return Results.Json(new
        {
            chain = Describe(chain.State),
            tools = (await registry.ToolsAsync(ct).ConfigureAwait(false)).Select(t => new { key = t.Key, displayName = t.DisplayName }),
            data = spans.Count == 0
                ? null
                : new { from = Values.Time(spans.Min(s => s.MinTsUs)), to = Values.Time(spans.Max(s => s.MaxTsUs)) },
            user = http.User.Identity?.Name,
        });
    }

    internal static object Describe(ChainState state) => state switch
    {
        { Error: { } } => new { state = "unreadable" },
        { Status: null } => new { state = "pending" },
        { Status: { Broken: null } s } => new
        {
            state = "verified",
            firstSeq = s.FirstSeq,
            lastSeq = s.LastSeq,
            rows = s.VerifiedRows,
            retired = s.Retired.Select(r => new { r.FirstSeq, r.LastSeq, r.Reason, r.Archived }),
            pauses = s.Pauses.Select(p => new { p.FromUs, p.ToUs, p.Missed }),
        },
        { Status: { Broken: { } b } s } => new
        {
            state = "broken",
            kind = b.Kind,
            seq = b.Seq,
            firstSeq = s.FirstSeq,
            lastSeq = s.LastSeq,
        },
    };
}
