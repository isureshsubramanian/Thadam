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
