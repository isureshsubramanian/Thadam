using Thadam.Store;

namespace Thadam.Api.Endpoints;

/// <summary>The header's data (ADR-008 Decision 4). Tools and the date range follow in step 3.</summary>
public static class MetaEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        ArgumentNullException.ThrowIfNull(api);
        api.MapGet("/meta", (ChainMonitor chain) => Results.Json(new { chain = Describe(chain.State) }))
            .RequireAuthorization();
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
