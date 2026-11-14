using Thadam.Api.Search;
using Thadam.Audit;
using Thadam.Store.Search;

namespace Thadam.Api.Endpoints;

/// <summary>
/// <c>GET /events?q&amp;after</c> (ADR-008 Decisions 4 and 5). Every search is audited
/// without its query (Decision 6): action, outcome and time only.
/// </summary>
public static class SearchEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        ArgumentNullException.ThrowIfNull(api);
        api.MapGet("/events", SearchAsync).RequireAuthorization();
    }

    private static async Task<IResult> SearchAsync(
        string? q, string? after, SearchRunner runner, SearchIndex index, ToolRegistry registry, AuditLog audit,
        TimeProvider time, CancellationToken ct)
    {
        var tools = await registry.ToolsAsync(ct).ConfigureAwait(false);
        string? Resolve(string name) => tools.FirstOrDefault(t =>
            t.Key == name || string.Equals(t.DisplayName, name, StringComparison.OrdinalIgnoreCase))?.Key;

        var (query, error) = SearchParser.Parse(q, Resolve, time.GetUtcNow());
        var bad = error is not null ? error.Field : !Args.IsAfter(after) ? "after" : null;
        if (bad is not null || query is null)
        {
            await audit.AppendAsync(AuditAction.Search, "", AuditOutcome.Failed, ct).ConfigureAwait(false);
            return Validation.Invalid([bad ?? "q"]);
        }
        var result = await runner.RunAsync(query, Args.After(after), ct).ConfigureAwait(false);
        await audit.AppendAsync(AuditAction.Search, "", AuditOutcome.Succeeded, ct).ConfigureAwait(false);
        var names = tools.ToDictionary(t => t.Key, t => t.DisplayName, StringComparer.Ordinal);
        return Results.Json(new
        {
            range = query.Range is { } r ? QueryEndpoints.Range(r) : null,
            index = new { indexedSeq = index.IndexedSeq },
            partial = result.Partial,
            summary = result.Summary is { } s
                ? new
                {
                    rows = s.Rows,
                    records = s.Records,
                    byCategory = s.ByCategory,
                    flagged = s.Flagged,
                    outsideFolders = s.Folders.Select(f => new { folder = f.Folder, records = f.Records }),
                }
                : null,
            hosts = result.Hosts?.Select(QueryEndpoints.Host),
            items = result.Page.Items.Select(e => QueryEndpoints.Event(e, key => names.GetValueOrDefault(key, key))),
            next = result.Page.Next,
        });
    }
}
