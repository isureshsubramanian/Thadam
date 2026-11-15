using System.Globalization;
using FluentValidation;
using Thadam.Api.Export;
using Thadam.Audit;
using Thadam.Store.Queries;
using Thadam.Store.Search;

namespace Thadam.Api.Endpoints;

/// <summary>Either a search (<c>q</c>) or a session timeline (<c>session</c>, <c>internal</c>).</summary>
public sealed record ExportArgs(string? Q, string? Session, string? Internal);

public sealed class ExportArgsValidator : AbstractValidator<ExportArgs>
{
    public ExportArgsValidator()
    {
        // Exactly one source; `internal` belongs to the timeline only.
        RuleFor(a => a.Q).Must((a, q) => (q is null) != (a.Session is null));
        RuleFor(a => a.Session).Must(s => s is null || Args.IsId(s));
        RuleFor(a => a.Internal).Must((a, i) => i is null || (a.Session is not null && i is "true" or "false"));
    }
}

/// <summary>
/// <c>GET /export</c> (ADR-012): the rows a search or a session timeline lists, as CSV. Pinned
/// to the newest row at the start, counted first, and refused above
/// <see cref="ApiOptions.ExportMaxRows"/> rather than cut short. Each attempt is one audit entry with
/// the export ID; never the query, the count or any value (Decision 6).
/// </summary>
public static class ExportEndpoints
{
    private static readonly string[] TooMany = ["rows"];

    public static void Map(RouteGroupBuilder api)
    {
        ArgumentNullException.ThrowIfNull(api);
        api.MapGet("/export", ExportAsync).RequireAuthorization();
    }

    private static async Task<IResult> ExportAsync(
        [AsParameters] ExportArgs args, SearchRunner runner, ApiOptions options, [AsParameters] QueryEndpoints.Deps d,
        HttpContext http, CancellationToken ct)
    {
        var exportId = Guid.CreateVersion7().ToString();
        Task Audit(AuditOutcome outcome) => d.Audit.AppendAsync(AuditAction.Export, exportId, outcome, CancellationToken.None);

        if (await Validation.CheckAsync(new ExportArgsValidator(), args, ct).ConfigureAwait(false) is { } bad)
        {
            await Audit(AuditOutcome.Failed).ConfigureAwait(false);
            return bad;
        }
        var upTo = await d.Queries.NewestSeqAsync(ct).ConfigureAwait(false);
        long? count;
        Func<CancellationToken, IAsyncEnumerable<ExportRow>> rows;
        if (args.Q is not null)
        {
            var (query, error) = SearchEndpoints.Parse(args.Q, await d.Registry.ToolsAsync(ct).ConfigureAwait(false), d.Time);
            if (query is null)
            {
                await Audit(AuditOutcome.Failed).ConfigureAwait(false);
                return Validation.Invalid([error?.Field ?? "q"]);
            }
            count = await runner.CountAsync(query, upTo, ct).ConfigureAwait(false);
            rows = c => runner.RowsAsync(query, upTo, c);
        }
        else
        {
            var sessionId = args.Session!;
            var tree = await d.Queries.SessionTreeAsync(sessionId, ct).ConfigureAwait(false);
            if (tree.Count == 0 || tree[0].SessionId != sessionId)
            {
                await Audit(AuditOutcome.Failed).ConfigureAwait(false);
                return Results.NotFound();
            }
            IReadOnlyList<string> ids = [.. tree.Select(s => s.SessionId)];
            var includeInternal = args.Internal == "true";
            count = await d.Queries.TimelineCountAsync(ids, includeInternal, upTo, ct).ConfigureAwait(false);
            rows = c => d.Queries.TimelineRowsAsync(ids, includeInternal, upTo, c);
        }
        if (count is null || count > options.ExportMaxRows)
        {
            await Audit(AuditOutcome.Denied).ConfigureAwait(false);
            return Results.Json(new { errors = TooMany, rows = count, limit = options.ExportMaxRows },
                statusCode: StatusCodes.Status413PayloadTooLarge);
        }

        var name = await d.NamesAsync(ct).ConfigureAwait(false);
        var stamp = d.Time.GetUtcNow().ToString("yyyyMMdd'T'HHmm'Z'", CultureInfo.InvariantCulture);
        var fileName = string.Create(CultureInfo.InvariantCulture, $"thadam-export-{stamp}-s{upTo}.csv");
        http.Response.Headers["X-Thadam-Export-Id"] = exportId;
        return Results.Stream(async body =>
        {
            // The response has started: a failure from here on can only end the download, so it
            // is audited as failed (a client that goes away included) and then ends it.
            var aborted = http.RequestAborted;
            try
            {
                await body.WriteAsync(CsvExport.Bom.ToArray(), aborted).ConfigureAwait(false);
                await using var writer = new StreamWriter(body, CsvExport.Utf8, bufferSize: 64 * 1024, leaveOpen: true);
                await writer.WriteAsync(CsvExport.HeaderLine().AsMemory(), aborted).ConfigureAwait(false);
                await foreach (var row in rows(aborted).ConfigureAwait(false))
                {
                    await writer.WriteAsync(CsvExport.Line(row, name).AsMemory(), aborted).ConfigureAwait(false);
                }
                await writer.FlushAsync(aborted).ConfigureAwait(false);
            }
            catch
            {
                await Audit(AuditOutcome.Failed).ConfigureAwait(false);
                throw;
            }
            await Audit(AuditOutcome.Succeeded).ConfigureAwait(false);
        }, "text/csv; charset=utf-8", fileName);
    }
}
