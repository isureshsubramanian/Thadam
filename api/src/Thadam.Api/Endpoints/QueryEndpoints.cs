using Thadam.Audit;
using Thadam.Store.Queries;

namespace Thadam.Api.Endpoints;

/// <summary>
/// Overview, flagged queue, review, sessions and timeline (ADR-008 Decision 4). Responses
/// carry stored values as stored: the collector redacted them before they were written.
/// </summary>
public static class QueryEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        ArgumentNullException.ThrowIfNull(api);
        api.MapGet("/overview", OverviewAsync).RequireAuthorization();
        api.MapGet("/flags", FlagsAsync).RequireAuthorization();
        api.MapPost("/flags/{eventId}/review", (string eventId, [AsParameters] Deps d, CancellationToken ct) =>
            ReviewAsync(eventId, true, d, ct)).RequireAuthorization().RequireCsrf();
        api.MapPost("/flags/{eventId}/reopen", (string eventId, [AsParameters] Deps d, CancellationToken ct) =>
            ReviewAsync(eventId, false, d, ct)).RequireAuthorization().RequireCsrf();
        api.MapGet("/sessions", SessionsAsync).RequireAuthorization();
        api.MapGet("/sessions/{sessionId}", TimelineAsync).RequireAuthorization();
    }

    /// <summary>The services every handler uses, bound as one argument.</summary>
    public sealed record Deps(StoreQueries Queries, ToolRegistry Registry, AuditLog Audit, TimeProvider Time)
    {
        public async Task<IReadOnlySet<string>> ToolKeysAsync(CancellationToken ct) =>
            (await Registry.ToolsAsync(ct).ConfigureAwait(false)).Select(t => t.Key).ToHashSet(StringComparer.Ordinal);

        public async Task<Func<string, string>> NamesAsync(CancellationToken ct)
        {
            var names = (await Registry.ToolsAsync(ct).ConfigureAwait(false)).ToDictionary(t => t.Key, t => t.DisplayName, StringComparer.Ordinal);
            return key => names.GetValueOrDefault(key, key);
        }
    }

    private static async Task<IResult> OverviewAsync([AsParameters] RangeArgs args, [AsParameters] Deps d, CancellationToken ct)
    {
        var tools = await d.ToolKeysAsync(ct).ConfigureAwait(false);
        if (await Validation.CheckAsync(new RangeArgsValidator(d.Time, tools), args, ct).ConfigureAwait(false) is { } bad)
        {
            return bad;
        }
        var range = Args.Range(args.From, args.To, d.Time);
        var reviewed = await d.Audit.ReviewedEventsAsync(ct).ConfigureAwait(false);
        var o = await d.Queries.OverviewAsync(new Filter(range, args.Tool), reviewed, ct).ConfigureAwait(false);
        var name = await d.NamesAsync(ct).ConfigureAwait(false);
        return Results.Json(new
        {
            range = Range(range),
            kpis = new
            {
                sessions = o.Sessions,
                outsideProject = new { records = o.OutsideRecords, folders = o.OutsideFolders },
                flaggedOpen = BySeverity(o.FlaggedOpen),
                denied = new { byAgent = o.DeniedByAgent, byUser = o.DeniedByUser, byOs = o.DeniedByOs },
                hosts = new { total = o.HostsTotal, unknown = o.HostsUnknown, networkVolume = o.NetworkVolume },
                sensitive = o.Sensitive,
            },
            byTool = o.ByTool.Select(t => new
            {
                tool = t.Tool,
                displayName = name(t.Tool),
                sessions = t.Sessions,
                filesRead = t.FilesRead,
                filesWritten = t.FilesWritten,
                commands = t.Commands,
                denied = t.Denied,
                outside = t.Outside,
                hosts = t.Hosts,
                flagged = t.FlaggedOpen,
            }),
            outsideFolders = o.Outside.Select(f => new { folder = f.Folder, records = f.Records, tools = f.Tools, flags = f.Flags }),
            hosts = o.Hosts.Select(h => new
            {
                target = h.Target,
                flows = h.Flows,
                bytesOut = h.BytesOut,
                bytesIn = h.BytesIn,
                unknown = h.Unknown,
                category = h.Category,
            }),
        });
    }

    private static async Task<IResult> FlagsAsync([AsParameters] FlagArgs args, [AsParameters] Deps d, CancellationToken ct)
    {
        var tools = await d.ToolKeysAsync(ct).ConfigureAwait(false);
        if (await Validation.CheckAsync(new FlagArgsValidator(d.Time, tools), args, ct).ConfigureAwait(false) is { } bad)
        {
            return bad;
        }
        var range = Args.Range(args.From, args.To, d.Time);
        var reviewed = await d.Audit.ReviewedEventsAsync(ct).ConfigureAwait(false);
        var all = await d.Queries.FlagItemsAsync(new Filter(range, args.Tool), reviewed, ct).ConfigureAwait(false);
        var wantReviewed = args.Status == "reviewed";
        var after = Args.After(args.After);
        var matching = all
            .Where(i => i.Reviewed == wantReviewed)
            .Where(i => args.Severity is null || SeverityRule.WireName(i.Severity) == args.Severity)
            .Where(i => after is null || i.LastSeq < after)
            .Take(StoreQueries.PageSize + 1)
            .ToList();
        var name = await d.NamesAsync(ct).ConfigureAwait(false);
        var page = matching.Take(StoreQueries.PageSize).ToList();
        return Results.Json(new
        {
            range = Range(range),
            items = page.Select(i => new
            {
                eventId = i.LastEventId,
                rule = i.Rule,
                severity = SeverityRule.WireName(i.Severity),
                target = i.Target,
                sessionId = i.SessionId,
                tool = i.Tool,
                displayName = name(i.Tool),
                rows = i.Rows,
                count = i.Count,
                first = Values.Time(i.FirstTsUs),
                last = Values.Time(i.LastTsUs),
                reviewed = i.Reviewed,
            }),
            next = matching.Count > StoreQueries.PageSize ? page[^1].LastSeq : (long?)null,
        });
    }

    /// <summary>
    /// Marks a flagged event reviewed, or reopens it: the API's only domain write, to
    /// <c>audit.db</c> (ADR-008 Decision 7). 404 when the event is unknown or not flagged.
    /// </summary>
    private static async Task<IResult> ReviewAsync(string eventId, bool reviewed, Deps d, CancellationToken ct)
    {
        if (!Args.IsId(eventId))
        {
            return Validation.Invalid(["eventId"]);
        }
        var action = reviewed ? AuditAction.FlagReviewed : AuditAction.FlagReopened;
        var e = await d.Queries.FindEventAsync(eventId, ct).ConfigureAwait(false);
        if (e?.Severity is null)
        {
            await d.Audit.AppendAsync(action, eventId, AuditOutcome.Failed, ct).ConfigureAwait(false);
            return Results.NotFound();
        }
        await d.Audit.SetReviewedAsync(eventId, reviewed, ct).ConfigureAwait(false);
        return Results.NoContent();
    }

    private static async Task<IResult> SessionsAsync([AsParameters] SessionArgs args, [AsParameters] Deps d, CancellationToken ct)
    {
        var tools = await d.ToolKeysAsync(ct).ConfigureAwait(false);
        if (await Validation.CheckAsync(new SessionArgsValidator(d.Time, tools), args, ct).ConfigureAwait(false) is { } bad)
        {
            return bad;
        }
        var range = Args.Range(args.From, args.To, d.Time);
        var after = Args.After(args.After);
        var matching = (await d.Queries.SessionsAsync(new Filter(range, args.Tool), ct).ConfigureAwait(false))
            .Where(s => after is null || s.LastSeq < after)
            .Take(StoreQueries.PageSize + 1)
            .ToList();
        var name = await d.NamesAsync(ct).ConfigureAwait(false);
        var page = matching.Take(StoreQueries.PageSize).ToList();
        return Results.Json(new
        {
            range = Range(range),
            items = page.Select(s => Session(s, name)),
            next = matching.Count > StoreQueries.PageSize ? page[^1].LastSeq : (long?)null,
        });
    }

    private static async Task<IResult> TimelineAsync(
        string sessionId, [AsParameters] TimelineArgs args, [AsParameters] Deps d, CancellationToken ct)
    {
        if (!Args.IsId(sessionId))
        {
            return Validation.Invalid(["sessionId"]);
        }
        if (await Validation.CheckAsync(new TimelineArgsValidator(), args, ct).ConfigureAwait(false) is { } bad)
        {
            return bad;
        }
        var tree = await d.Queries.SessionTreeAsync(sessionId, ct).ConfigureAwait(false);
        if (tree.Count == 0 || tree[0].SessionId != sessionId)
        {
            return Results.NotFound();
        }
        var page = await d.Queries.TimelineAsync(
            [.. tree.Select(s => s.SessionId)], args.Internal == "true", Args.After(args.After) ?? 0, ct).ConfigureAwait(false);
        var name = await d.NamesAsync(ct).ConfigureAwait(false);
        return Results.Json(new
        {
            session = Session(tree[0], name),
            children = tree.Skip(1).Select(s => Session(s, name)),
            events = page.Items.Select(e => new
            {
                seq = e.Seq,
                eventId = e.EventId,
                ts = Values.Time(e.TsUs),
                tool = e.Tool,
                sessionId = e.SessionId,
                pid = e.Pid,
                processPath = e.ProcessPath,
                category = e.Category,
                action = e.Action,
                target = e.Target,
                outcome = e.Outcome,
                sizeBytes = e.SizeBytes,
                bytesOut = e.BytesOut,
                bytesIn = e.BytesIn,
                flags = e.Flags.Order(StringComparer.Ordinal),
                count = e.Count,
                detections = e.Detections,
                source = e.Source,
                severity = e.Severity is { } s ? SeverityRule.WireName(s) : null,
                rule = e.Rule,
            }),
            next = page.Next,
        });
    }

    private static object Range(TimeRange r) => new { from = Values.Time(r.FromUs), to = Values.Time(r.ToUs) };

    private static object BySeverity(IReadOnlyDictionary<Severity, int> counts) => new
    {
        high = counts.GetValueOrDefault(Severity.High),
        medium = counts.GetValueOrDefault(Severity.Medium),
        low = counts.GetValueOrDefault(Severity.Low),
    };

    private static object Session(SessionSummary s, Func<string, string> name) => new
    {
        sessionId = s.SessionId,
        tool = s.Tool,
        displayName = name(s.Tool),
        parentSessionId = s.ParentSessionId,
        project = s.Project,
        first = Values.Time(s.FirstTsUs),
        last = Values.Time(s.LastTsUs),
        rows = s.Rows,
        events = s.Events,
    };
}
