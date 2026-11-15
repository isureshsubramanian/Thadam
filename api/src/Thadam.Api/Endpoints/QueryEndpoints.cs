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
        api.MapPost("/flags/review", (ReviewBatch batch, [AsParameters] Deps d, CancellationToken ct) =>
            ReviewManyAsync(batch, true, d, ct)).RequireAuthorization().RequireCsrf().Validate<ReviewBatch, ReviewBatchValidator>();
        api.MapPost("/flags/reopen", (ReviewBatch batch, [AsParameters] Deps d, CancellationToken ct) =>
            ReviewManyAsync(batch, false, d, ct)).RequireAuthorization().RequireCsrf().Validate<ReviewBatch, ReviewBatchValidator>();
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
            hosts = o.Hosts.Select(Host),
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
        var limit = Args.Limit(args.Limit);
        var filter = Args.Filter(args.Q);
        var name = await d.NamesAsync(ct).ConfigureAwait(false);
        var listed = all
            .Where(i => i.Reviewed == wantReviewed)
            .Where(i => args.Severity is null || SeverityRule.WireName(i.Severity) == args.Severity)
            .Where(i => filter is null || Args.Matches(filter, i.Target, i.SessionId, i.Tool, name(i.Tool), i.Rule))
            .ToList();
        if (filter is not null)
        {
            await d.Audit.AppendAsync(AuditAction.Search, "", AuditOutcome.Succeeded, ct).ConfigureAwait(false);
        }
        var matching = listed.Where(i => after is null || i.LastSeq < after).Take(limit + 1).ToList();
        var page = matching.Take(limit).ToList();
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
            next = matching.Count > limit ? page[^1].LastSeq : (long?)null,
            total = (long?)listed.Count,
            totalCapped = false,
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

    /// <summary>
    /// Marks up to one page of flags reviewed, or reopens them (ADR-014 Decision 5). Every id is
    /// checked before anything is written: one unknown or unflagged id fails the whole request
    /// (404, each failing id audited as failed). Each change is its own audit entry, as with
    /// single reviews; ids already in the wanted state write nothing.
    /// </summary>
    private static async Task<IResult> ReviewManyAsync(ReviewBatch batch, bool reviewed, Deps d, CancellationToken ct)
    {
        var ids = batch.EventIds ?? [];
        var action = reviewed ? AuditAction.FlagReviewed : AuditAction.FlagReopened;
        var missing = new List<string>();
        foreach (var id in ids)
        {
            if ((await d.Queries.FindEventAsync(id, ct).ConfigureAwait(false))?.Severity is null)
            {
                missing.Add(id);
            }
        }
        if (missing.Count > 0)
        {
            foreach (var id in missing)
            {
                await d.Audit.AppendAsync(action, id, AuditOutcome.Failed, ct).ConfigureAwait(false);
            }
            return Results.NotFound();
        }
        var changed = await d.Audit.SetReviewedManyAsync(ids, reviewed, ct).ConfigureAwait(false);
        return Results.Json(new { changed });
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
        var limit = Args.Limit(args.Limit);
        var filter = Args.Filter(args.Q);
        var name = await d.NamesAsync(ct).ConfigureAwait(false);
        var listed = (await d.Queries.SessionsAsync(new Filter(range, args.Tool), ct).ConfigureAwait(false))
            .Where(s => filter is null || Args.Matches(filter, s.SessionId, s.Tool, name(s.Tool), s.Project))
            .ToList();
        if (filter is not null)
        {
            await d.Audit.AppendAsync(AuditAction.Search, "", AuditOutcome.Succeeded, ct).ConfigureAwait(false);
        }
        var matching = listed.Where(s => after is null || s.LastSeq < after).Take(limit + 1).ToList();
        var page = matching.Take(limit).ToList();
        return Results.Json(new
        {
            range = Range(range),
            items = page.Select(s => Session(s, name)),
            next = matching.Count > limit ? page[^1].LastSeq : (long?)null,
            total = (long?)listed.Count,
            totalCapped = false,
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
        IReadOnlyList<string> ids = [.. tree.Select(s => s.SessionId)];
        var includeInternal = args.Internal == "true";
        var after = Args.After(args.After);
        var page = await d.Queries.TimelineAsync(ids, includeInternal, after ?? 0, Args.Limit(args.Limit), ct).ConfigureAwait(false);
        // Counted on the first page only; later pages keep the first page's total.
        long? total = after is null
            ? await d.Queries.TimelineCountAsync(ids, includeInternal, long.MaxValue, ct).ConfigureAwait(false)
            : null;
        var name = await d.NamesAsync(ct).ConfigureAwait(false);
        return Results.Json(new
        {
            session = Session(tree[0], name),
            children = tree.Skip(1).Select(s => Session(s, name)),
            events = page.Items.Select(e => Event(e, name)),
            next = page.Next,
            total,
            totalCapped = false,
        });
    }

    /// <summary>One row as the timeline and search show it.</summary>
    internal static object Event(EventView e, Func<string, string> name) => new
    {
        seq = e.Seq,
        eventId = e.EventId,
        ts = Values.Time(e.TsUs),
        tool = e.Tool,
        displayName = name(e.Tool),
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
        agentSessionId = e.AgentSessionId,
        transcript = e.Transcript,
        severity = e.Severity is { } s ? SeverityRule.WireName(s) : null,
        rule = e.Rule,
    };

    internal static object Host(HostStats h) => new
    {
        target = h.Target,
        flows = h.Flows,
        bytesOut = h.BytesOut,
        bytesIn = h.BytesIn,
        unknown = h.Unknown,
        flaggedFlows = h.FlaggedFlows,
        category = h.Category,
    };

    internal static object Range(TimeRange r) => new { from = Values.Time(r.FromUs), to = Values.Time(r.ToUs) };

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
        prompts = s.Prompts,
        rows = s.Rows,
        events = s.Events,
    };
}
