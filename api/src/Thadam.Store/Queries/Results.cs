namespace Thadam.Store.Queries;

/// <summary>Which rows a query covers: a time range, and optionally one tool.</summary>
public sealed record Filter(TimeRange Range, string? Tool);

/// <summary>One stored row, as the dashboard shows it. Values exactly as stored (already redacted).</summary>
public sealed record EventView(
    long Seq,
    string EventId,
    long TsUs,
    string Tool,
    string? SessionId,
    string? ParentSessionId,
    long Pid,
    string ProcessPath,
    string Category,
    string Action,
    string Target,
    string Outcome,
    long? SizeBytes,
    long? BytesOut,
    long? BytesIn,
    string? Project,
    IReadOnlySet<string> Flags,
    long Count,
    IReadOnlyDictionary<string, long> Detections,
    string Source,
    Severity? Severity,
    string? Rule,
    string? AgentSessionId = null,
    string? Transcript = null);

/// <summary>
/// One flagged-queue item: rows grouped by (rule, target, session), so 200 reads of one
/// folder are one item (ADR-008 Decision 7). Keyed by its latest event: reviewing marks
/// "reviewed up to here", so a new row in the same group opens the item again.
/// </summary>
public sealed record FlagItem(
    string Rule,
    Severity Severity,
    string Target,
    string? SessionId,
    string Tool,
    long Rows,
    long Count,
    long FirstTsUs,
    long LastTsUs,
    long LastSeq,
    string LastEventId,
    bool Reviewed);

public sealed record SessionSummary(
    string SessionId,
    string Tool,
    string? ParentSessionId,
    string? Project,
    long FirstTsUs,
    long LastTsUs,
    long Rows,
    long Events,
    long LastSeq);

public sealed record ToolStats(
    string Tool, int Sessions, long FilesRead, long FilesWritten, long Commands, long Denied, long Outside, int Hosts, int FlaggedOpen);

public sealed record OutsideFolder(string Folder, long Records, IReadOnlyList<string> Tools, IReadOnlyList<string> Flags);

/// <summary>
/// <c>Unknown</c>: the newest connection in the range was to a host the tool's registry entry did not
/// list. <c>FlaggedFlows</c>: how many connections in the range were flagged when written.
/// </summary>
public sealed record HostStats(
    string Target, string Category, long Flows, long BytesOut, long BytesIn, bool Unknown, long FlaggedFlows);

public sealed record Overview(
    int Sessions,
    long OutsideRecords,
    int OutsideFolders,
    IReadOnlyDictionary<Severity, int> FlaggedOpen,
    long DeniedByAgent,
    long DeniedByUser,
    long DeniedByOs,
    int HostsTotal,
    int HostsUnknown,
    int NetworkVolume,
    IReadOnlyDictionary<string, long> Sensitive,
    IReadOnlyList<ToolStats> ByTool,
    IReadOnlyList<OutsideFolder> Outside,
    IReadOnlyList<HostStats> Hosts);

/// <summary>A page of results and the seq to continue after, or null at the end.</summary>
public sealed record Page<T>(IReadOnlyList<T> Items, long? Next);

/// <summary>A row as exported (ADR-012 Decision 2): the row and its chain hash in lowercase hex.</summary>
public sealed record ExportRow(EventView Event, string Hash);
