namespace Thadam.Store;

/// <summary>One stored event, every column the chain covers (ADR-002 Decision 3).</summary>
public sealed record EventRow(
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
    string Flags,
    long Count,
    string Detections,
    string Source,
    string? AgentSessionId = null,
    string? Transcript = null);

/// <summary>One catalog entry (ADR-009 Decision 1). Kinds: opened, closed, retired, archived, paused.</summary>
public sealed record CatalogEntry(
    long Seq,
    long AtUs,
    string Kind,
    string? Segment,
    long? FirstSeq,
    long? LastSeq,
    string? FirstPrevHash,
    string? LastHash,
    long? LastTsUs,
    long? Rows,
    long? Bytes,
    string? Reason,
    string? Detail,
    long? FromUs,
    long? ToUs,
    long? Missed);
