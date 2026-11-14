namespace Thadam.Store;

/// <summary>Hash-chain primitives shared by the event and catalog chains.</summary>
public static class Chain
{
    /// <summary>Encoding of rows in version 2 segments (ADR-004).</summary>
    public const string EventDomain = "thadam.event.v2";
    /// <summary>Encoding of rows in version 3 segments: v2 plus agent_session_id and transcript (ADR-011).</summary>
    public const string EventDomainV3 = "thadam.event.v3";
    public const string CatalogDomain = "thadam.catalog.v1";

    /// <summary>The <c>prev_hash</c> of the first row of a chain.</summary>
    public static ReadOnlyMemory<byte> Genesis { get; } = new byte[32];

    /// <summary>
    /// Hash of an event row, chained to <paramref name="prevHash"/>, in the encoding of its segment's
    /// schema <paramref name="version"/> (2 or 3). CONTRACT: the same bytes as <c>encode</c> in
    /// <c>crates/thadam-core/src/encode.rs</c>.
    /// </summary>
    public static byte[] EventHash(ReadOnlySpan<byte> prevHash, EventRow row, int version)
    {
        ArgumentNullException.ThrowIfNull(row);
        if (version is not (2 or 3))
        {
            throw new ArgumentOutOfRangeException(nameof(version));
        }
        if (version == 2 && (row.AgentSessionId is not null || row.Transcript is not null))
        {
            throw new ArgumentException("v2 events cannot contain agent fields", nameof(row));
        }
        var wire = new Wire()
            .Text(version == 2 ? EventDomain : EventDomainV3)
            .Int(row.Seq)
            .Text(row.EventId)
            .Int(row.TsUs)
            .Text(row.Tool)
            .Text(row.SessionId, nullable: true)
            .Text(row.ParentSessionId, nullable: true)
            .Int(row.Pid)
            .Text(row.ProcessPath)
            .Text(row.Category)
            .Text(row.Action)
            .Text(row.Target)
            .Text(row.Outcome)
            .Int(row.SizeBytes)
            .Int(row.BytesOut)
            .Int(row.BytesIn)
            .Text(row.Project, nullable: true)
            .Text(row.Flags)
            .Int(row.Count)
            .Text(row.Detections)
            .Text(row.Source);
        if (version == 3)
        {
            wire.Text(row.AgentSessionId, nullable: true).Text(row.Transcript, nullable: true);
        }
        return wire.Hash(prevHash);
    }

    /// <summary>Hash of a catalog entry, chained to <paramref name="prevHash"/>.</summary>
    public static byte[] CatalogHash(ReadOnlySpan<byte> prevHash, CatalogEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return new Wire()
            .Text(CatalogDomain)
            .Int(entry.Seq)
            .Int(entry.AtUs)
            .Text(entry.Kind)
            .Text(entry.Segment, nullable: true)
            .Int(entry.FirstSeq)
            .Int(entry.LastSeq)
            .Text(entry.FirstPrevHash, nullable: true)
            .Text(entry.LastHash, nullable: true)
            .Int(entry.LastTsUs)
            .Int(entry.Rows)
            .Int(entry.Bytes)
            .Text(entry.Reason, nullable: true)
            .Text(entry.Detail, nullable: true)
            .Int(entry.FromUs)
            .Int(entry.ToUs)
            .Int(entry.Missed)
            .Hash(prevHash);
    }

    public static string ToHex(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);

    /// <summary>32 bytes from 64 hex digits, or null.</summary>
    public static byte[]? FromHex(string? hex)
    {
        if (hex is not { Length: 64 })
        {
            return null;
        }
        try
        {
            return Convert.FromHexString(hex);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
