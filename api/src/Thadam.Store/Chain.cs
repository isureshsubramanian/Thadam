namespace Thadam.Store;

/// <summary>Hash-chain primitives shared by the event and catalog chains.</summary>
public static class Chain
{
    public const string EventDomain = "thadam.event.v2";
    public const string CatalogDomain = "thadam.catalog.v1";

    /// <summary>The <c>prev_hash</c> of the first row of a chain.</summary>
    public static ReadOnlyMemory<byte> Genesis { get; } = new byte[32];

    /// <summary>Hash of an event row, chained to <paramref name="prevHash"/>.</summary>
    public static byte[] EventHash(ReadOnlySpan<byte> prevHash, EventRow row)
    {
        ArgumentNullException.ThrowIfNull(row);
        return new Wire()
            .Text(EventDomain)
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
            .Text(row.Source)
            .Hash(prevHash);
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
