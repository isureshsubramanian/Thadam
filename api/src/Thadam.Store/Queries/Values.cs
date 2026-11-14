using System.Globalization;

namespace Thadam.Store.Queries;

/// <summary>A closed time range in microseconds since the Unix epoch (UTC).</summary>
public readonly record struct TimeRange(long FromUs, long ToUs)
{
    public bool Overlaps(long minUs, long maxUs) => minUs <= ToUs && maxUs >= FromUs;
}

/// <summary>Parsing and printing of the stored list columns and times.</summary>
public static class Values
{
    /// <summary><c>flags</c>: sorted wire names joined by commas (thadam-core <c>wire_set</c>).</summary>
    public static IReadOnlySet<string> Flags(string flags) =>
        string.IsNullOrEmpty(flags)
            ? new HashSet<string>(StringComparer.Ordinal)
            : new HashSet<string>(flags.Split(','), StringComparer.Ordinal);

    /// <summary><c>detections</c>: <c>KIND:n</c> pairs joined by commas. Kinds and counts only.</summary>
    public static IReadOnlyDictionary<string, long> Detections(string detections)
    {
        var d = new SortedDictionary<string, long>(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(detections))
        {
            return d;
        }
        foreach (var pair in detections.Split(','))
        {
            var colon = pair.LastIndexOf(':');
            if (colon > 0 && long.TryParse(pair.AsSpan(colon + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var n))
            {
                var kind = pair[..colon];
                d[kind] = d.GetValueOrDefault(kind) + n;
            }
        }
        return d;
    }

    public static string Time(long us) =>
        DateTimeOffset.UnixEpoch.AddTicks(us * 10).ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);

    public static long Micros(DateTimeOffset t) => (t.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10;

    /// <summary>
    /// The folder an outside-project path is grouped under: its first two folders, with the
    /// home folder shown as <c>~</c>. <c>/Users/dev/.cargo/registry/src/x.rs</c> is
    /// <c>~/.cargo/registry</c>; <c>/etc/hosts</c> is <c>/etc</c>.
    /// </summary>
    public static string OutsideFolder(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        var prefix = "";
        var rest = path;
        if (path.StartsWith("/Users/", StringComparison.Ordinal))
        {
            var slash = path.IndexOf('/', "/Users/".Length);
            if (slash > 0)
            {
                prefix = "~";
                rest = path[slash..];
            }
        }
        var parts = rest.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var folders = parts.Length > 0 ? parts[..^1] : parts;
        return prefix + "/" + string.Join('/', folders.Take(2));
    }
}
