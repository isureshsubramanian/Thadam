using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Thadam.Store.Queries;

namespace Thadam.Store.Search;

/// <summary>
/// A parsed search (ADR-008 Decision 5). Values are kept as data: the runner binds them as
/// parameters and quotes them as FTS5 phrases, never splices them into SQL text.
/// </summary>
public sealed record SearchQuery
{
    /// <summary>Free-text terms; each must occur in <c>target</c> or <c>process_path</c>.</summary>
    public IReadOnlyList<string> Text { get; init; } = [];
    public string? Tool { get; init; }
    public string? Session { get; init; }
    public string? Project { get; init; }
    /// <summary><c>outside:&lt;project&gt;</c>: rows flagged outside that project.</summary>
    public string? Outside { get; init; }
    public string? Category { get; init; }
    public string? Action { get; init; }
    public IReadOnlyList<string> Outcomes { get; init; } = [];
    public IReadOnlyList<string> Flags { get; init; } = [];
    public string? Host { get; init; }
    /// <summary>Null when the search covers every kept row.</summary>
    public TimeRange? Range { get; init; }

    /// <summary>Terms long enough for the trigram index; shorter ones are matched by a scan.</summary>
    public IEnumerable<string> IndexedText => Text.Where(t => t.Length >= SearchParser.MinIndexedLength);

    public IEnumerable<string> ScannedText => Text.Where(t => t.Length < SearchParser.MinIndexedLength);
}

/// <summary>A parse failure: the field it concerns (from a fixed set), never the value.</summary>
public sealed record SearchError(string Field);

/// <summary>
/// Parses the mock-up's syntax: free words or <c>"quoted phrases"</c>, and
/// <c>field:value</c> or <c>field:"quoted value"</c>. Unknown fields, repeated fields and bad
/// values are errors, not ignored.
/// </summary>
public static partial class SearchParser
{
    public const int MaxLength = 512;
    /// <summary>Trigram index: a term needs at least three characters to use it.</summary>
    public const int MinIndexedLength = 3;
    /// <summary>Most terms in one search (estimate; the mock-up's saved queries use three).</summary>
    public const int MaxTerms = 16;
    /// <summary>A search with no time field and nothing for the index scans this far back.</summary>
    public const int DefaultScanDays = 7;
    public const int MaxRangeDays = 366;
    private const int MaxValue = 1024;
    private const int MaxId = 128;

    public static readonly IReadOnlySet<string> Fields = Set(
        "tool", "session", "project", "outside", "category", "action", "outcome", "flag", "host", "since", "from", "to");
    public static readonly IReadOnlySet<string> Categories = Set(
        "file", "command", "prompt", "network_internal", "network_external", "network_volume");
    public static readonly IReadOnlySet<string> Actions = Set(
        "read", "create", "write", "rename", "delete", "exec", "connect", "prompt");
    public static readonly IReadOnlySet<string> Outcomes = Set(
        "allowed", "denied_by_agent", "denied_by_user", "denied_by_os", "never_ran", "failed");
    public static readonly IReadOnlySet<string> FlagNames = Set(
        "outside_project", "sensitive_path", "secret_pattern", "unknown_host", "large_upload", "tool_internal", "internal",
        "rolled_up", "unconfirmed", "continued");
    private static readonly string[] Denied = ["denied_by_agent", "denied_by_user", "denied_by_os", "never_ran"];

    [GeneratedRegex(@"^(\d{1,4})([dh])$", RegexOptions.CultureInvariant)]
    private static partial Regex SincePattern();

    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}$", RegexOptions.CultureInvariant)]
    private static partial Regex DatePattern();

    [GeneratedRegex(@"^[A-Za-z0-9._:-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex IdPattern();

    /// <summary>
    /// Parses <paramref name="q"/>. <paramref name="resolveTool"/> maps a tool key or display
    /// name to its registry key, or null when there is no such tool.
    /// </summary>
    public static (SearchQuery? Query, SearchError? Error) Parse(
        string? q, Func<string, string?> resolveTool, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(resolveTool);
        if (string.IsNullOrWhiteSpace(q) || q.Length > MaxLength)
        {
            return Fail("q");
        }
        var terms = Tokenize(q);
        if (terms is null || terms.Count == 0 || terms.Count > MaxTerms)
        {
            return Fail("q");
        }

        var query = new SearchQuery();
        var text = new List<string>();
        var flags = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string? since = null, from = null, to = null;
        foreach (var (field, value) in terms)
        {
            if (field is null)
            {
                text.Add(value);
                continue;
            }
            if (!Fields.Contains(field))
            {
                return Fail("q.unknown");
            }
            // flag: may repeat (all must hold); every other field once.
            if (field != "flag" && !seen.Add(field))
            {
                return Fail($"q.{field}");
            }
            if (value.Length == 0 || value.Length > MaxValue)
            {
                return Fail($"q.{field}");
            }
            var word = value.ToLowerInvariant().Replace('-', '_');
            switch (field)
            {
                case "tool":
                    if (resolveTool(value) is not { } key)
                    {
                        return Fail("q.tool");
                    }
                    query = query with { Tool = key };
                    break;
                case "session" when value.Length <= MaxId && IdPattern().IsMatch(value):
                    query = query with { Session = value };
                    break;
                case "project":
                    query = query with { Project = value };
                    break;
                case "outside":
                    query = query with { Outside = value };
                    break;
                case "category" when Categories.Contains(word):
                    query = query with { Category = word };
                    break;
                case "action" when Actions.Contains(word):
                    query = query with { Action = word };
                    break;
                case "outcome" when word == "denied":
                    query = query with { Outcomes = Denied };
                    break;
                case "outcome" when Outcomes.Contains(word):
                    query = query with { Outcomes = [word] };
                    break;
                case "flag" when FlagNames.Contains(word):
                    flags.Add(word);
                    break;
                case "host" when value.Length <= 255:
                    query = query with { Host = value };
                    break;
                case "since":
                    since = value;
                    break;
                case "from":
                    from = value;
                    break;
                case "to":
                    to = value;
                    break;
                default:
                    return Fail($"q.{field}");
            }
        }
        if (query.Project is not null && query.Outside is not null)
        {
            return Fail("q.outside");
        }
        var (range, rangeError) = Range(since, from, to, now);
        if (rangeError is not null)
        {
            return Fail(rangeError);
        }
        query = query with { Text = text, Flags = flags.Distinct(StringComparer.Ordinal).ToList(), Range = range };
        if (query.Range is null && !query.IndexedText.Any())
        {
            // Nothing the index can answer: bound the scan (ADR-008 Decision 5).
            query = query with
            {
                Range = new TimeRange(Values.Micros(now.AddDays(-DefaultScanDays)), Values.Micros(now)),
            };
        }
        return (query, null);
    }

    /// <summary>The terms as (field or null, value). Null when a quote is not closed.</summary>
    private static List<(string? Field, string Value)>? Tokenize(string q)
    {
        var terms = new List<(string?, string)>();
        var i = 0;
        while (i < q.Length)
        {
            if (char.IsWhiteSpace(q[i]))
            {
                i++;
                continue;
            }
            string? field = null;
            var start = i;
            while (i < q.Length && char.IsAsciiLetter(q[i]))
            {
                i++;
            }
            if (i > start && i < q.Length && q[i] == ':')
            {
                field = q[start..i].ToLowerInvariant();
                i++;
            }
            else
            {
                i = start;
            }
            string value;
            if (i < q.Length && q[i] == '"')
            {
                var end = q.IndexOf('"', i + 1);
                if (end < 0)
                {
                    return null;
                }
                value = q[(i + 1)..end];
                i = end + 1;
            }
            else
            {
                var vstart = i;
                while (i < q.Length && !char.IsWhiteSpace(q[i]))
                {
                    i++;
                }
                value = q[vstart..i];
            }
            if (field is null && value.Length == 0)
            {
                continue; // an empty pair of quotes
            }
            terms.Add((field, value));
        }
        return terms;
    }

    private static (TimeRange? Range, string? Error) Range(string? since, string? from, string? to, DateTimeOffset now)
    {
        if (since is not null)
        {
            if (from is not null || to is not null)
            {
                return (null, "q.since");
            }
            var m = SincePattern().Match(since);
            if (!m.Success)
            {
                return (null, "q.since");
            }
            var n = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
            var span = m.Groups[2].Value == "d" ? TimeSpan.FromDays(n) : TimeSpan.FromHours(n);
            if (n == 0 || span > TimeSpan.FromDays(MaxRangeDays))
            {
                return (null, "q.since");
            }
            return (new TimeRange(Values.Micros(now - span), Values.Micros(now)), null);
        }
        if (from is null && to is null)
        {
            return (null, null);
        }
        long? f = null, t = null;
        if (from is not null)
        {
            if (Time(from, endOfDay: false) is not { } v)
            {
                return (null, "q.from");
            }
            f = v;
        }
        if (to is not null)
        {
            if (Time(to, endOfDay: true) is not { } v)
            {
                return (null, "q.to");
            }
            t = v;
        }
        var end = t ?? Values.Micros(now);
        var startUs = f ?? 0;
        if (startUs > end || (f is not null && end - startUs > MaxRangeDays * 86_400_000_000L))
        {
            return (null, "q.range");
        }
        return (new TimeRange(startUs, end), null);
    }

    /// <summary>RFC 3339, or a plain UTC date (<c>to:</c> a date means the end of that day).</summary>
    private static long? Time(string s, bool endOfDay)
    {
        if (Values.ParseTime(s) is { } t)
        {
            return Values.Micros(t);
        }
        if (DatePattern().IsMatch(s)
            && DateTimeOffset.TryParseExact(s, "yyyy-MM-dd", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d))
        {
            return Values.Micros(endOfDay ? d.AddDays(1) : d) - (endOfDay ? 1 : 0);
        }
        return null;
    }

    /// <summary>An FTS5 query matching every term as a phrase: user text never acts as an operator.</summary>
    public static string FtsQuery(IEnumerable<string> terms)
    {
        ArgumentNullException.ThrowIfNull(terms);
        var sb = new StringBuilder();
        foreach (var t in terms)
        {
            if (sb.Length > 0)
            {
                sb.Append(" AND ");
            }
            sb.Append('"').Append(t.Replace("\"", "\"\"", StringComparison.Ordinal)).Append('"');
        }
        return sb.ToString();
    }

    /// <summary>A LIKE pattern for a substring, with <c>\</c> as the escape character.</summary>
    public static string LikeContains(string s) => "%" + LikeEscape(s) + "%";

    public static string LikeEscape(string s)
    {
        ArgumentNullException.ThrowIfNull(s);
        return s.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("%", "\\%", StringComparison.Ordinal)
            .Replace("_", "\\_", StringComparison.Ordinal);
    }

    private static (SearchQuery?, SearchError?) Fail(string field) => (null, new SearchError(field));

    private static HashSet<string> Set(params string[] items) => new(items, StringComparer.Ordinal);
}
