using System.Globalization;
using System.Text.RegularExpressions;
using FluentValidation;
using Thadam.Store.Queries;

namespace Thadam.Api.Endpoints;

/// <summary>Query-string arguments, bound as text and checked here (ADR-008 Decision 4).</summary>
public sealed record RangeArgs(string? From, string? To, string? Tool);

public sealed record FlagArgs(
    string? From, string? To, string? Tool, string? Status, string? Severity, string? After, string? Q, string? Limit);

public sealed record SessionArgs(string? From, string? To, string? Tool, string? After, string? Q, string? Limit);

public sealed record TimelineArgs(string? Internal, string? After, string? Limit);

/// <summary>The flags to mark reviewed or reopen together (ADR-014 Decision 5).</summary>
public sealed record ReviewBatch(IReadOnlyList<string>? EventIds);

public static partial class Args
{
    /// <summary>The longest range a query may cover (ADR-008 Decision 4).</summary>
    public const int MaxRangeDays = 366;
    /// <summary>The range when none is given: the last week, as the mock-up's default view.</summary>
    public const int DefaultRangeDays = 7;
    /// <summary>Event and session IDs: bounded length, a safe character set (estimate; real IDs are UUIDs).</summary>
    public const int MaxId = 128;

    /// <summary>Most flags one bulk review covers: one page (ADR-014 Decision 5).</summary>
    public const int MaxBatch = StoreQueries.DefaultPageSize;
    /// <summary>Longest grid filter text (estimate: well past any path or id a person types).</summary>
    public const int MaxFilter = 200;

    public static readonly IReadOnlySet<string> Statuses = new HashSet<string>(StringComparer.Ordinal) { "open", "reviewed" };
    public static readonly IReadOnlySet<string> Severities = new HashSet<string>(StringComparer.Ordinal) { "high", "medium", "low" };

    [GeneratedRegex(@"^[A-Za-z0-9._:-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex IdPattern();

    public static DateTimeOffset? Time(string? s) => Values.ParseTime(s);

    public static bool IsTime(string? s) => s is null || Time(s) is not null;

    public static bool IsAfter(string? s) => s is null || (long.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n > 0);

    public static long? After(string? s) => s is null ? null : long.Parse(s, NumberStyles.None, CultureInfo.InvariantCulture);

    public static bool IsLimit(string? s) =>
        s is null || (int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n is >= 1 and <= StoreQueries.MaxPageSize);

    /// <summary>The page size; argument already validated.</summary>
    public static int Limit(string? s) => s is null ? StoreQueries.DefaultPageSize : int.Parse(s, NumberStyles.None, CultureInfo.InvariantCulture);

    /// <summary>Grid filter text: bounded, no control characters. Absent or empty means no filter.</summary>
    public static bool IsFilter(string? s) => s is null || (s.Length <= MaxFilter && !s.Any(char.IsControl));

    /// <summary>The filter to apply, or null for none; argument already validated.</summary>
    public static string? Filter(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    /// <summary>Case-insensitive substring match of <paramref name="filter"/> in any of <paramref name="fields"/>.</summary>
    public static bool Matches(string filter, params ReadOnlySpan<string?> fields)
    {
        foreach (var f in fields)
        {
            if (f is not null && f.Contains(filter, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    public static bool IsId(string? s) => s is { Length: > 0 and <= MaxId } && IdPattern().IsMatch(s);

    /// <summary>The range to query; arguments already validated.</summary>
    public static TimeRange Range(string? from, string? to, TimeProvider time)
    {
        var end = Time(to) ?? time.GetUtcNow();
        var start = Time(from) ?? end.AddDays(-DefaultRangeDays);
        return new TimeRange(Values.Micros(start), Values.Micros(end));
    }

    internal static bool RangeFits(string? from, string? to, TimeProvider time)
    {
        if (!IsTime(from) || !IsTime(to))
        {
            return true; // reported on the field itself
        }
        var r = Range(from, to, time);
        return r.FromUs <= r.ToUs && r.ToUs - r.FromUs <= MaxRangeDays * 86_400_000_000L;
    }
}

/// <summary>Range and tool checks shared by the list endpoints.</summary>
public abstract class RangeRules<T> : AbstractValidator<T>
{
    protected RangeRules(
        TimeProvider time, IReadOnlySet<string> tools,
        Func<T, string?> from, Func<T, string?> to, Func<T, string?> tool)
    {
        RuleFor(a => from(a)).Must(Args.IsTime).OverridePropertyName("from");
        RuleFor(a => to(a)).Must(Args.IsTime).OverridePropertyName("to");
        RuleFor(a => a).Must(a => Args.RangeFits(from(a), to(a), time)).OverridePropertyName("range");
        RuleFor(a => tool(a)).Must(t => t is null || tools.Contains(t)).OverridePropertyName("tool");
    }
}

public sealed class RangeArgsValidator(TimeProvider time, IReadOnlySet<string> tools)
    : RangeRules<RangeArgs>(time, tools, a => a.From, a => a.To, a => a.Tool);

public sealed class FlagArgsValidator : RangeRules<FlagArgs>
{
    public FlagArgsValidator(TimeProvider time, IReadOnlySet<string> tools)
        : base(time, tools, a => a.From, a => a.To, a => a.Tool)
    {
        RuleFor(a => a.Status).Must(s => s is null || Args.Statuses.Contains(s));
        RuleFor(a => a.Severity).Must(s => s is null || Args.Severities.Contains(s));
        RuleFor(a => a.After).Must(Args.IsAfter);
        RuleFor(a => a.Q).Must(Args.IsFilter);
        RuleFor(a => a.Limit).Must(Args.IsLimit);
    }
}

public sealed class SessionArgsValidator : RangeRules<SessionArgs>
{
    public SessionArgsValidator(TimeProvider time, IReadOnlySet<string> tools)
        : base(time, tools, a => a.From, a => a.To, a => a.Tool)
    {
        RuleFor(a => a.After).Must(Args.IsAfter);
        RuleFor(a => a.Q).Must(Args.IsFilter);
        RuleFor(a => a.Limit).Must(Args.IsLimit);
    }
}

public sealed class TimelineArgsValidator : AbstractValidator<TimelineArgs>
{
    public TimelineArgsValidator()
    {
        RuleFor(a => a.Internal).Must(s => s is null or "true" or "false");
        RuleFor(a => a.After).Must(Args.IsAfter);
        RuleFor(a => a.Limit).Must(Args.IsLimit);
    }
}

public sealed class ReviewBatchValidator : AbstractValidator<ReviewBatch>
{
    public ReviewBatchValidator() =>
        RuleFor(b => b.EventIds).NotNull()
            .Must(ids => ids is { Count: >= 1 and <= Args.MaxBatch }
                && ids.All(Args.IsId)
                && ids.Distinct(StringComparer.Ordinal).Count() == ids.Count);
}
