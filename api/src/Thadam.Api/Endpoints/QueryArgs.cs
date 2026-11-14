using System.Globalization;
using System.Text.RegularExpressions;
using FluentValidation;
using Thadam.Store.Queries;

namespace Thadam.Api.Endpoints;

/// <summary>Query-string arguments, bound as text and checked here (ADR-008 Decision 4).</summary>
public sealed record RangeArgs(string? From, string? To, string? Tool);

public sealed record FlagArgs(string? From, string? To, string? Tool, string? Status, string? Severity, string? After);

public sealed record SessionArgs(string? From, string? To, string? Tool, string? After);

public sealed record TimelineArgs(string? Internal, string? After);

public static partial class Args
{
    /// <summary>The longest range a query may cover (ADR-008 Decision 4).</summary>
    public const int MaxRangeDays = 366;
    /// <summary>The range when none is given: the last week, as the mock-up's default view.</summary>
    public const int DefaultRangeDays = 7;
    /// <summary>Event and session IDs: bounded length, a safe character set (estimate; real IDs are UUIDs).</summary>
    public const int MaxId = 128;

    public static readonly IReadOnlySet<string> Statuses = new HashSet<string>(StringComparer.Ordinal) { "open", "reviewed" };
    public static readonly IReadOnlySet<string> Severities = new HashSet<string>(StringComparer.Ordinal) { "high", "medium", "low" };

    /// <summary>RFC 3339 date-time: a full date, time, optional fraction and an offset or Z.</summary>
    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?(Z|[+-]\d{2}:\d{2})$", RegexOptions.CultureInvariant)]
    private static partial Regex Rfc3339Pattern();

    [GeneratedRegex(@"^[A-Za-z0-9._:-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex IdPattern();

    public static DateTimeOffset? Time(string? s) =>
        s is { Length: <= 40 } && Rfc3339Pattern().IsMatch(s)
        && DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var t)
            ? t
            : null;

    public static bool IsTime(string? s) => s is null || Time(s) is not null;

    public static bool IsAfter(string? s) => s is null || (long.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n > 0);

    public static long? After(string? s) => s is null ? null : long.Parse(s, NumberStyles.None, CultureInfo.InvariantCulture);

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
    }
}

public sealed class SessionArgsValidator : RangeRules<SessionArgs>
{
    public SessionArgsValidator(TimeProvider time, IReadOnlySet<string> tools)
        : base(time, tools, a => a.From, a => a.To, a => a.Tool) =>
        RuleFor(a => a.After).Must(Args.IsAfter);
}

public sealed class TimelineArgsValidator : AbstractValidator<TimelineArgs>
{
    public TimelineArgsValidator()
    {
        RuleFor(a => a.Internal).Must(s => s is null or "true" or "false");
        RuleFor(a => a.After).Must(Args.IsAfter);
    }
}
