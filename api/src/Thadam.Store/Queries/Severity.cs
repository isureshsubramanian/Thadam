namespace Thadam.Store.Queries;

public enum Severity
{
    Low = 1,
    Medium = 2,
    High = 3,
}

/// <summary>
/// The flagged-queue rule (ADR-008 Decision 7, as revised and approved). Derived here, never
/// stored, so it can change without touching the chain. A row takes the highest severity it
/// qualifies for; <c>rolled_up</c>, <c>unconfirmed</c>, <c>continued</c> and
/// <c>tool_internal</c> never put a row in the queue on their own.
/// </summary>
public static class SeverityRule
{
    private static readonly HashSet<string> Changes = new(StringComparer.Ordinal) { "write", "create", "rename", "delete" };

    /// <summary>The severity and rule name, or null when the row is not flagged.</summary>
    public static (Severity Severity, string Rule)? Classify(
        IReadOnlySet<string> flags, string outcome, string action, string detections)
    {
        ArgumentNullException.ThrowIfNull(flags);
        if (flags.Contains("secret_pattern") || !string.IsNullOrEmpty(detections))
        {
            return (Severity.High, "secret");
        }
        if (flags.Contains("sensitive_path"))
        {
            return (Severity.High, "sensitive_path");
        }
        var unknownHost = flags.Contains("unknown_host");
        var largeUpload = flags.Contains("large_upload");
        if (largeUpload && unknownHost)
        {
            return (Severity.High, "large_upload_unknown_host");
        }
        if (outcome is "denied_by_user" or "denied_by_agent")
        {
            return (Severity.Medium, "denied");
        }
        var outside = flags.Contains("outside_project");
        if (outside && Changes.Contains(action))
        {
            return (Severity.Medium, "outside_change");
        }
        if (unknownHost)
        {
            return (Severity.Medium, "unknown_host");
        }
        if (largeUpload)
        {
            return (Severity.Medium, "large_upload");
        }
        if (outside)
        {
            return (Severity.Low, "outside_read");
        }
        if (outcome == "denied_by_os")
        {
            return (Severity.Low, "denied_by_os");
        }
        return null;
    }

    public static string WireName(Severity s) => s switch
    {
        Severity.High => "high",
        Severity.Medium => "medium",
        _ => "low",
    };
}
