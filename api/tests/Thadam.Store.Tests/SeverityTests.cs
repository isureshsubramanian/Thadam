using Thadam.Store.Queries;

namespace Thadam.Store.Tests;

public sealed class SeverityTests
{
    [Theory]
    [InlineData("launch_outside", "allowed", "exec", Severity.High, "launch_outside")]
    [InlineData("launch_outside,outside_project", "allowed", "create", Severity.High, "launch_outside")]
    [InlineData("launch_outside", "denied_by_user", "exec", Severity.High, "launch_outside")]
    [InlineData("sensitive_path,launch_outside", "allowed", "write", Severity.High, "sensitive_path")]
    public void AHandOffOutsideTheTreeIsHigh(string flags, string outcome, string action, Severity severity, string rule)
    {
        var set = flags.Split(',').ToHashSet(StringComparer.Ordinal);
        Assert.Equal((severity, rule), SeverityRule.Classify(set, outcome, action, ""));
    }

    [Theory]
    [InlineData("tool_config_change", "allowed", "write", Severity.Medium, "tool_config_change")]
    [InlineData("tool_config_change,outside_project", "allowed", "create", Severity.Medium, "tool_config_change")]
    [InlineData("tool_config_change", "denied_by_os", "write", Severity.Medium, "tool_config_change")]
    [InlineData("tool_config_change", "denied_by_user", "write", Severity.Medium, "denied")]
    [InlineData("tool_config_change,sensitive_path", "allowed", "write", Severity.High, "sensitive_path")]
    public void AChangeToTheToolsConfigurationIsMedium(string flags, string outcome, string action, Severity severity, string rule)
    {
        var set = flags.Split(',').ToHashSet(StringComparer.Ordinal);
        Assert.Equal((severity, rule), SeverityRule.Classify(set, outcome, action, ""));
    }
}
