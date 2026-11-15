using System.Diagnostics;
using System.Xml.Linq;

namespace Thadam.Api.Tests;

/// <summary>The launch agent's property list (ADR-008 Decision 12). launchctl itself is not run here.</summary>
public sealed class LaunchAgentTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly ApiOptions Options =
        new("/synthetic/store & <x>", "/synthetic/registry.json", "/synthetic/data", 7400);

    private static XElement Dict(string plist) =>
        XDocument.Parse(plist).Root?.Element("dict") ?? throw new InvalidOperationException("no dict");

    private static XElement? ValueOf(XElement dict, string key) =>
        dict.Elements("key").FirstOrDefault(k => k.Value == key)?.ElementsAfterSelf().First();

    [Fact]
    public void CollectorOptionsUseSystemDatabaseAndValidatePaths()
    {
        var (options, error) = ApiOptions.Parse(["--audit-socket", "/var/run/thadam-audit/audit.sock"]);
        Assert.Null(error);
        Assert.NotNull(options);
        Assert.Equal("/Library/Application Support/Thadam/audit/audit.db", options.AuditPath);
        Assert.NotNull(ApiOptions.Parse(["--audit-socket", "relative"]).Error);
        Assert.NotNull(ApiOptions.Parse(["--audit-db", "relative"]).Error);
        var local = ApiOptions.Defaults();
        Assert.Equal(Path.Combine(local.DataDir, "audit.db"), local.AuditPath);
    }

    [Fact]
    public void CollectorArgumentsAreEscapedAndPreserved()
    {
        var options = Options with { AuditSocket = "/synthetic/a & <b>.sock", AuditDb = "/synthetic/audit.db" };
        var dict = Dict(LaunchAgent.Plist("/synthetic/bin/thadam-api", options, "/synthetic/api.log"));
        var args = ValueOf(dict, "ProgramArguments")!.Elements("string").Select(e => e.Value).ToArray();
        Assert.Equal(["--audit-socket", options.AuditSocket, "--audit-db", options.AuditDb], args[^4..]);
    }

    [Fact]
    public void TheAgentRunsTheInstallingExecutableWithItsOptions()
    {
        var dict = Dict(LaunchAgent.Plist("/synthetic/bin/thadam-api", Options, "/synthetic/api.log"));
        Assert.Equal(LaunchAgent.Label, ValueOf(dict, "Label")?.Value);
        var args = ValueOf(dict, "ProgramArguments")?.Elements("string").Select(e => e.Value).ToArray() ?? [];
        Assert.Equal(
            ["/synthetic/bin/thadam-api", "run", "--store", "/synthetic/store & <x>", "--registry",
                "/synthetic/registry.json", "--data-dir", "/synthetic/data", "--port", "7400"],
            args);
        Assert.Equal("/synthetic/api.log", ValueOf(dict, "StandardOutPath")?.Value);
        Assert.Equal("/synthetic/api.log", ValueOf(dict, "StandardErrorPath")?.Value);
    }

    [Fact]
    public void ItStartsAtLoginAndRestartsOnlyAfterACrash()
    {
        var dict = Dict(LaunchAgent.Plist("/synthetic/bin/thadam-api", Options, "/synthetic/api.log"));
        Assert.Equal("true", ValueOf(dict, "RunAtLoad")?.Name.LocalName);
        var keepAlive = ValueOf(dict, "KeepAlive");
        Assert.NotNull(keepAlive);
        Assert.Equal("false", ValueOf(keepAlive, "SuccessfulExit")?.Name.LocalName);
    }

    [Fact]
    public async Task ThePropertyListIsValidForTheSystemParser()
    {
        if (!File.Exists("/usr/bin/plutil"))
        {
            return; // not macOS
        }
        var dir = Directory.CreateTempSubdirectory("thadam-plist-");
        try
        {
            var path = Path.Combine(dir.FullName, "agent.plist");
            await File.WriteAllTextAsync(path, LaunchAgent.Plist("/synthetic/bin/thadam-api", Options, "/synthetic/api.log"), Ct);
            var start = new ProcessStartInfo("/usr/bin/plutil") { RedirectStandardOutput = true, UseShellExecute = false };
            start.ArgumentList.Add("-lint");
            start.ArgumentList.Add(path);
            using var p = Process.Start(start) ?? throw new InvalidOperationException("plutil did not start");
            await p.StandardOutput.ReadToEndAsync(Ct);
            await p.WaitForExitAsync(Ct);
            Assert.Equal(0, p.ExitCode);
        }
        finally
        {
            dir.Delete(recursive: true);
        }
    }
}
