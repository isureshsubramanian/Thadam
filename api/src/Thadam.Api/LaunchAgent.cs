using System.Diagnostics;
using System.Globalization;
using System.Xml.Linq;
using Thadam.Audit;

namespace Thadam.Api;

/// <summary>
/// The per-user launch agent (ADR-008 Decision 12): starts the API at login and again after a
/// crash, never after a clean stop. It runs the copy of <c>thadam-api</c> that installed it.
/// </summary>
internal static class LaunchAgent
{
    public const string Label = "com.nerttiyana.thadam.api";

    private static string Home => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    public static string PlistPath => Path.Combine(Home, "Library", "LaunchAgents", Label + ".plist");

    /// <summary>Counts and errors only (ApiHost keeps request logs below the written level).</summary>
    public static string LogPath => Path.Combine(Home, "Library", "Logs", "Thadam", "api.log");

    /// <summary>The property list. Values go through the XML writer, so a path is never markup.</summary>
    public static string Plist(string executable, ApiOptions options, string logPath)
    {
        ArgumentNullException.ThrowIfNull(options);
        string[] arguments =
        [
            executable, "run",
            "--store", options.StorePath,
            "--registry", options.RegistryPath,
            "--data-dir", options.DataDir,
            "--port", options.Port.ToString(CultureInfo.InvariantCulture),
        ];
        var dict = new XElement("dict",
            Key("Label"), new XElement("string", Label),
            Key("ProgramArguments"), new XElement("array", arguments.Select(a => new XElement("string", a))),
            Key("RunAtLoad"), new XElement("true"),
            // Restart after a crash; a clean exit (stop, uninstall) stays stopped.
            Key("KeepAlive"), new XElement("dict", Key("SuccessfulExit"), new XElement("false")),
            Key("ThrottleInterval"), new XElement("integer", "10"),
            Key("StandardOutPath"), new XElement("string", logPath),
            Key("StandardErrorPath"), new XElement("string", logPath));
        var doc = new XDocument(
            new XDeclaration("1.0", "UTF-8", null),
            new XDocumentType("plist", "-//Apple//DTD PLIST 1.0//EN", "http://www.apple.com/DTDs/PropertyList-1.0.dtd", null),
            new XElement("plist", new XAttribute("version", "1.0"), dict));
        return doc.Declaration + "\n" + doc + "\n";
    }

    public static async Task<int> InstallAsync(ApiOptions options, CancellationToken ct)
    {
        var exe = Environment.ProcessPath;
        if (exe is null || Path.GetFileName(exe) != "thadam-api")
        {
            Console.Error.WriteLine("Run install from the thadam-api executable itself.");
            return 2;
        }
        if (!File.Exists(options.CredentialsPath))
        {
            Console.Error.WriteLine("Set a password first: thadam-api set-password");
            return 2;
        }
        PrivateFiles.EnsureFolder(Path.GetDirectoryName(LogPath) ?? ".");
        Directory.CreateDirectory(Path.GetDirectoryName(PlistPath) ?? ".");
        // launchd refuses a plist that others can write: 0644, written whole then renamed.
        var tmp = PlistPath + ".tmp";
        await File.WriteAllTextAsync(tmp, Plist(exe, options, LogPath), ct).ConfigureAwait(false);
        File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        File.Move(tmp, PlistPath, overwrite: true);

        var domain = await DomainAsync(ct).ConfigureAwait(false);
        if (domain is null)
        {
            return 2;
        }
        // A reinstall replaces the running agent; "not loaded" is not an error here.
        await LaunchctlAsync(["bootout", $"{domain}/{Label}"], ct).ConfigureAwait(false);
        if (await LaunchctlAsync(["bootstrap", domain, PlistPath], ct).ConfigureAwait(false) != 0)
        {
            Console.Error.WriteLine("launchctl did not load the agent; see the system log.");
            return 2;
        }
        Console.WriteLine($"Installed: the API starts at login. Dashboard: http://127.0.0.1:{options.Port}/");
        return 0;
    }

    public static async Task<int> UninstallAsync(CancellationToken ct)
    {
        var domain = await DomainAsync(ct).ConfigureAwait(false);
        if (domain is null)
        {
            return 2;
        }
        await LaunchctlAsync(["bootout", $"{domain}/{Label}"], ct).ConfigureAwait(false);
        File.Delete(PlistPath);
        Console.WriteLine("Removed the launch agent. The password, audit log, search index and logs are kept.");
        return 0;
    }

    private static XElement Key(string name) => new("key", name);

    /// <summary>The user's GUI launchd domain, <c>gui/&lt;uid&gt;</c>.</summary>
    private static async Task<string?> DomainAsync(CancellationToken ct)
    {
        var (code, output) = await RunAsync("/usr/bin/id", ["-u"], ct).ConfigureAwait(false);
        if (code != 0 || !int.TryParse(output.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var uid))
        {
            Console.Error.WriteLine("Could not read the user id.");
            return null;
        }
        return $"gui/{uid}";
    }

    private static async Task<int> LaunchctlAsync(string[] args, CancellationToken ct) =>
        (await RunAsync("/bin/launchctl", args, ct).ConfigureAwait(false)).Code;

    private static async Task<(int Code, string Output)> RunAsync(string file, string[] args, CancellationToken ct)
    {
        var start = new ProcessStartInfo(file)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in args)
        {
            start.ArgumentList.Add(a);
        }
        using var p = Process.Start(start) ?? throw new InvalidOperationException("process did not start");
        var output = p.StandardOutput.ReadToEndAsync(ct);
        var errors = p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct).ConfigureAwait(false);
        await errors.ConfigureAwait(false);
        return (p.ExitCode, await output.ConfigureAwait(false));
    }
}
