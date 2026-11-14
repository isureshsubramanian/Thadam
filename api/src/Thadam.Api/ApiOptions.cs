namespace Thadam.Api;

/// <summary>Where the API reads and writes, and its port (ADR-008 Decisions 3, 5, 6; ADR-009 Decision 6).</summary>
public sealed record ApiOptions(string StorePath, string RegistryPath, string DataDir, int Port)
{
    public const int DefaultPort = 7341;
    public const string SystemFolder = "/Library/Application Support/Thadam";

    public string AuditPath => Path.Combine(DataDir, "audit.db");

    public string CredentialsPath => Path.Combine(DataDir, "credentials.json");

    public string KeysPath => Path.Combine(DataDir, "keys");

    public string SearchPath => Path.Combine(DataDir, "search.db");

    /// <summary>The defaults: the root-owned store and registry, the user's own API folder.</summary>
    public static ApiOptions Defaults() => new(
        Path.Combine(SystemFolder, "store"),
        Path.Combine(SystemFolder, "registry.json"),
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Library", "Application Support", "Thadam", "api"),
        DefaultPort);

    /// <summary>
    /// Applies <c>--store</c>, <c>--registry</c>, <c>--data-dir</c> and <c>--port</c>.
    /// Returns null with a reason naming the flag (never its value) when an argument is bad.
    /// </summary>
    public static (ApiOptions? Options, string? Error) Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var o = Defaults();
        for (var i = 0; i < args.Count; i += 2)
        {
            if (i + 1 >= args.Count)
            {
                return (null, $"{args[i]} needs a value");
            }
            var value = args[i + 1];
            switch (args[i])
            {
                case "--store" when Path.IsPathFullyQualified(value):
                    o = o with { StorePath = value };
                    break;
                case "--registry" when Path.IsPathFullyQualified(value):
                    o = o with { RegistryPath = value };
                    break;
                case "--data-dir" when Path.IsPathFullyQualified(value):
                    o = o with { DataDir = value };
                    break;
                case "--port" when int.TryParse(value, out var port) && port is 0 or (>= 1024 and <= 65535):
                    o = o with { Port = port };
                    break;
                case "--store" or "--registry" or "--data-dir":
                    return (null, $"{args[i]} must be an absolute path");
                case "--port":
                    return (null, "--port must be 1024 to 65535");
                default:
                    return (null, "unknown option");
            }
        }
        return (o, null);
    }
}
