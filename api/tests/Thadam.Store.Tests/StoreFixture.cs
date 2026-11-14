using System.Diagnostics;

namespace Thadam.Store.Tests;

/// <summary>
/// A synthetic store folder written by the real Rust store code
/// (<c>crates/thadam-store/examples/fixture.rs</c>), once per test run. Tests that change
/// files work on a copy (<see cref="Copy"/>).
/// </summary>
public sealed class StoreFixture : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"thadam-api-fixture-{Environment.ProcessId}");

    public StoreFixture()
    {
        RepoRoot = FindRepoRoot();
        Directory.CreateDirectory(_root);
        Folder = System.IO.Path.Combine(_root, "store");
        var psi = new ProcessStartInfo("cargo", ["run", "-q", "-p", "thadam-store", "--example", "fixture", "--", Folder])
        {
            WorkingDirectory = RepoRoot,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("cannot start cargo");
        var err = p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0)
        {
            throw new InvalidOperationException($"fixture failed: {err}");
        }
    }

    public string RepoRoot { get; }

    public string Folder { get; }

    /// <summary>A private copy of the fixture folder, deleted with the fixture.</summary>
    public string Copy(string name)
    {
        var dest = System.IO.Path.Combine(_root, name);
        if (Directory.Exists(dest))
        {
            Directory.Delete(dest, recursive: true);
        }
        Directory.CreateDirectory(dest);
        foreach (var f in Directory.GetFiles(Folder))
        {
            File.Copy(f, System.IO.Path.Combine(dest, System.IO.Path.GetFileName(f)));
        }
        return dest;
    }

    public void Dispose()
    {
        foreach (var d in Directory.GetDirectories(_root))
        {
            File.SetUnixFileMode(d, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        Directory.Delete(_root, recursive: true);
    }

    private static string FindRepoRoot()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
        {
            if (File.Exists(System.IO.Path.Combine(d.FullName, "Cargo.toml"))
                && Directory.Exists(System.IO.Path.Combine(d.FullName, "api")))
            {
                return d.FullName;
            }
        }
        throw new InvalidOperationException("repository root not found");
    }
}

[CollectionDefinition(Name)]
public sealed class StoreFixtureDefinition : ICollectionFixture<StoreFixture>
{
    public const string Name = "store";
}
