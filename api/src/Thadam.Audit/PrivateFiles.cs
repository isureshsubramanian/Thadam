namespace Thadam.Audit;

/// <summary>Files only the user may read: folder 0700, file 0600 (ADR-008 Decisions 2, 5, 6).</summary>
public static class PrivateFiles
{
    private const UnixFileMode FolderMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode PrivateFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    /// <summary>Creates the parent folder (0700) and an empty file (0600) if missing.</summary>
    public static void EnsureFile(string path)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path)) ?? throw new ArgumentException("no folder", nameof(path));
        EnsureFolder(dir);
        if (!File.Exists(path))
        {
            using var _ = new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                UnixCreateMode = PrivateFileMode,
            });
        }
        File.SetUnixFileMode(path, PrivateFileMode);
    }

    public static void EnsureFolder(string dir)
    {
        Directory.CreateDirectory(dir, FolderMode);
        File.SetUnixFileMode(dir, FolderMode);
    }

    /// <summary>Writes a whole file atomically with mode 0600 (temporary file, then rename).</summary>
    public static async Task WriteAllTextAsync(string path, string text, CancellationToken ct)
    {
        EnsureFolder(Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".");
        var tmp = path + ".tmp";
        await using (var fs = new FileStream(tmp, new FileStreamOptions
        {
            Mode = FileMode.Create,
            Access = FileAccess.Write,
            UnixCreateMode = PrivateFileMode,
        }))
        await using (var w = new StreamWriter(fs))
        {
            await w.WriteAsync(text.AsMemory(), ct).ConfigureAwait(false);
        }
        File.SetUnixFileMode(tmp, PrivateFileMode);
        File.Move(tmp, path, overwrite: true);
    }
}
