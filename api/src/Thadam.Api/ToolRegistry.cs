using System.Text.Json;

namespace Thadam.Api;

/// <summary>A registry tool as the dashboard shows it.</summary>
public sealed record ToolName(string Key, string DisplayName);

/// <summary>
/// Reads the tool keys and display names from the collector's registry file (ADR-008
/// Decision 10). Only those two fields are read; matching rules stay the collector's. The
/// file is read again when it changes. A missing or unreadable file means no tools, so
/// every <c>tool</c> filter is rejected rather than guessed.
/// </summary>
public sealed class ToolRegistry(ApiOptions options, TimeProvider time)
{
    /// <summary>Same bounds as the collector's registry checks.</summary>
    private const int MaxKey = 64;
    private const int MaxDisplayName = 64;
    private static readonly TimeSpan RecheckEvery = TimeSpan.FromSeconds(10);

    private readonly Lock _lock = new();
    private IReadOnlyList<ToolName> _tools = [];
    private DateTime _stamp = DateTime.MinValue;
    private DateTimeOffset _checked = DateTimeOffset.MinValue;

    public async Task<IReadOnlyList<ToolName>> ToolsAsync(CancellationToken ct)
    {
        var now = time.GetUtcNow();
        lock (_lock)
        {
            if (now - _checked < RecheckEvery)
            {
                return _tools;
            }
        }
        var stamp = File.Exists(options.RegistryPath) ? File.GetLastWriteTimeUtc(options.RegistryPath) : DateTime.MinValue;
        IReadOnlyList<ToolName>? tools = null;
        lock (_lock)
        {
            if (stamp == _stamp)
            {
                _checked = now;
                return _tools;
            }
        }
        tools = await ReadAsync(options.RegistryPath, ct).ConfigureAwait(false);
        lock (_lock)
        {
            _tools = tools;
            _stamp = stamp;
            _checked = now;
            return _tools;
        }
    }

    public async Task<string> DisplayNameAsync(string key, CancellationToken ct) =>
        (await ToolsAsync(ct).ConfigureAwait(false)).FirstOrDefault(t => t.Key == key)?.DisplayName ?? key;

    private static async Task<IReadOnlyList<ToolName>> ReadAsync(string path, CancellationToken ct)
    {
        try
        {
            await using var file = File.OpenRead(path);
            using var doc = await JsonDocument.ParseAsync(file, cancellationToken: ct).ConfigureAwait(false);
            if (!doc.RootElement.TryGetProperty("tools", out var tools) || tools.ValueKind != JsonValueKind.Array)
            {
                return [];
            }
            var list = new List<ToolName>();
            foreach (var t in tools.EnumerateArray())
            {
                if (t.ValueKind != JsonValueKind.Object
                    || !t.TryGetProperty("key", out var k) || k.ValueKind != JsonValueKind.String
                    || k.GetString() is not { Length: > 0 and <= MaxKey } key)
                {
                    continue;
                }
                var name = t.TryGetProperty("display_name", out var d) && d.ValueKind == JsonValueKind.String
                    && d.GetString() is { Length: > 0 and <= MaxDisplayName } n && !n.Any(char.IsControl)
                    ? n
                    : key;
                list.Add(new ToolName(key, name));
            }
            return list;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException)
        {
            return [];
        }
    }
}
