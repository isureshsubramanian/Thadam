using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Thadam.Audit;

namespace Thadam.Api.Tests;

/// <summary>Synthetic collector: the local writer supplies the identical schema and hash chain.</summary>
internal sealed class FakeCollector : IAsyncDisposable
{
    private readonly Socket _listener = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _loop;
    private readonly string _db;
    public string? Error { get; set; }
    public bool Available { get; set; } = true;

    public FakeCollector(string socket, string db)
    {
        _db = db;
        _listener.Bind(new UnixDomainSocketEndPoint(socket));
        _listener.Listen(8);
        _loop = RunAsync();
    }

    private async Task RunAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                using var peer = await _listener.AcceptAsync(_stop.Token);
                await using var stream = new NetworkStream(peer, ownsSocket: false);
                using var reader = new StreamReader(stream, leaveOpen: true);
                var line = await reader.ReadLineAsync(_stop.Token);
                using var doc = JsonDocument.Parse(line!);
                var request = doc.RootElement;
                object reply;
                if (Encoding.UTF8.GetByteCount(line!) + 1 > 4096
                    || !request.TryGetProperty("contract", out var contract) || contract.GetString() != "thadam.audit-append.v1")
                    reply = new { error = "invalid" };
                else if (!Available || Error is not null) reply = new { error = Error ?? "unavailable" };
                else if (request.TryGetProperty("ping", out _)) reply = new { ok = true };
                else if (!ValidText(request, "actor", 1, 64, "._@-")
                    || !ValidText(request, "target", 0, 128, "._:-")
                    || !request.TryGetProperty("action", out var actionName) || actionName.ValueKind != JsonValueKind.String
                    || !Enum.GetValues<AuditAction>().Any(a => AuditLog.WireName(a) == actionName.GetString())
                    || !request.TryGetProperty("outcome", out var outcomeName) || outcomeName.ValueKind != JsonValueKind.String
                    || !Enum.GetValues<AuditOutcome>().Any(a => AuditLog.WireName(a) == outcomeName.GetString()))
                    reply = new { error = "invalid" };
                else
                {
                    var action = Enum.GetValues<AuditAction>().Single(a => AuditLog.WireName(a) == request.GetProperty("action").GetString());
                    var outcome = Enum.GetValues<AuditOutcome>().Single(a => AuditLog.WireName(a) == request.GetProperty("outcome").GetString());
                    await using var writer = await AuditLog.OpenAsync(_db, request.GetProperty("actor").GetString()!, TimeProvider.System, _stop.Token);
                    var entry = await writer.AppendAsync(action, request.GetProperty("target").GetString()!, outcome, _stop.Token);
                    reply = new { seq = entry.Seq, auditId = entry.AuditId, tsUs = entry.TsUs };
                }
                await using var output = new StreamWriter(stream, leaveOpen: true);
                await output.WriteLineAsync(JsonSerializer.Serialize(reply));
                await output.FlushAsync(_stop.Token);
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
    }

    private static bool ValidText(JsonElement request, string name, int min, int max, string punctuation)
    {
        if (!request.TryGetProperty(name, out var field) || field.ValueKind != JsonValueKind.String) return false;
        var value = field.GetString()!;
        return value.Length >= min && value.Length <= max
            && value.All(c => char.IsAsciiLetterOrDigit(c) || punctuation.Contains(c, StringComparison.Ordinal));
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        await _loop;
        _listener.Dispose();
        _stop.Dispose();
    }
}
