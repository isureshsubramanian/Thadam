using System.Net.Sockets;
using System.Text.Json;

namespace Thadam.Audit;

public sealed class AuditUnavailableException(string message) : Exception(message);

/// <summary>One bounded request per connection; diagnostics never include request values.</summary>
internal sealed class CollectorWriter(string socketPath, string actor)
{
    private const string Contract = "thadam.audit-append.v1";

    public async Task PingAsync(CancellationToken ct)
    {
        var reply = await SendAsync(new { contract = Contract, ping = true }, ct).ConfigureAwait(false);
        if (!reply.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True)
            throw new AuditUnavailableException("Audit collector reply is malformed");
    }

    public async Task<AuditEntry> AppendAsync(AuditAction action, string target, AuditOutcome outcome, CancellationToken ct)
    {
        var reply = await SendAsync(new
        {
            contract = Contract,
            actor,
            action = AuditLog.WireName(action),
            target,
            outcome = AuditLog.WireName(outcome),
        }, ct).ConfigureAwait(false);
        if (!reply.TryGetProperty("seq", out var seq) || seq.ValueKind != JsonValueKind.Number || !seq.TryGetInt64(out var sequence) || sequence <= 0
            || !reply.TryGetProperty("tsUs", out var ts) || ts.ValueKind != JsonValueKind.Number || !ts.TryGetInt64(out var timestamp) || timestamp <= 0
            || !reply.TryGetProperty("auditId", out var id) || id.ValueKind != JsonValueKind.String
            || !Guid.TryParseExact(id.GetString(), "D", out var guid) || guid.Version != 7)
            throw new AuditUnavailableException("Audit collector reply is malformed");
        return new AuditEntry(sequence, id.GetString()!, timestamp, actor, AuditLog.WireName(action), target, AuditLog.WireName(outcome));
    }

    private async Task<JsonElement> SendAsync(object request, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(request);
            if (bytes.Length + 1 > 4096) throw new AuditUnavailableException("Audit collector request is too large");
            using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), timeout.Token).ConfigureAwait(false);
            await using var stream = new NetworkStream(socket, ownsSocket: false);
            await stream.WriteAsync(bytes, timeout.Token).ConfigureAwait(false);
            await stream.WriteAsync(new byte[] { 10 }, timeout.Token).ConfigureAwait(false);
            var buffer = new byte[4096];
            var length = 0;
            while (length < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(length, 1), timeout.Token).ConfigureAwait(false);
                if (read == 0) break;
                if (buffer[length++] != 10) continue;
                using var doc = JsonDocument.Parse(buffer.AsMemory(0, length - 1));
                var reply = doc.RootElement;
                if (reply.ValueKind != JsonValueKind.Object) break;
                if (reply.TryGetProperty("error", out var error))
                    throw new AuditUnavailableException(error.ValueKind == JsonValueKind.String ? error.GetString() switch
                    {
                        "refused" => "Audit collector refused the sender",
                        "invalid" => "Audit collector rejected the request",
                        "unavailable" => "Audit collector cannot write",
                        _ => "Audit collector returned an error",
                    } : "Audit collector returned an error");
                return reply.Clone();
            }
            throw new AuditUnavailableException("Audit collector reply is malformed");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new AuditUnavailableException("Audit collector timed out");
        }
        catch (Exception ex) when (ex is SocketException or IOException or JsonException or ArgumentException)
        {
            throw new AuditUnavailableException(ex is JsonException ? "Audit collector reply is malformed" : "Audit collector connection failed");
        }
    }
}
