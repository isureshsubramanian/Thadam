using System.Net.Sockets;
using System.Text.Json;

namespace Thadam.Audit;

public sealed class AuditUnavailableException(string message) : Exception(message);

/// <summary>
/// The collector no longer knows the session (it restarted, the password changed, the session
/// went idle or was signed out): the caller must sign in again (ADR-015 Decision 1).
/// </summary>
public sealed class AuditSessionEndedException() : Exception("The audit session has ended");

public enum SignInStatus
{
    SignedIn,
    WrongPassword,
    NoPassword,
    Wait,
}

/// <summary>A sign-in's outcome: the session on success, the wait in seconds when limited.</summary>
public sealed record SignInResult(SignInStatus Status, string? Session = null, int RetryAfter = 0);

/// <summary>
/// The collector's audit socket, contract <c>thadam.audit-append.v2</c> (ADR-015 Decision 1):
/// the collector checks the password, hands out sessions, and appends only with a live one.
/// One bounded request per connection; diagnostics never include request values.
/// </summary>
internal sealed class CollectorWriter(string socketPath, string actor)
{
    private const string Contract = "thadam.audit-append.v2";
    private const int MaxLine = 8192;

    public async Task PingAsync(string? session, CancellationToken ct)
    {
        var reply = await SendAsync(session is null
            ? new { contract = Contract, ping = true }
            : new { contract = Contract, ping = true, session }, ct).ConfigureAwait(false);
        if (!reply.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True)
            throw new AuditUnavailableException("Audit collector reply is malformed");
    }

    public async Task<SignInResult> SignInAsync(string password, CancellationToken ct)
    {
        JsonElement reply;
        try
        {
            reply = await SendAsync(new { contract = Contract, actor, password }, ct).ConfigureAwait(false);
        }
        catch (SignInRefusal refusal)
        {
            return refusal.Result;
        }
        if (!reply.TryGetProperty("session", out var session) || session.ValueKind != JsonValueKind.String
            || session.GetString() is not { Length: 64 } token)
            throw new AuditUnavailableException("Audit collector reply is malformed");
        return new SignInResult(SignInStatus.SignedIn, token);
    }

    public async Task SignOutAsync(string session, CancellationToken ct)
    {
        var reply = await SendAsync(new { contract = Contract, signOut = true, session }, ct).ConfigureAwait(false);
        ReadAppended(reply);
    }

    public async Task<AuditEntry> AppendAsync(
        string session, AuditAction action, string target, AuditOutcome outcome, CancellationToken ct)
    {
        var reply = await SendAsync(new
        {
            contract = Contract,
            session,
            action = AuditLog.WireName(action),
            target,
            outcome = AuditLog.WireName(outcome),
        }, ct).ConfigureAwait(false);
        var (sequence, id, timestamp) = ReadAppended(reply);
        return new AuditEntry(sequence, id, timestamp, actor, AuditLog.WireName(action), target, AuditLog.WireName(outcome));
    }

    private static (long Seq, string Id, long TsUs) ReadAppended(JsonElement reply)
    {
        if (!reply.TryGetProperty("seq", out var seq) || seq.ValueKind != JsonValueKind.Number || !seq.TryGetInt64(out var sequence) || sequence <= 0
            || !reply.TryGetProperty("tsUs", out var ts) || ts.ValueKind != JsonValueKind.Number || !ts.TryGetInt64(out var timestamp) || timestamp <= 0
            || !reply.TryGetProperty("auditId", out var id) || id.ValueKind != JsonValueKind.String
            || !Guid.TryParseExact(id.GetString(), "D", out var guid) || guid.Version != 7)
            throw new AuditUnavailableException("Audit collector reply is malformed");
        return (sequence, id.GetString()!, timestamp);
    }

    /// <summary>A sign-in the collector answered with a refusal that is an outcome, not a fault.</summary>
    private sealed class SignInRefusal(SignInResult result) : Exception
    {
        public SignInResult Result { get; } = result;
    }

    private async Task<JsonElement> SendAsync(object request, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(request);
            if (bytes.Length + 1 > MaxLine) throw new AuditUnavailableException("Audit collector request is too large");
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
                    throw Failure(error.ValueKind == JsonValueKind.String ? error.GetString() : null, reply);
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

    private static Exception Failure(string? error, JsonElement reply) => error switch
    {
        "session_ended" => new AuditSessionEndedException(),
        "wrong_password" => new SignInRefusal(new SignInResult(SignInStatus.WrongPassword)),
        "no_password" => new SignInRefusal(new SignInResult(SignInStatus.NoPassword)),
        "wait" => new SignInRefusal(new SignInResult(SignInStatus.Wait, RetryAfter:
            reply.TryGetProperty("retryAfter", out var r) && r.TryGetInt32(out var seconds) && seconds > 0 ? seconds : 1)),
        "refused" => new AuditUnavailableException("Audit collector refused the sender"),
        "invalid" => new AuditUnavailableException("Audit collector rejected the request"),
        "unavailable" => new AuditUnavailableException("Audit collector cannot write"),
        _ => new AuditUnavailableException("Audit collector returned an error"),
    };
}
