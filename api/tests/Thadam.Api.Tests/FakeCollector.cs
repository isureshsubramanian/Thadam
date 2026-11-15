using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Thadam.Audit;

namespace Thadam.Api.Tests;

/// <summary>
/// Synthetic collector speaking <c>thadam.audit-append.v2</c>: it checks the password, hands
/// out sessions and writes each append as its session's actor. The local writer supplies the
/// identical schema and hash chain.
/// </summary>
internal sealed class FakeCollector : IAsyncDisposable
{
    private const string Contract = "thadam.audit-append.v2";
    private readonly Socket _listener = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _loop;
    private readonly string _db;
    private readonly ConcurrentDictionary<string, string> _sessions = new(StringComparer.Ordinal);
    public string? Error { get; set; }
    public bool Available { get; set; } = true;
    /// <summary>The password it accepts; null as if none had been set.</summary>
    public string? Password { get; set; } = ApiTestHost.Password;
    /// <summary>When set, a sign-in is told to wait this many seconds.</summary>
    public int? Wait { get; set; }

    public FakeCollector(string socket, string db)
    {
        _db = db;
        _listener.Bind(new UnixDomainSocketEndPoint(socket));
        _listener.Listen(8);
        _loop = RunAsync();
    }

    /// <summary>As a collector restart or a new password does.</summary>
    public void EndSessions() => _sessions.Clear();

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
                var reply = await AnswerAsync(line!, doc.RootElement);
                await using var output = new StreamWriter(stream, leaveOpen: true);
                await output.WriteLineAsync(JsonSerializer.Serialize(reply));
                await output.FlushAsync(_stop.Token);
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
    }

    private async Task<object> AnswerAsync(string line, JsonElement request)
    {
        if (Encoding.UTF8.GetByteCount(line) + 1 > 8192
            || !request.TryGetProperty("contract", out var contract) || contract.GetString() != Contract)
            return new { error = "invalid" };
        if (!Available || Error is not null) return new { error = Error ?? "unavailable" };
        var session = request.TryGetProperty("session", out var s) ? s.GetString() : null;
        if (request.TryGetProperty("ping", out _))
            return session is null || _sessions.ContainsKey(session) ? new { ok = true } : new { error = "session_ended" };
        if (request.TryGetProperty("password", out var password))
        {
            if (!ValidText(request, "actor", 1, 64, "._@-")) return new { error = "invalid" };
            var actor = request.GetProperty("actor").GetString()!;
            if (Wait is { } wait)
            {
                await WriteAsync(actor, AuditAction.SignIn, "", AuditOutcome.Denied);
                return new { error = "wait", retryAfter = wait };
            }
            if (Password is null)
            {
                await WriteAsync(actor, AuditAction.SignIn, "", AuditOutcome.Failed);
                return new { error = "no_password" };
            }
            if (password.GetString() != Password)
            {
                await WriteAsync(actor, AuditAction.SignIn, "", AuditOutcome.Failed);
                return new { error = "wrong_password" };
            }
            await WriteAsync(actor, AuditAction.SignIn, "", AuditOutcome.Succeeded);
            var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
            _sessions[token] = actor;
            return new { session = token, actor };
        }
        if (session is null || !_sessions.TryGetValue(session, out var owner)) return new { error = "session_ended" };
        if (request.TryGetProperty("signOut", out _))
        {
            _sessions.TryRemove(session, out _);
            return await WriteAsync(owner, AuditAction.SignOut, "", AuditOutcome.Succeeded);
        }
        if (!ValidText(request, "target", 0, 128, "._:-")
            || !request.TryGetProperty("action", out var actionName) || actionName.ValueKind != JsonValueKind.String
            || !new[] { AuditAction.Search, AuditAction.Export, AuditAction.FlagReviewed, AuditAction.FlagReopened }
                .Any(a => AuditLog.WireName(a) == actionName.GetString())
            || !request.TryGetProperty("outcome", out var outcomeName) || outcomeName.ValueKind != JsonValueKind.String
            || !Enum.GetValues<AuditOutcome>().Any(a => AuditLog.WireName(a) == outcomeName.GetString()))
            return new { error = "invalid" };
        var action = Enum.GetValues<AuditAction>().Single(a => AuditLog.WireName(a) == actionName.GetString());
        var outcome = Enum.GetValues<AuditOutcome>().Single(a => AuditLog.WireName(a) == outcomeName.GetString());
        return await WriteAsync(owner, action, request.GetProperty("target").GetString()!, outcome);
    }

    private async Task<object> WriteAsync(string actor, AuditAction action, string target, AuditOutcome outcome)
    {
        await using var writer = await AuditLog.OpenAsync(_db, actor, TimeProvider.System, _stop.Token);
        var entry = await writer.AppendAsync(action, target, outcome, null, _stop.Token);
        return new { seq = entry.Seq, auditId = entry.AuditId, tsUs = entry.TsUs };
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
