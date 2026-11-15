using System.Security.Claims;
using System.Security.Cryptography;
using Thadam.Audit;

namespace Thadam.Api.Security;

/// <summary>
/// Who may sign in (ADR-008 Decision 2, ADR-015 Decision 1). Installed, the collector checks
/// the password against its root-only verifier and hands out the session; the API only
/// carries it, in the encrypted cookie, to every audited call. Without a collector (the API
/// alone, in development and tests) the API checks its own credentials file, under the same
/// rule for wrong passwords: after <see cref="FreeAttempts"/> failures each further attempt
/// waits 2^n seconds after the last one, up to <see cref="MaxWait"/>, unchecked until then.
/// </summary>
public sealed class SignInGate(ApiOptions options, AuditLog audit, TimeProvider time) : IDisposable
{
    /// <summary>The cookie claim holding the session the audit log checks.</summary>
    public const string SessionClaim = "thadam:session";
    private const int FreeAttempts = 5;
    private static readonly TimeSpan MaxWait = TimeSpan.FromMinutes(5);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private int _failures;
    private DateTimeOffset _last;

    /// <summary>The signed-in user's session, or null.</summary>
    public static string? Session(ClaimsPrincipal user)
    {
        ArgumentNullException.ThrowIfNull(user);
        return user.FindFirst(SessionClaim)?.Value;
    }

    public async Task<SignInResult> SignInAsync(string password, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (audit.UsesCollector)
        {
            return await audit.SignInThroughCollectorAsync(password, ct).ConfigureAwait(false);
        }
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var now = time.GetUtcNow();
            if (_failures >= FreeAttempts)
            {
                var delay = TimeSpan.FromSeconds(Math.Pow(2, Math.Min(_failures - FreeAttempts, 16)));
                var left = _last + (delay < MaxWait ? delay : MaxWait) - now;
                if (left > TimeSpan.Zero)
                {
                    await audit.AppendAsync(AuditAction.SignIn, "", AuditOutcome.Denied, null, ct).ConfigureAwait(false);
                    return new SignInResult(SignInStatus.Wait, RetryAfter: (int)Math.Ceiling(left.TotalSeconds));
                }
            }
            var stored = await Credentials.LoadAsync(options.CredentialsPath, ct).ConfigureAwait(false);
            if (stored is null)
            {
                await audit.AppendAsync(AuditAction.SignIn, "", AuditOutcome.Failed, null, ct).ConfigureAwait(false);
                return new SignInResult(SignInStatus.NoPassword);
            }
            if (!Credentials.Verify(password, stored))
            {
                _failures++;
                _last = now;
                await audit.AppendAsync(AuditAction.SignIn, "", AuditOutcome.Failed, null, ct).ConfigureAwait(false);
                return new SignInResult(SignInStatus.WrongPassword);
            }
            await audit.AppendAsync(AuditAction.SignIn, "", AuditOutcome.Succeeded, null, ct).ConfigureAwait(false);
            _failures = 0;
            return new SignInResult(SignInStatus.SignedIn, Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)));
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose() => _gate.Dispose();
}
