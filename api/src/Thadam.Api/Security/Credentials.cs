using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Thadam.Audit;

namespace Thadam.Api.Security;

/// <summary>The stored password hash (ADR-008 Decision 2). Never the password.</summary>
public sealed record CredentialFile(int Version, string Algorithm, int Iterations, string Salt, string Hash);

/// <summary>
/// The single local user's password: PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP Password
/// Storage Cheat Sheet's figure for PBKDF2-HMAC-SHA256), 16-byte salt, 32-byte hash, in
/// <c>credentials.json</c> (mode 0600). Compared in constant time.
/// </summary>
public static class Credentials
{
    public const string Algorithm = "PBKDF2-HMAC-SHA256";
    public const int Iterations = 600_000;
    /// <summary>NIST SP 800-63B-4 §3.1.1.2: at least 15 characters for a password used alone.</summary>
    public const int MinLength = 15;
    public const int MaxLength = 1024;
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    /// <summary>Why a new password is not acceptable, or null.</summary>
    public static string? Problem(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        return password.Length switch
        {
            < MinLength => $"the password must be at least {MinLength} characters",
            > MaxLength => $"the password must be at most {MaxLength} characters",
            _ => null,
        };
    }

    public static CredentialFile Create(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Derive(password, salt, Iterations);
        return new CredentialFile(1, Algorithm, Iterations, Convert.ToBase64String(salt), Convert.ToBase64String(hash));
    }

    public static bool Verify(string password, CredentialFile file)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(file);
        if (file.Version != 1 || file.Algorithm != Algorithm || file.Iterations < Iterations
            || password.Length > MaxLength)
        {
            return false;
        }
        byte[] salt;
        byte[] expected;
        try
        {
            salt = Convert.FromBase64String(file.Salt);
            expected = Convert.FromBase64String(file.Hash);
        }
        catch (FormatException)
        {
            return false;
        }
        if (expected.Length != HashBytes)
        {
            return false;
        }
        return CryptographicOperations.FixedTimeEquals(Derive(password, salt, file.Iterations), expected);
    }

    public static async Task SaveAsync(string path, CredentialFile file, CancellationToken ct) =>
        await PrivateFiles.WriteAllTextAsync(path, JsonSerializer.Serialize(file, Json), ct).ConfigureAwait(false);

    /// <summary>The stored file, or null when no password has been set or it can't be read.</summary>
    public static async Task<CredentialFile?> LoadAsync(string path, CancellationToken ct)
    {
        if (!File.Exists(path))
        {
            return null;
        }
        try
        {
            await using var fs = File.OpenRead(path);
            return await JsonSerializer.DeserializeAsync<CredentialFile>(fs, Json, ct).ConfigureAwait(false);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static byte[] Derive(string password, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, HashBytes);
}
