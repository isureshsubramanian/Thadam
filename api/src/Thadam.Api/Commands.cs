using System.Text;
using Thadam.Api.Security;
using Thadam.Audit;

namespace Thadam.Api;

/// <summary>The command-line tasks besides <c>run</c>.</summary>
internal static class Commands
{
    /// <summary>
    /// Sets the password, read from the terminal with echo off (never from an argument, which
    /// <c>ps</c> would show). From a pipe it reads one line.
    /// </summary>
    public static async Task<int> SetPasswordAsync(ApiOptions options, CancellationToken ct)
    {
        string password;
        if (Console.IsInputRedirected)
        {
            password = await Console.In.ReadLineAsync(ct).ConfigureAwait(false) ?? "";
        }
        else
        {
            password = ReadHidden("New password: ");
            if (ReadHidden("Again: ") != password)
            {
                Console.Error.WriteLine("The two entries differ; nothing changed.");
                return 2;
            }
        }
        if (Credentials.Problem(password) is { } problem)
        {
            Console.Error.WriteLine($"Not set: {problem}.");
            return 2;
        }
        await Credentials.SaveAsync(options.CredentialsPath, Credentials.Create(password), ct).ConfigureAwait(false);
        Console.WriteLine("Password set.");
        return 0;
    }

    public static async Task<int> VerifyAuditAsync(ApiOptions options, CancellationToken ct)
    {
        if (!File.Exists(options.AuditPath))
        {
            Console.Error.WriteLine("No audit log yet.");
            return 2;
        }
        await using var audit = await (options.AuditSocket is { } socket
            ? AuditLog.OpenCollectorAsync(options.AuditPath, socket, Environment.UserName, TimeProvider.System, ct)
            : AuditLog.OpenAsync(options.AuditPath, Environment.UserName, TimeProvider.System, ct)).ConfigureAwait(false);
        var report = await audit.VerifyAsync(ct).ConfigureAwait(false);
        if (report.Ok)
        {
            Console.WriteLine($"OK    {report.Verified} audit entries verified");
            return 0;
        }
        Console.WriteLine($"FAIL  audit chain broken at entry {report.BrokenAt}; {report.Verified} entries verified before it");
        return 1;
    }

    private static string ReadHidden(string prompt)
    {
        Console.Write(prompt);
        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return sb.ToString();
            }
            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0)
                {
                    sb.Length--;
                }
            }
            else if (!char.IsControl(key.KeyChar))
            {
                sb.Append(key.KeyChar);
            }
        }
    }
}
