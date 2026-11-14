using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace Thadam.Api.Security;

/// <summary>
/// Refuses any request whose Host header is not <c>127.0.0.1:port</c> or
/// <c>localhost:port</c> (ADR-008 Decision 3): a page on another site that rebinds its DNS
/// name to 127.0.0.1 still sends its own name, so it can't read the API through the browser.
/// The built-in host filter ignores ports, so this checks the exact pair.
/// </summary>
public sealed class HostCheck(RequestDelegate next, IServer server)
{
    private string[]? _allowed;

    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var allowed = _allowed ??= Allowed(server);
        var host = context.Request.Host.Value ?? "";
        if (!allowed.Contains(host, StringComparer.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        await next(context).ConfigureAwait(false);
    }

    /// <summary>The bound port, read from the server, so a test port 0 works too.</summary>
    private static string[] Allowed(IServer server)
    {
        var address = server.Features.Get<IServerAddressesFeature>()?.Addresses.FirstOrDefault()
            ?? throw new InvalidOperationException("the server has no address");
        var port = new Uri(address).Port;
        return [$"127.0.0.1:{port}", $"localhost:{port}"];
    }
}

/// <summary>Response headers on every response (ADR-008 Decision 3).</summary>
public sealed class SecurityHeaders(RequestDelegate next)
{
    private const string Csp =
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
        "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

    public Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        context.Response.OnStarting(() =>
        {
            var h = context.Response.Headers;
            h.ContentSecurityPolicy = Csp;
            h.XContentTypeOptions = "nosniff";
            h.XFrameOptions = "DENY";
            h["Referrer-Policy"] = "no-referrer";
            h["Cross-Origin-Opener-Policy"] = "same-origin";
            h["Cross-Origin-Resource-Policy"] = "same-origin";
            if (context.Request.Path.StartsWithSegments("/api", StringComparison.Ordinal))
            {
                h.CacheControl = "no-store";
            }
            return Task.CompletedTask;
        });
        return next(context);
    }
}
