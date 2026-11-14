using System.Net;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.RateLimiting;
using Thadam.Api.Endpoints;
using Thadam.Api.Security;
using Thadam.Audit;
using Thadam.Store;
using Thadam.Store.Queries;

namespace Thadam.Api;

/// <summary>Builds the web application: one process serves the API and, later, the dashboard.</summary>
public static class ApiHost
{
    public const string SignInPolicy = "sign-in";
    public const string CookieName = "thadam_session";
    public const string CsrfCookieName = "thadam_csrf";
    public const string CsrfHeader = "X-Thadam-Csrf";
    /// <summary>ADR-008 Decision 2: at most 5 sign-in attempts a minute, then 429.</summary>
    private const int SignInPermits = 5;
    /// <summary>A working day (estimate, ADR-008 Decision 2).</summary>
    private static readonly TimeSpan SessionLength = TimeSpan.FromHours(8);

    public static async Task<WebApplication> BuildAsync(ApiOptions options, TimeProvider time, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(options);
        PrivateFiles.EnsureFolder(options.DataDir);
        PrivateFiles.EnsureFolder(options.KeysPath);

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = [],
            EnvironmentName = Environments.Production,
            ContentRootPath = AppContext.BaseDirectory,
        });

        // Loopback only, IPv4: never 0.0.0.0 or :: (ADR-008 Decision 3).
        builder.WebHost.ConfigureKestrel(k =>
        {
            k.AddServerHeader = false;
            k.Limits.MaxRequestBodySize = 64 * 1024;
            k.Listen(IPAddress.Loopback, options.Port);
        });

        // Diagnostics: counts and errors only. Framework request logs carry paths and query
        // strings (search text), so they stay below the level that is written.
        builder.Logging.ClearProviders();
        builder.Logging.AddSimpleConsole(o => o.SingleLine = true);
        builder.Logging.AddFilter("Microsoft", LogLevel.Warning);
        builder.Logging.AddFilter("System", LogLevel.Warning);

        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton(time);
        var audit = await AuditLog.OpenAsync(options.AuditPath, Environment.UserName, time, ct).ConfigureAwait(false);
        builder.Services.AddSingleton(audit);
        var store = new StoreFolder(options.StorePath);
        builder.Services.AddSingleton(store);
        var index = new SegmentIndex(store);
        builder.Services.AddSingleton(index);
        builder.Services.AddSingleton(new StoreQueries(index));
        builder.Services.AddSingleton<ToolRegistry>();
        builder.Services.AddSingleton<ChainMonitor>();
        builder.Services.AddHostedService(sp => sp.GetRequiredService<ChainMonitor>());

        builder.Services.AddDataProtection()
            .SetApplicationName("thadam-api")
            .PersistKeysToFileSystem(new DirectoryInfo(options.KeysPath));

        builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(o =>
            {
                o.Cookie.Name = CookieName;
                o.Cookie.HttpOnly = true;
                o.Cookie.SameSite = SameSiteMode.Strict;
                // Plain HTTP on loopback (ADR-008 Decision 2), so the cookie can't be Secure.
                o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                o.ExpireTimeSpan = SessionLength;
                o.SlidingExpiration = true;
                o.Events.OnRedirectToLogin = c =>
                {
                    c.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                };
                o.Events.OnRedirectToAccessDenied = c =>
                {
                    c.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return Task.CompletedTask;
                };
            });
        builder.Services.AddAuthorization();
        builder.Services.AddAntiforgery(o =>
        {
            o.HeaderName = CsrfHeader;
            o.Cookie.Name = CsrfCookieName;
            o.Cookie.HttpOnly = true;
            o.Cookie.SameSite = SameSiteMode.Strict;
            o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        });
        builder.Services.AddRateLimiter(o =>
        {
            o.AddFixedWindowLimiter(SignInPolicy, w =>
            {
                w.PermitLimit = SignInPermits;
                w.Window = TimeSpan.FromMinutes(1);
                w.QueueLimit = 0;
            });
            o.OnRejected = async (c, token) =>
            {
                c.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                await audit.AppendAsync(AuditAction.SignIn, "", AuditOutcome.Denied, token).ConfigureAwait(false);
            };
        });
        builder.Services.ConfigureHttpJsonOptions(o =>
            o.SerializerOptions.Converters.Add(new JsonStringEnumConverter(System.Text.Json.JsonNamingPolicy.SnakeCaseLower)));
        builder.Services.AddProblemDetails();

        var app = builder.Build();
        app.UseMiddleware<HostCheck>();
        app.UseMiddleware<SecurityHeaders>();
        app.UseExceptionHandler(e => e.Run(c =>
        {
            c.Response.StatusCode = StatusCodes.Status500InternalServerError;
            return Task.CompletedTask;
        }));
        app.UseStatusCodePages();
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseRateLimiter();

        var api = app.MapGroup("/api/v1");
        SessionEndpoints.Map(api);
        MetaEndpoints.Map(api);
        QueryEndpoints.Map(api);
        app.Lifetime.ApplicationStopped.Register(() => audit.DisposeAsync().AsTask().GetAwaiter().GetResult());
        return app;
    }
}
