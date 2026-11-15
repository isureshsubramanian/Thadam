using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Thadam.Api.Security;
using Thadam.Store.Tests;

namespace Thadam.Api.Tests;

[CollectionDefinition(Name)]
public sealed class ApiFixtureDefinition : ICollectionFixture<StoreFixture>
{
    public const string Name = "api";
}

/// <summary>A real API server on a free loopback port, over the Rust-written store fixture.</summary>
public sealed class ApiTestHost : IAsyncDisposable
{
    public const string Password = "correct horse battery staple";

    /// <summary>Synthetic registry: one tool with a display name, one without.</summary>
    public const string Registry = """
        {"version": 1, "tools": [
          {"key": "cli_agent", "display_name": "CLI agent", "match": [{"path": "/opt/example/cli-agent"}]},
          {"key": "desktop_assistant", "match": [{"path": "/opt/example/assistant"}]}
        ]}
        """;

    private readonly WebApplication _app;

    private ApiTestHost(WebApplication app, ApiOptions options, Uri baseAddress)
    {
        _app = app;
        Options = options;
        BaseAddress = baseAddress;
        Client = NewClient();
    }

    public ApiOptions Options { get; }

    public Uri BaseAddress { get; }

    /// <summary>A client with its own cookies.</summary>
    public HttpClient Client { get; }

    public T Service<T>() where T : notnull => _app.Services.GetRequiredService<T>();

    public ICollection<string> Urls => _app.Urls;

    public static Task<ApiTestHost> StartAsync(StoreFixture store, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(store);
        return StartAsync(store.Folder, ct);
    }

    /// <summary>A server over any store folder (the benchmark's).</summary>
    public static async Task<ApiTestHost> StartAsync(string storeFolder, CancellationToken ct, int? exportMaxRows = null)
    {
        var dataDir = Path.Combine(Path.GetTempPath(), $"thadam-api-test-{Guid.NewGuid():N}");
        // A synthetic dashboard and notices file, so tests don't depend on the web build.
        var webDir = Path.Combine(dataDir, "web");
        Directory.CreateDirectory(webDir);
        await File.WriteAllTextAsync(Path.Combine(webDir, "index.html"), "<!doctype html><title>test dashboard</title>", ct);
        var options = new ApiOptions(storeFolder, Path.Combine(dataDir, "registry.json"), dataDir, 0)
        {
            WebDir = webDir,
            NoticesPath = Path.Combine(dataDir, "notices.txt"),
            ExportMaxRows = exportMaxRows ?? Export.CsvExport.MaxRows,
        };
        await File.WriteAllTextAsync(options.NoticesPath, "synthetic notices", ct);
        await Credentials.SaveAsync(options.CredentialsPath, Credentials.Create(Password), ct);
        await File.WriteAllTextAsync(options.RegistryPath, Registry, ct);
        var app = await ApiHost.BuildAsync(options, TimeProvider.System, ct);
        await app.StartAsync(ct);
        var url = new Uri(app.Urls.First());
        return new ApiTestHost(app, options, new Uri($"http://127.0.0.1:{url.Port}"));
    }

    public HttpClient NewClient() => new(new HttpClientHandler
    {
        CookieContainer = new CookieContainer(),
        UseCookies = true,
        AllowAutoRedirect = false,
    })
    { BaseAddress = BaseAddress };

    public static async Task<string> CsrfAsync(HttpClient client, CancellationToken ct)
    {
        var r = await client.GetFromJsonAsync<TokenResponse>("/api/v1/antiforgery", ct);
        return r!.Token;
    }

    public static async Task<HttpResponseMessage> SignInAsync(HttpClient client, string password, CancellationToken ct)
    {
        var token = await CsrfAsync(client, ct);
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/session")
        {
            Content = JsonContent.Create(new { password }),
        };
        req.Headers.Add(ApiHost.CsrfHeader, token);
        return await client.SendAsync(req, ct);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.StopAsync();
        await _app.DisposeAsync();
        Directory.Delete(Options.DataDir, recursive: true);
    }

    /// <summary>A signed-in client and its antiforgery token.</summary>
    public async Task<(HttpClient Client, string Csrf)> SignedInAsync(CancellationToken ct)
    {
        var client = NewClient();
        (await SignInAsync(client, Password, ct)).EnsureSuccessStatusCode();
        return (client, await CsrfAsync(client, ct));
    }

    public sealed record TokenResponse(string Token);
}
