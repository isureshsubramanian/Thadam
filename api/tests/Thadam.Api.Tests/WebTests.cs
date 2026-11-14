using System.Net;
using Thadam.Store.Tests;

namespace Thadam.Api.Tests;

/// <summary>The dashboard and notices are served from the API's own origin (ADR-008 Decision 1).</summary>
[Collection(ApiFixtureDefinition.Name)]
public sealed class WebTests(StoreFixture store)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task TheDashboardIsServedWithTheSecurityHeaders()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        using var r = await host.Client.GetAsync("/", Ct);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Contains("test dashboard", await r.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
        var csp = string.Join(";", r.Headers.GetValues("Content-Security-Policy"));
        Assert.Contains("script-src 'self'", csp, StringComparison.Ordinal);
        Assert.Contains("frame-ancestors 'none'", csp, StringComparison.Ordinal);
        Assert.Equal("nosniff", r.Headers.GetValues("X-Content-Type-Options").Single());
    }

    [Fact]
    public async Task NoticesAreReadableWithoutSigningIn()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        using var r = await host.Client.GetAsync("/notices", Ct);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal("text/plain", r.Content.Headers.ContentType?.MediaType);
        Assert.Equal("synthetic notices", await r.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task TheDashboardRefusesAForeignHost()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        using var req = new HttpRequestMessage(HttpMethod.Get, "/");
        req.Headers.Host = "evil.test";
        using var r = await host.Client.SendAsync(req, Ct);
        Assert.NotEqual(HttpStatusCode.OK, r.StatusCode);
    }
}
