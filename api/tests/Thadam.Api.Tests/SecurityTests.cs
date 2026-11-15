using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Thadam.Audit;
using Thadam.Store.Tests;

namespace Thadam.Api.Tests;

/// <summary>ADR-008 acceptance tests 1 (sign-in), 2 (exposure) and 4 (validation, sign-in part).</summary>
[Collection(ApiFixtureDefinition.Name)]
public sealed class SecurityTests(StoreFixture store)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<IReadOnlyList<(string Action, string Outcome)>> AuditAsync(ApiTestHost host) =>
        [.. (await host.Service<AuditLog>().EntriesAsync(Ct)).Select(e => (e.Action, e.Outcome))];

    [Fact]
    public async Task ApiCallsWithoutASessionAre401()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        using var r = await host.Client.GetAsync("/api/v1/meta", Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact]
    public async Task TheRightPasswordGivesASessionAndSignOutEndsIt()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        using (var r = await ApiTestHost.SignInAsync(host.Client, ApiTestHost.Password, Ct))
        {
            Assert.Equal(HttpStatusCode.NoContent, r.StatusCode);
            var cookie = Assert.Single(r.Headers.GetValues("Set-Cookie"), c => c.StartsWith(ApiHost.CookieName, StringComparison.Ordinal));
            Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("samesite=strict", cookie, StringComparison.OrdinalIgnoreCase);
        }
        using (var meta = await host.Client.GetAsync("/api/v1/meta", Ct))
        {
            Assert.Equal(HttpStatusCode.OK, meta.StatusCode);
        }
        var token = await ApiTestHost.CsrfAsync(host.Client, Ct);
        using (var req = new HttpRequestMessage(HttpMethod.Delete, "/api/v1/session"))
        {
            req.Headers.Add(ApiHost.CsrfHeader, token);
            using var r = await host.Client.SendAsync(req, Ct);
            Assert.Equal(HttpStatusCode.NoContent, r.StatusCode);
        }
        using (var after = await host.Client.GetAsync("/api/v1/meta", Ct))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
        }
        Assert.Equal([("sign_in", "succeeded"), ("sign_out", "succeeded")], await AuditAsync(host));
    }

    [Fact]
    public async Task AWrongPasswordIs401AndAudited()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        using var r = await ApiTestHost.SignInAsync(host.Client, "not the password at all", Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        Assert.Equal([("sign_in", "failed")], await AuditAsync(host));
    }

    [Fact]
    public async Task AfterFiveWrongPasswordsTheNextWaitsUncheckedAndSaysHowLong()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var codes = new List<HttpStatusCode>();
        for (var i = 0; i < 5; i++)
        {
            using var r = await ApiTestHost.SignInAsync(host.Client, "wrong password number " + i, Ct);
            codes.Add(r.StatusCode);
        }
        // Even the right password waits: the wait cannot be skipped by guessing faster.
        using var limited = await ApiTestHost.SignInAsync(host.Client, ApiTestHost.Password, Ct);
        codes.Add(limited.StatusCode);
        Assert.Equal([.. Enumerable.Repeat(HttpStatusCode.Unauthorized, 5), HttpStatusCode.TooManyRequests], codes);
        Assert.Equal(TimeSpan.FromSeconds(1), limited.Headers.RetryAfter?.Delta);
        Assert.Equal(("sign_in", "denied"), (await AuditAsync(host))[^1]);
        // Another client is not locked out for long: after the wait, the right password works.
        await Task.Delay(TimeSpan.FromSeconds(1.1), Ct);
        using var later = await ApiTestHost.SignInAsync(host.NewClient(), ApiTestHost.Password, Ct);
        Assert.Equal(HttpStatusCode.NoContent, later.StatusCode);
    }

    [Fact]
    public async Task AWriteWithoutTheAntiforgeryTokenIs400()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        using var r = await host.Client.PostAsJsonAsync("/api/v1/session", new { password = ApiTestHost.Password }, Ct);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Contains("antiforgery", await r.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
        Assert.Empty(await AuditAsync(host));
    }

    [Fact]
    public async Task AnInvalidPasswordFieldNamesTheFieldNotTheValue()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var tooLong = new string('q', 1025) + "MARKER";
        using var r = await ApiTestHost.SignInAsync(host.Client, tooLong, Ct);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        var body = await r.Content.ReadAsStringAsync(Ct);
        Assert.Equal(["password"], JsonElement.Parse(body).GetProperty("errors").EnumerateArray().Select(e => e.GetString()));
        Assert.DoesNotContain("MARKER", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AForeignHostHeaderIsRefused()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/antiforgery");
        req.Headers.Host = "evil.test";
        using var r = await host.Client.SendAsync(req, Ct);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);

        using var ok = new HttpRequestMessage(HttpMethod.Get, "/api/v1/antiforgery");
        ok.Headers.Host = $"localhost:{host.BaseAddress.Port}";
        using var r2 = await host.Client.SendAsync(ok, Ct);
        Assert.Equal(HttpStatusCode.OK, r2.StatusCode);
    }

    [Fact]
    public async Task ItListensOnIpv4LoopbackOnly()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        Assert.NotEmpty(host.Urls);
        Assert.All(host.Urls, u => Assert.Equal("127.0.0.1", new Uri(u).Host));
    }

    [Fact]
    public async Task ResponsesCarryTheSecurityHeaders()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        using var r = await host.Client.GetAsync("/api/v1/antiforgery", Ct);
        Assert.Contains("frame-ancestors 'none'", r.Headers.GetValues("Content-Security-Policy").Single(), StringComparison.Ordinal);
        Assert.Equal("nosniff", r.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("no-referrer", r.Headers.GetValues("Referrer-Policy").Single());
        Assert.Equal("no-store", r.Headers.CacheControl?.ToString());
        Assert.False(r.Headers.Contains("Server"));
    }

    [Fact]
    public async Task PrivateFilesAreTheUsersOnly()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var owner = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        Assert.Equal(owner | UnixFileMode.UserExecute, File.GetUnixFileMode(host.Options.DataDir));
        Assert.Equal(owner, File.GetUnixFileMode(host.Options.CredentialsPath));
        Assert.Equal(owner, File.GetUnixFileMode(host.Options.AuditPath));
    }

    [Fact]
    public async Task TheHeaderShowsTheVerifiedChain()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        await host.Service<ChainMonitor>().CheckAsync(Ct);
        using var signIn = await ApiTestHost.SignInAsync(host.Client, ApiTestHost.Password, Ct);
        var meta = JsonElement.Parse(await host.Client.GetStringAsync("/api/v1/meta", Ct)).GetProperty("chain");
        Assert.Equal("verified", meta.GetProperty("state").GetString());
        Assert.Equal(5, meta.GetProperty("firstSeq").GetInt64());
        Assert.Equal(33, meta.GetProperty("lastSeq").GetInt64());
        Assert.Equal(2, meta.GetProperty("retired").GetArrayLength());
    }
}
