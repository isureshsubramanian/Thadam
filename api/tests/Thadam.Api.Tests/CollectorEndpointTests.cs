using System.Net;
using System.Text.Json;
using Thadam.Audit;
using Thadam.Store.Tests;

namespace Thadam.Api.Tests;

[Collection(ApiFixtureDefinition.Name)]
public sealed class CollectorEndpointTests(StoreFixture store)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnauditedActionsReturnOnlyAuditError(bool refused)
    {
        var dir = Directory.CreateTempSubdirectory("thadam-ac-");
        try
        {
            var socket = Path.Combine(dir.FullName, "a.sock");
            var db = Path.Combine(dir.FullName, "audit.db");
            await using var collector = new FakeCollector(socket, db);
            await using var host = await ApiTestHost.StartAsync(store.Folder, Ct, auditSocket: socket, auditDb: db);
            var (client, csrf) = await host.SignedInAsync(Ct);
            using (client)
            {
                using var flags = await client.GetAsync("/api/v1/flags?from=2026-10-01T00:00:00Z&to=2026-11-30T00:00:00Z", Ct);
                flags.EnsureSuccessStatusCode();
                using var flagBody = JsonDocument.Parse(await flags.Content.ReadAsStringAsync(Ct));
                var items = flagBody.RootElement.GetProperty("items");
                var openId = items[0].GetProperty("eventId").GetString()!;
                var reviewedId = items[1].GetProperty("eventId").GetString()!;
                await host.Service<AuditLog>().SetReviewedAsync(reviewedId, true, Ct);
                var before = (await host.Service<AuditLog>().EntriesAsync(Ct)).Count;
                if (refused) collector.Error = "refused";
                else File.Delete(socket); // New connections fail while the listener stays alive for disposal.
                using var signIn = await ApiTestHost.SignInAsync(host.Client, ApiTestHost.Password, Ct);
                await AssertAuditAsync(signIn);
                using var failedSignIn = await ApiTestHost.SignInAsync(host.Client, "synthetic wrong password", Ct);
                await AssertAuditAsync(failedSignIn);
                Assert.DoesNotContain(signIn.Headers.TryGetValues("Set-Cookie", out var cookies) ? cookies : [],
                    c => c.StartsWith(ApiHost.CookieName + "=", StringComparison.Ordinal));
                using var anonymous = await host.Client.GetAsync("/api/v1/overview", Ct);
                Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
                foreach (var path in new[] { "/api/v1/events?q=since:7d", "/api/v1/export?q=since:7d" })
                {
                    using var response = await client.GetAsync(path, Ct);
                    await AssertAuditAsync(response);
                    Assert.False(response.Content.Headers.ContentType?.MediaType == "text/csv");
                }
                foreach (var action in new[] { (Action: "review", Id: openId), (Action: "reopen", Id: reviewedId) })
                {
                    using var request = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/flags/{action.Id}/{action.Action}");
                    request.Headers.Add(ApiHost.CsrfHeader, csrf);
                    using var response = await client.SendAsync(request, Ct);
                    await AssertAuditAsync(response);
                }
                Assert.Equal([reviewedId], await host.Service<AuditLog>().ReviewedEventsAsync(Ct));
                Assert.Equal(before, (await host.Service<AuditLog>().EntriesAsync(Ct)).Count);
                using var logout = new HttpRequestMessage(HttpMethod.Delete, "/api/v1/session");
                logout.Headers.Add(ApiHost.CsrfHeader, csrf);
                using var signedOut = await client.SendAsync(logout, Ct);
                await AssertAuditAsync(signedOut);
                using var after = await client.GetAsync("/api/v1/overview", Ct);
                Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
            }
        }
        finally { dir.Delete(recursive: true); }
    }

    private static async Task AssertAuditAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(Ct);
        using var json = JsonDocument.Parse(body);
        Assert.Equal(["audit"], json.RootElement.GetProperty("errors").EnumerateArray().Select(e => e.GetString()));
        Assert.Single(json.RootElement.EnumerateObject());
    }
}
