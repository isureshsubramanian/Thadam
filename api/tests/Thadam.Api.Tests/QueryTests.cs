using System.Net;
using System.Text.Json;
using Thadam.Store.Tests;

namespace Thadam.Api.Tests;

/// <summary>
/// ADR-008 acceptance tests 4, 5 and 7 over the Rust-written fixture. Kept rows (seq 5-33):
/// W46 has s-b1 (a project read, 12 outside reads, a command with a redacted token) and its
/// delegated child s-b2 (a read, an outside write); W47 has s-c1 (reads, 40 tool-internal
/// reads, an unknown host, a read the OS refused).
/// </summary>
[Collection(ApiFixtureDefinition.Name)]
public sealed class QueryTests(StoreFixture store)
{
    private const string All = "from=2026-10-01T00:00:00Z&to=2026-11-30T00:00:00Z";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<JsonElement> GetAsync(HttpClient client, string url)
    {
        using var r = await client.GetAsync(url, Ct);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return JsonElement.Parse(await r.Content.ReadAsStringAsync(Ct));
    }

    private static async Task<HttpResponseMessage> PostAsync(HttpClient client, string csrf, string url)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, url);
        req.Headers.Add(ApiHost.CsrfHeader, csrf);
        return await client.SendAsync(req, Ct);
    }

    private static string[] Names(JsonElement array, string field) =>
        [.. array.EnumerateArray().Select(e => e.GetProperty(field).GetString()!)];

    [Fact]
    public async Task OverviewCountsTheKeptRows()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        var o = await GetAsync(client, $"/api/v1/overview?{All}");
        var k = o.GetProperty("kpis");
        Assert.Equal(3, k.GetProperty("sessions").GetInt32());
        Assert.Equal(2, k.GetProperty("outsideProject").GetProperty("records").GetInt64());
        Assert.Equal(2, k.GetProperty("outsideProject").GetProperty("folders").GetInt32());
        var open = k.GetProperty("flaggedOpen");
        Assert.Equal((1, 2, 2), (open.GetProperty("high").GetInt32(), open.GetProperty("medium").GetInt32(), open.GetProperty("low").GetInt32()));
        Assert.Equal(1, k.GetProperty("denied").GetProperty("byOs").GetInt64());
        Assert.Equal(0, k.GetProperty("denied").GetProperty("byUser").GetInt64()); // the W45 refusal is retired
        Assert.Equal(1, k.GetProperty("hosts").GetProperty("unknown").GetInt32());
        Assert.True(k.GetProperty("sensitive").EnumerateObject().Any());

        var tools = o.GetProperty("byTool");
        Assert.Equal(["cli_agent", "desktop_assistant"], Names(tools, "tool"));
        Assert.Equal(["CLI agent", "desktop_assistant"], Names(tools, "displayName"));
        Assert.Contains("~/.cargo/registry", Names(o.GetProperty("outsideFolders"), "folder"));
        Assert.Equal(["203.0.113.7:443"], Names(o.GetProperty("hosts"), "target"));
    }

    [Fact]
    public async Task OverviewFiltersByToolAndTime()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        var assistant = await GetAsync(client, $"/api/v1/overview?{All}&tool=desktop_assistant");
        Assert.Equal(1, assistant.GetProperty("kpis").GetProperty("sessions").GetInt32());
        // W47 only: s-c1.
        var week = await GetAsync(client, "/api/v1/overview?from=2026-11-16T00:00:00Z&to=2026-11-22T23:59:59Z");
        Assert.Equal(1, week.GetProperty("kpis").GetProperty("sessions").GetInt32());
        Assert.Equal(0, week.GetProperty("kpis").GetProperty("outsideProject").GetProperty("records").GetInt64());
    }

    [Fact]
    public async Task FlagsAreGroupedRankedAndRedacted()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        var f = await GetAsync(client, $"/api/v1/flags?{All}");
        var items = f.GetProperty("items");
        Assert.Equal(["denied_by_os", "unknown_host", "outside_change", "secret", "outside_read"], Names(items, "rule"));
        Assert.Equal(["low", "medium", "medium", "high", "low"], Names(items, "severity"));
        var secret = items.EnumerateArray().Single(i => i.GetProperty("rule").GetString() == "secret");
        Assert.DoesNotContain("ghp_", secret.GetProperty("target").GetString(), StringComparison.Ordinal);
        var outside = items.EnumerateArray().Single(i => i.GetProperty("rule").GetString() == "outside_read");
        Assert.Equal(12, outside.GetProperty("count").GetInt64());
        Assert.Equal(JsonValueKind.Null, f.GetProperty("next").ValueKind);

        var high = await GetAsync(client, $"/api/v1/flags?{All}&severity=high");
        Assert.Equal(["secret"], Names(high.GetProperty("items"), "rule"));
    }

    [Fact]
    public async Task ReviewMovesAnItemAndReopenBringsItBack()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, csrf) = await host.SignedInAsync(Ct);
        var first = (await GetAsync(client, $"/api/v1/flags?{All}")).GetProperty("items")[0];
        var id = first.GetProperty("eventId").GetString()!;

        using (var r = await PostAsync(client, csrf, $"/api/v1/flags/{id}/review"))
        {
            Assert.Equal(HttpStatusCode.NoContent, r.StatusCode);
        }
        using (var again = await PostAsync(client, csrf, $"/api/v1/flags/{id}/review"))
        {
            Assert.Equal(HttpStatusCode.NoContent, again.StatusCode);
        }
        Assert.DoesNotContain(id, Names((await GetAsync(client, $"/api/v1/flags?{All}")).GetProperty("items"), "eventId"));
        Assert.Equal([id], Names((await GetAsync(client, $"/api/v1/flags?{All}&status=reviewed")).GetProperty("items"), "eventId"));
        var overview = await GetAsync(client, $"/api/v1/overview?{All}");
        Assert.Equal(1, overview.GetProperty("kpis").GetProperty("flaggedOpen").GetProperty("low").GetInt32());

        using (var r = await PostAsync(client, csrf, $"/api/v1/flags/{id}/reopen"))
        {
            Assert.Equal(HttpStatusCode.NoContent, r.StatusCode);
        }
        Assert.Contains(id, Names((await GetAsync(client, $"/api/v1/flags?{All}")).GetProperty("items"), "eventId"));

        var audit = host.Service<Thadam.Audit.AuditLog>();
        var reviews = (await audit.EntriesAsync(Ct)).Where(e => e.TargetId == id).Select(e => e.Action).ToList();
        Assert.Equal(["flag_reviewed", "flag_reopened"], reviews); // twice reviewed, written once
        Assert.True((await audit.VerifyAsync(Ct)).Ok);
    }

    [Fact]
    public async Task ReviewNeedsAFlaggedEventAndTheToken()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, csrf) = await host.SignedInAsync(Ct);
        var timeline = await GetAsync(client, "/api/v1/sessions/s-c1");
        var plain = timeline.GetProperty("events")[0].GetProperty("eventId").GetString()!;
        using (var r = await PostAsync(client, csrf, $"/api/v1/flags/{plain}/review"))
        {
            Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
        }
        using (var r = await PostAsync(client, csrf, "/api/v1/flags/no-such-event/review"))
        {
            Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
        }
        using (var r = await client.PostAsync($"/api/v1/flags/{plain}/review", null, Ct))
        {
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        }
        using var anonymous = host.NewClient();
        using (var r = await anonymous.GetAsync($"/api/v1/flags?{All}", Ct))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        }
    }

    [Fact]
    public async Task SessionsListAndTimelineWithChildSession()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        var list = await GetAsync(client, $"/api/v1/sessions?{All}");
        Assert.Equal(["s-c1", "s-b2", "s-b1"], Names(list.GetProperty("items"), "sessionId"));

        var b1 = await GetAsync(client, "/api/v1/sessions/s-b1");
        Assert.Equal("s-b1", b1.GetProperty("session").GetProperty("sessionId").GetString());
        var child = b1.GetProperty("children").EnumerateArray().Single();
        Assert.Equal(("s-b2", "s-b1"), (child.GetProperty("sessionId").GetString(), child.GetProperty("parentSessionId").GetString()));
        Assert.Equal(5, b1.GetProperty("events").GetArrayLength());
        Assert.Equal(["s-b1", "s-b1", "s-b1", "s-b2", "s-b2"], Names(b1.GetProperty("events"), "sessionId"));

        var c1 = await GetAsync(client, "/api/v1/sessions/s-c1");
        Assert.Equal(23, c1.GetProperty("events").GetArrayLength());
        var withInternal = await GetAsync(client, "/api/v1/sessions/s-c1?internal=true");
        Assert.Equal(24, withInternal.GetProperty("events").GetArrayLength());

        using var missing = await client.GetAsync("/api/v1/sessions/s-none", Ct);
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
    }

    [Fact]
    public async Task MetaShowsToolsAndDataRange()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        var m = await GetAsync(client, "/api/v1/meta");
        Assert.Equal(["CLI agent", "desktop_assistant"], Names(m.GetProperty("tools"), "displayName"));
        Assert.StartsWith("2026-11-11", m.GetProperty("data").GetProperty("from").GetString(), StringComparison.Ordinal);
        Assert.StartsWith("2026-11-17", m.GetProperty("data").GetProperty("to").GetString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/api/v1/overview?from=2026-11-01", "from")]
    [InlineData("/api/v1/overview?to=yesterday", "to")]
    [InlineData("/api/v1/overview?from=2026-11-10T00:00:00Z&to=2026-11-01T00:00:00Z", "range")]
    [InlineData("/api/v1/overview?from=2025-01-01T00:00:00Z&to=2026-11-01T00:00:00Z", "range")]
    [InlineData("/api/v1/overview?tool=secret_tool_name", "tool")]
    [InlineData("/api/v1/flags?status=everything", "status")]
    [InlineData("/api/v1/flags?severity=critical", "severity")]
    [InlineData("/api/v1/flags?after=-5", "after")]
    [InlineData("/api/v1/sessions?after=abc", "after")]
    [InlineData("/api/v1/sessions/s-c1?internal=maybe", "internal")]
    [InlineData("/api/v1/sessions/bad%20id", "sessionId")]
    public async Task BadArgumentsNameTheFieldNotTheValue(string url, string field)
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        using var r = await client.GetAsync(url, Ct);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        var body = await r.Content.ReadAsStringAsync(Ct);
        Assert.Equal([field], JsonElement.Parse(body).GetProperty("errors").EnumerateArray().Select(e => e.GetString()));
        foreach (var value in new[] { "secret_tool_name", "yesterday", "everything", "critical", "maybe", "abc" })
        {
            Assert.DoesNotContain(value, body, StringComparison.Ordinal);
        }
    }
}
