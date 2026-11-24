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

    private static async Task<HttpResponseMessage> PostJsonAsync(HttpClient client, string? csrf, string url, object body)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json"),
        };
        if (csrf is not null)
        {
            req.Headers.Add(ApiHost.CsrfHeader, csrf);
        }
        return await client.SendAsync(req, Ct);
    }

    [Fact]
    public async Task PagesHonourTheLimitAndCarryTheTotal()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);

        var first = await GetAsync(client, $"/api/v1/sessions?{All}&limit=2");
        Assert.Equal(["s-c1", "s-b2"], Names(first.GetProperty("items"), "sessionId"));
        Assert.Equal((3, false), (first.GetProperty("total").GetInt64(), first.GetProperty("totalCapped").GetBoolean()));
        var second = await GetAsync(client, $"/api/v1/sessions?{All}&limit=2&after={first.GetProperty("next").GetInt64()}");
        Assert.Equal(["s-b1"], Names(second.GetProperty("items"), "sessionId"));
        Assert.Equal(JsonValueKind.Null, second.GetProperty("next").ValueKind);

        var flags = await GetAsync(client, $"/api/v1/flags?{All}&limit=1");
        Assert.Equal(1, flags.GetProperty("items").GetArrayLength());
        Assert.Equal(5, flags.GetProperty("total").GetInt64());

        // The timeline counts on its first page only; later pages keep that total.
        var t1 = await GetAsync(client, "/api/v1/sessions/s-c1?limit=10");
        Assert.Equal((10, 23L), (t1.GetProperty("events").GetArrayLength(), t1.GetProperty("total").GetInt64()));
        var t2 = await GetAsync(client, $"/api/v1/sessions/s-c1?limit=10&after={t1.GetProperty("next").GetInt64()}");
        Assert.Equal(10, t2.GetProperty("events").GetArrayLength());
        Assert.Equal(JsonValueKind.Null, t2.GetProperty("total").ValueKind);
        Assert.Equal(24, (await GetAsync(client, "/api/v1/sessions/s-c1?internal=true")).GetProperty("total").GetInt64());

        // Pinned to the sample data's dates: without a range, search covers the last 7 days
        // from now, which the fixed sample data leaves behind as time passes.
        var search = await GetAsync(client, "/api/v1/events?q=" + Uri.EscapeDataString("session:s-b1 from:2026-10-01 to:2026-11-30") + "&limit=2");
        Assert.Equal(2, search.GetProperty("items").GetArrayLength());
        Assert.Equal(3, search.GetProperty("total").GetInt64());
        Assert.False(search.GetProperty("totalCapped").GetBoolean());
    }

    [Fact]
    public async Task GridFiltersMatchAnyColumnAndAreAuditedWithoutTheText()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        var audit = host.Service<Thadam.Audit.AuditLog>();
        var before = (await audit.EntriesAsync(Ct)).Count(e => e.Action == "search");

        Assert.Equal(["s-b2", "s-b1"], Names((await GetAsync(client, $"/api/v1/sessions?{All}&q=S-B")).GetProperty("items"), "sessionId"));
        Assert.Equal(["s-c1", "s-b2", "s-b1"], Names((await GetAsync(client, $"/api/v1/sessions?{All}&q=%20")).GetProperty("items"), "sessionId"));
        var flags = await GetAsync(client, $"/api/v1/flags?{All}&q=203.0.113.7");
        Assert.Equal(["unknown_host"], Names(flags.GetProperty("items"), "rule"));
        Assert.Equal(1, flags.GetProperty("total").GetInt64());

        var searches = (await audit.EntriesAsync(Ct)).Where(e => e.Action == "search").ToList();
        Assert.Equal(before + 2, searches.Count); // the blank filter is no filter, so no search
        Assert.All(searches, e => Assert.Equal("", e.TargetId));
    }

    [Fact]
    public async Task BulkReviewMarksEveryFlagOrNone()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, csrf) = await host.SignedInAsync(Ct);
        var open = Names((await GetAsync(client, $"/api/v1/flags?{All}")).GetProperty("items"), "eventId");
        var two = open[..2];

        var plain = (await GetAsync(client, "/api/v1/sessions/s-c1")).GetProperty("events")[0].GetProperty("eventId").GetString()!;
        using (var r = await PostJsonAsync(client, csrf, "/api/v1/flags/review", new { eventIds = new[] { two[0], plain } }))
        {
            Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
        }
        Assert.Equal(open, Names((await GetAsync(client, $"/api/v1/flags?{All}")).GetProperty("items"), "eventId"));

        using (var r = await PostJsonAsync(client, csrf, "/api/v1/flags/review", new { eventIds = two }))
        {
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            Assert.Equal(2, JsonElement.Parse(await r.Content.ReadAsStringAsync(Ct)).GetProperty("changed").GetInt32());
        }
        Assert.Equal(open[2..], Names((await GetAsync(client, $"/api/v1/flags?{All}")).GetProperty("items"), "eventId"));
        Assert.Equal(two.Order(StringComparer.Ordinal), Names((await GetAsync(client, $"/api/v1/flags?{All}&status=reviewed")).GetProperty("items"), "eventId").Order(StringComparer.Ordinal));

        using (var r = await PostJsonAsync(client, csrf, "/api/v1/flags/reopen", new { eventIds = two }))
        {
            Assert.Equal(2, JsonElement.Parse(await r.Content.ReadAsStringAsync(Ct)).GetProperty("changed").GetInt32());
        }
        Assert.Equal(open, Names((await GetAsync(client, $"/api/v1/flags?{All}")).GetProperty("items"), "eventId"));

        var audit = host.Service<Thadam.Audit.AuditLog>();
        var entries = await audit.EntriesAsync(Ct);
        Assert.Equal(["flag_reviewed", "flag_reopened"], entries.Where(e => e.TargetId == two[1]).Select(e => e.Action));
        Assert.Equal(["flag_reviewed"], entries.Where(e => e.TargetId == plain).Select(e => e.Action));
        Assert.Equal(["failed"], entries.Where(e => e.TargetId == plain).Select(e => e.Outcome));
        Assert.True((await audit.VerifyAsync(Ct)).Ok);
    }

    [Fact]
    public async Task BulkReviewChecksTheListAndTheToken()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, csrf) = await host.SignedInAsync(Ct);
        var id = Names((await GetAsync(client, $"/api/v1/flags?{All}")).GetProperty("items"), "eventId")[0];
        foreach (var body in new object[]
        {
            new { eventIds = Array.Empty<string>() },
            new { eventIds = new[] { id, id } },
            new { eventIds = Enumerable.Range(0, 51).Select(i => $"e-{i}").ToArray() },
            new { eventIds = new[] { "bad id" } },
            new { other = 1 },
        })
        {
            using var r = await PostJsonAsync(client, csrf, "/api/v1/flags/review", body);
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        }
        using var noToken = await PostJsonAsync(client, null, "/api/v1/flags/review", new { eventIds = new[] { id } });
        Assert.Equal(HttpStatusCode.BadRequest, noToken.StatusCode);
        Assert.Contains(id, Names((await GetAsync(client, $"/api/v1/flags?{All}")).GetProperty("items"), "eventId"));
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
    [InlineData("/api/v1/sessions?limit=0", "limit")]
    [InlineData("/api/v1/flags?limit=201", "limit")]
    [InlineData("/api/v1/sessions/s-c1?limit=abc", "limit")]
    [InlineData("/api/v1/events?q=read&limit=500", "limit")]
    [InlineData("/api/v1/sessions?q=a%01b", "q")]
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
