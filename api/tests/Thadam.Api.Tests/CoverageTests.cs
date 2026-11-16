using System.Net;
using System.Text.Json;
using Thadam.Store.Tests;

namespace Thadam.Api.Tests;

public sealed class CoverageTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task CoverageClipsSortsAndUnionsMachineWideWindows()
    {
        using var store = new CoverageStore();
        await store.CreateAsync(2, Ct);
        await store.AppendAsync("gap", "hooks_silent", "cli_agent", 28, 29, null, Ct);
        await using var host = await ApiTestHost.StartAsync(store.Path, Ct);
        using var anonymous = host.NewClient();
        using var denied = await anonymous.GetAsync("/api/v1/coverage", Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        var (client, _) = await host.SignedInAsync(Ct);
        using var response = await client.GetAsync("/api/v1/coverage?from=1970-01-01T00:00:10Z&to=1970-01-01T00:00:30Z&tool=cli_agent", Ct);
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));
        var body = doc.RootElement;
        Assert.Equal(15, body.GetProperty("notWatchedSeconds").GetInt64());
        var gaps = body.GetProperty("gaps").EnumerateArray().ToList();
        Assert.Equal(["not_running", "machine_off", "before_start", "paused", "dropped", "future_reason", "hooks_silent"], gaps.Select(g => g.GetProperty("reason").GetString()));
        Assert.StartsWith("1970-01-01T00:00:10", gaps[0].GetProperty("from").GetString(), StringComparison.Ordinal);
        Assert.StartsWith("1970-01-01T00:00:30", gaps[4].GetProperty("to").GetString(), StringComparison.Ordinal);
        Assert.Equal(9, gaps[3].GetProperty("missed").GetInt64());
        // Silent hooks leave the OS rows recorded, so they are not counted as unwatched time.
        Assert.Equal("cli_agent", gaps[6].GetProperty("detail").GetString());
    }

    [Theory]
    [InlineData("from=invalid", "from")]
    [InlineData("to=invalid", "to")]
    [InlineData("from=1970-01-02T00:00:00Z&to=1970-01-01T00:00:00Z", "range")]
    [InlineData("tool=unknown", "tool")]
    public async Task CoverageValidatesArguments(string query, string field)
    {
        using var store = new CoverageStore();
        await store.CreateAsync(2, Ct);
        await using var host = await ApiTestHost.StartAsync(store.Path, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        using var response = await client.GetAsync($"/api/v1/coverage?{query}", Ct);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));
        Assert.Equal([field], doc.RootElement.GetProperty("errors").EnumerateArray().Select(e => e.GetString()));
    }
}
