using System.Diagnostics;
using System.Net;

namespace Thadam.Api.Tests;

/// <summary>
/// Times the Overview for the last 7 and 28 days on the synthetic 5 million row store (see
/// <see cref="SearchBenchmark"/>). Runs only when <c>THADAM_BENCH_STORE</c> is set; it prints
/// the figures and asserts nothing about them.
/// </summary>
public sealed class OverviewBenchmark
{
    [Fact]
    public async Task OverviewTimes()
    {
        var folder = Environment.GetEnvironmentVariable("THADAM_BENCH_STORE");
        Assert.SkipWhen(string.IsNullOrEmpty(folder), "THADAM_BENCH_STORE not set");
        var ct = TestContext.Current.CancellationToken;
        await using var host = await ApiTestHost.StartAsync(folder!, ct);
        var (client, _) = await host.SignedInAsync(ct);
        var to = DateTimeOffset.UtcNow;
        foreach (var days in new[] { 7, 28 })
        {
            var url = $"/api/v1/overview?from={to.AddDays(-days):yyyy-MM-ddTHH:mm:ssZ}&to={to:yyyy-MM-ddTHH:mm:ssZ}";
            var times = new List<int>();
            for (var i = 0; i < 3; i++)
            {
                var sw = Stopwatch.StartNew();
                using var r = await client.GetAsync(url, ct);
                await r.Content.ReadAsStringAsync(ct);
                sw.Stop();
                Assert.Equal(HttpStatusCode.OK, r.StatusCode);
                times.Add((int)sw.Elapsed.TotalMilliseconds);
            }
            await Console.Error.WriteLineAsync($"overview {days}d times (ms): {string.Join(", ", times)}".AsMemory(), ct);
        }
    }
}
