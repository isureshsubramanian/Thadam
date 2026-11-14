using System.Diagnostics;
using System.Net;

namespace Thadam.Api.Tests;

/// <summary>
/// ADR-008 acceptance test 6: on a generated synthetic store of 5 million rows,
/// <c>tool:X outside:Y since:7d</c> with its hosts returns in under 2 s. Runs only when
/// <c>THADAM_BENCH_STORE</c> names a folder written by
/// <c>cargo run --release -p thadam-store --example bench_store -- &lt;folder&gt;</c>;
/// otherwise skipped, so the gate stays fast.
/// </summary>
public sealed class SearchBenchmark
{
    private static readonly TimeSpan Target = TimeSpan.FromSeconds(2);

    [Fact]
    public async Task OutsideProjectSearchWithHostsIsUnderTwoSeconds()
    {
        var folder = Environment.GetEnvironmentVariable("THADAM_BENCH_STORE");
        Assert.SkipWhen(string.IsNullOrEmpty(folder), "THADAM_BENCH_STORE not set");
        var ct = TestContext.Current.CancellationToken;
        await using var host = await ApiTestHost.StartAsync(folder!, ct);
        var (client, _) = await host.SignedInAsync(ct);
        var url = "/api/v1/events?q=" + Uri.EscapeDataString("tool:cli_agent outside:project-2 since:7d");
        var times = new List<TimeSpan>();
        for (var i = 0; i < 3; i++)
        {
            var sw = Stopwatch.StartNew();
            using var r = await client.GetAsync(url, ct);
            var body = await r.Content.ReadAsStringAsync(ct);
            sw.Stop();
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            Assert.Contains("\"hosts\":[{", body, StringComparison.Ordinal);
            times.Add(sw.Elapsed);
        }
        var line = $"search times (ms): {string.Join(", ", times.Select(t => (int)t.TotalMilliseconds))}";
        TestContext.Current.TestOutputHelper?.WriteLine(line);
        // The benchmark is run by hand: the figure goes to the terminal too.
        await Console.Error.WriteLineAsync(line.AsMemory(), ct);
        Assert.All(times, t => Assert.True(t < Target, $"{t.TotalMilliseconds:F0} ms"));
    }
}
