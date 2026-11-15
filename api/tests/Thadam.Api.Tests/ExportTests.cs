using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using Thadam.Api.Export;
using Thadam.Store.Queries;
using Thadam.Store.Tests;

namespace Thadam.Api.Tests;

/// <summary>ADR-012 tests over the Rust fixture (kept rows seq 5-33; see <see cref="QueryTests"/>).</summary>
[Collection(ApiFixtureDefinition.Name)]
public sealed class ExportTests(StoreFixture store)
{
    private const string Range = "from:2026-10-01 to:2026-11-30";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static Task<HttpResponseMessage> ExportAsync(HttpClient client, string query) =>
        client.GetAsync("/api/v1/export?" + query, Ct);

    private static string Q(string q) => "q=" + Uri.EscapeDataString(q);

    /// <summary>The body as text after its BOM, which must be there.</summary>
    private static async Task<string> CsvAsync(HttpResponseMessage r)
    {
        var bytes = await r.Content.ReadAsByteArrayAsync(Ct);
        Assert.True(bytes.AsSpan().StartsWith(CsvExport.Bom), "missing BOM");
        return Encoding.UTF8.GetString(bytes.AsSpan(CsvExport.Bom.Length));
    }

    private static long[] Seqs(string csv) =>
        [.. csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Skip(1).Select(l => long.Parse(l[..l.IndexOf(',', StringComparison.Ordinal)], System.Globalization.CultureInfo.InvariantCulture))];

    [Fact]
    public async Task ASearchExportsItsRowsOldestFirstAndIsAuditedWithoutTheQuery()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        using var r = await ExportAsync(client, Q($"session:s-b1 {Range}"));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal("text/csv", r.Content.Headers.ContentType?.MediaType);
        Assert.Equal("utf-8", r.Content.Headers.ContentType?.CharSet);
        Assert.Matches(@"^thadam-export-\d{8}T\d{4}Z-s\d+\.csv$", r.Content.Headers.ContentDisposition?.FileName?.Trim('"'));
        Assert.Equal("attachment", r.Content.Headers.ContentDisposition?.DispositionType);
        Assert.Equal("no-store", r.Headers.CacheControl?.ToString());
        var exportId = Assert.Single(r.Headers.GetValues("X-Thadam-Export-Id"));
        Assert.True(Guid.TryParse(exportId, out var id) && id.Version == 7);

        var csv = await CsvAsync(r);
        Assert.StartsWith(string.Join(',', CsvExport.Columns) + "\r\n", csv, StringComparison.Ordinal);
        Assert.Equal([5L, 6L, 7L], Seqs(csv));
        Assert.DoesNotContain("\n", csv.Replace("\r\n", "", StringComparison.Ordinal), StringComparison.Ordinal);
        Assert.Contains(",CLI agent,", csv, StringComparison.Ordinal);

        var last = (await host.Service<Thadam.Audit.AuditLog>().EntriesAsync(Ct))[^1];
        Assert.Equal(("export", "succeeded", exportId), (last.Action, last.Outcome, last.TargetId));
        var audit = await File.ReadAllBytesAsync(host.Options.AuditPath, Ct);
        Assert.Equal(-1, audit.AsSpan().IndexOf("s-b1"u8));
    }

    [Fact]
    public async Task ATimelineExportHasExactlyTheTimelinesRows()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        foreach (var include in new[] { "true", "false" })
        {
            using var t = await client.GetAsync($"/api/v1/sessions/s-b1?internal={include}", Ct);
            var timeline = JsonElement.Parse(await t.Content.ReadAsStringAsync(Ct));
            var expected = timeline.GetProperty("events").EnumerateArray().Select(e => e.GetProperty("seq").GetInt64()).ToArray();
            using var r = await ExportAsync(client, $"session=s-b1&internal={include}");
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            Assert.Equal(expected, Seqs(await CsvAsync(r)));
        }
    }

    [Theory]
    [InlineData("", "q")]
    [InlineData("q=main.rs&session=s-b1", "q")]
    [InlineData("q=main.rs&internal=true", "internal")]
    [InlineData("session=s-b1&internal=yes", "internal")]
    [InlineData("session=bad%20id", "session")]
    public async Task BadArgumentsNameTheFieldAndAreAuditedAsFailed(string query, string field)
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        using var r = await ExportAsync(client, query);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Contains(field, await r.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
        var last = (await host.Service<Thadam.Audit.AuditLog>().EntriesAsync(Ct))[^1];
        Assert.Equal(("export", "failed"), (last.Action, last.Outcome));
    }

    [Fact]
    public async Task ABadSearchFieldIsNamedNotEchoed()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        var (client, _) = await host.SignedInAsync(Ct);
        using var r = await ExportAsync(client, Q("colour:secret_value"));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.DoesNotContain("secret_value", await r.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
        using var missing = await ExportAsync(client, "session=no-such-session");
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
    }

    [Fact]
    public async Task SignedOutGets401()
    {
        await using var host = await ApiTestHost.StartAsync(store, Ct);
        using var r = await ExportAsync(host.Client, Q("main.rs"));
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact]
    public async Task OverTheLimitIsRefusedWholeNotCutShort()
    {
        await using var host = await ApiTestHost.StartAsync(store.Folder, Ct, exportMaxRows: 2);
        var (client, _) = await host.SignedInAsync(Ct);
        using var r = await ExportAsync(client, Q($"session:s-b1 {Range}"));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, r.StatusCode);
        var body = JsonElement.Parse(await r.Content.ReadAsStringAsync(Ct));
        Assert.Equal((3, 2), (body.GetProperty("rows").GetInt64(), body.GetProperty("limit").GetInt32()));
        var last = (await host.Service<Thadam.Audit.AuditLog>().EntriesAsync(Ct))[^1];
        Assert.Equal(("export", "denied"), (last.Action, last.Outcome));
    }

    private static EventView Row(string target, string? project = null) => new(
        42, "0190f1a2-0000-7000-8000-000000000042", 1_763_000_000_123_456, "cli_agent", "s-1", null, 4100,
        "/Users/dev/bin/cli-agent", "command", "exec", target, "denied_by_user", null, null, null, project,
        new HashSet<string>(StringComparer.Ordinal) { "unconfirmed", "outside_project" }, 1,
        new Dictionary<string, long>(StringComparer.Ordinal) { ["SECRET"] = 2, ["EMAIL"] = 1 },
        "agent", Severity.Medium, "denied", "a-51c2", null);

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    [InlineData("two\nlines", "\"two\nlines\"")]
    [InlineData("=HYPERLINK(\"x\")", "\"'=HYPERLINK(\"\"x\"\")\"")]
    [InlineData("+1", "'+1")]
    [InlineData("-rf build/", "'-rf build/")]
    [InlineData("@SUM(A1)", "'@SUM(A1)")]
    [InlineData("\tx", "'\tx")]
    [InlineData("\rx", "\"'\rx\"")]
    [InlineData("பாதை/ファイル", "பாதை/ファイル")]
    public void TextCellsAreQuotedAndGuarded(string value, string cell) =>
        Assert.Equal(cell, CsvExport.Quote(CsvExport.Text(value)));

    [Fact]
    public void ALineFollowsTheContract()
    {
        var line = CsvExport.Line(new ExportRow(Row("rm -rf build/, now"), new string('a', 64)), _ => "CLI agent");
        Assert.Equal(
            "42,0190f1a2-0000-7000-8000-000000000042,2025-11-13T02:13:20.123456Z,cli_agent,CLI agent,s-1,,4100,"
            + "/Users/dev/bin/cli-agent,command,exec,\"rm -rf build/, now\",denied_by_user,,,,,"
            + "outside_project;unconfirmed,1,EMAIL=1;SECRET=2,agent,medium,denied,a-51c2,," + new string('a', 64) + "\r\n",
            line);
        Assert.Equal(CsvExport.Columns.Count, CsvExport.Columns.Distinct().Count());
    }

    [Fact]
    public void AnIndependentCsvReaderSeesTheSameCells()
    {
        var rows = new[] { Row("a,\"b\"\r\nc"), Row("=cmd", "/Users/dev/projects/பாதை") };
        var csv = CsvExport.HeaderLine() + string.Concat(rows.Select(r => CsvExport.Line(new ExportRow(r, new string('b', 64)), k => k)));
        const string script = """
            import csv, io, json, sys
            data = sys.stdin.buffer.read().decode("utf-8")
            print(json.dumps(list(csv.reader(io.StringIO(data, newline="")))))
            """;
        ProcessStartInfo start = new("python3") { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false };
        start.ArgumentList.Add("-I");
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add(script);
        Process p;
        try
        {
            p = Process.Start(start)!;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return; // no Python here: the golden line test still holds
        }
        using (p)
        {
            p.StandardInput.Write(csv);
            p.StandardInput.Close();
            var parsed = JsonSerializer.Deserialize<string[][]>(p.StandardOutput.ReadToEnd())!;
            p.WaitForExit();
            Assert.Equal(CsvExport.Columns, parsed[0]);
            Assert.Equal("a,\"b\"\r\nc", parsed[1][11]);
            Assert.Equal("'=cmd", parsed[2][11]);
            Assert.Equal("/Users/dev/projects/பாதை", parsed[2][16]);
            Assert.All(parsed, row => Assert.Equal(CsvExport.Columns.Count, row.Length));
        }
    }
}
