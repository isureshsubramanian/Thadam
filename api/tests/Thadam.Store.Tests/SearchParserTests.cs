using Thadam.Store.Search;

namespace Thadam.Store.Tests;

public sealed class SearchParserTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 15, 12, 0, 0, TimeSpan.Zero);

    private static string? Tools(string name) => name switch
    {
        "cli_agent" or "CLI agent" => "cli_agent",
        _ => null,
    };

    private static SearchQuery Ok(string q)
    {
        var (query, error) = SearchParser.Parse(q, Tools, Now);
        Assert.Null(error);
        return query!;
    }

    private static string Fails(string q)
    {
        var (query, error) = SearchParser.Parse(q, Tools, Now);
        Assert.Null(query);
        return error!.Field;
    }

    [Fact]
    public void ParsesTheMockUpQuery()
    {
        var q = Ok("tool:\"CLI agent\" outside:sample-app since:7d");
        Assert.Equal("cli_agent", q.Tool);
        Assert.Equal("sample-app", q.Outside);
        Assert.Empty(q.Text);
        Assert.Equal(7L * 86_400_000_000, q.Range!.Value.ToUs - q.Range.Value.FromUs);
    }

    [Fact]
    public void FreeTextWordsAndPhrases()
    {
        var q = Ok("main.rs \"two words\" ab");
        Assert.Equal(["main.rs", "two words", "ab"], q.Text);
        Assert.Equal(["main.rs", "two words"], q.IndexedText);
        Assert.Equal(["ab"], q.ScannedText);
    }

    [Fact]
    public void TextTheIndexCanAnswerSearchesEverything()
    {
        Assert.Null(Ok("main.rs").Range);
    }

    [Fact]
    public void OtherwiseTheScanIsBoundedToAWeek()
    {
        foreach (var q in new[] { "ab", "category:file", "flag:unknown-host" })
        {
            var r = Ok(q).Range!.Value;
            Assert.Equal(SearchParser.DefaultScanDays * 86_400_000_000L, r.ToUs - r.FromUs);
        }
    }

    [Fact]
    public void FixedSetsAcceptHyphensAndTheDeniedShorthand()
    {
        var q = Ok("category:network-external flag:unknown-host flag:large_upload outcome:denied action:connect");
        Assert.Equal("network_external", q.Category);
        Assert.Equal(["unknown_host", "large_upload"], q.Flags);
        Assert.Equal(["denied_by_agent", "denied_by_user", "denied_by_os", "never_ran"], q.Outcomes);
        Assert.Equal("connect", q.Action);
    }

    [Fact]
    public void DatesAndTimes()
    {
        var r = Ok("from:2026-11-01 to:2026-11-14").Range!.Value;
        Assert.Equal(new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero), DateTimeOffset.UnixEpoch.AddTicks(r.FromUs * 10));
        Assert.Equal(new DateTimeOffset(2026, 11, 15, 0, 0, 0, TimeSpan.Zero), DateTimeOffset.UnixEpoch.AddTicks((r.ToUs + 1) * 10));
        Assert.NotNull(Ok("from:2026-11-01T08:00:00+05:30").Range);
        Assert.NotNull(Ok("since:24h").Range);
    }

    [Theory]
    [InlineData("", "q")]
    [InlineData("   ", "q")]
    [InlineData("\"not closed", "q")]
    [InlineData("colour:blue", "q.unknown")]
    [InlineData("https://example.test/x", "q.unknown")]
    [InlineData("tool:unknown_tool", "q.tool")]
    [InlineData("tool:cli_agent tool:cli_agent", "q.tool")]
    [InlineData("category:everything", "q.category")]
    [InlineData("outcome:maybe", "q.outcome")]
    [InlineData("flag:pretty", "q.flag")]
    [InlineData("session:a;b", "q.session")]
    [InlineData("since:400d", "q.since")]
    [InlineData("since:0d", "q.since")]
    [InlineData("since:week", "q.since")]
    [InlineData("since:7d from:2026-11-01", "q.since")]
    [InlineData("from:yesterday", "q.from")]
    [InlineData("to:2026-13-01", "q.to")]
    [InlineData("from:2026-11-10 to:2026-11-01", "q.range")]
    [InlineData("from:2024-01-01 to:2026-11-01", "q.range")]
    [InlineData("project:a outside:b", "q.outside")]
    [InlineData("host:", "q.host")]
    public void RejectsWithTheFieldName(string q, string field) => Assert.Equal(field, Fails(q));

    [Fact]
    public void RejectsOverLongAndTooManyTerms()
    {
        Assert.Equal("q", Fails(new string('a', SearchParser.MaxLength + 1)));
        Assert.Equal("q", Fails(string.Join(' ', Enumerable.Repeat("abc", SearchParser.MaxTerms + 1))));
    }

    [Fact]
    public void FtsOperatorsInUserTextAreQuoted()
    {
        Assert.Equal("\"a OR b\" AND \"x\"\"y\" AND \"NEAR(c)\"", SearchParser.FtsQuery(["a OR b", "x\"y", "NEAR(c)"]));
    }

    [Fact]
    public void LikeWildcardsAreEscaped()
    {
        Assert.Equal("%100\\%\\_done\\\\x%", SearchParser.LikeContains("100%_done\\x"));
    }
}
