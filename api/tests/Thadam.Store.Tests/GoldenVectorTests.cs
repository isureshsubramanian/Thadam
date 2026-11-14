using System.Text.Json;

namespace Thadam.Store.Tests;

/// <summary>
/// The C# chain must match the Rust one. Both read
/// <c>crates/thadam-core/testdata/golden-chain.json</c>; the Rust side is
/// <c>crates/thadam-core/tests/golden_file.rs</c>.
/// </summary>
public sealed class GoldenVectorTests
{
    private static JsonElement File_() =>
        JsonElement.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "golden-chain.json")));

    private static string? S(JsonElement e, string k) => e.GetProperty(k).ValueKind == JsonValueKind.Null ? null : e.GetProperty(k).GetString();

    private static long? L(JsonElement e, string k) => e.GetProperty(k).ValueKind == JsonValueKind.Null ? null : e.GetProperty(k).GetInt64();

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    public void EventVectorsMatchTheRustImplementation(int version)
    {
        var f = File_().GetProperty($"event_v{version}");
        Assert.Equal(version == 2 ? Chain.EventDomain : Chain.EventDomainV3, f.GetProperty("domain").GetString());
        var prev = Chain.Genesis.ToArray();
        foreach (var v in f.GetProperty("rows").EnumerateArray())
        {
            var row = new EventRow(
                L(v, "seq")!.Value, S(v, "event_id")!, L(v, "ts_us")!.Value, S(v, "tool")!,
                S(v, "session_id"), S(v, "parent_session_id"), L(v, "pid")!.Value, S(v, "process_path")!,
                S(v, "category")!, S(v, "action")!, S(v, "target")!, S(v, "outcome")!,
                L(v, "size_bytes"), L(v, "bytes_out"), L(v, "bytes_in"), S(v, "project"),
                S(v, "flags")!, L(v, "count")!.Value, S(v, "detections")!, S(v, "source")!,
                version == 3 ? S(v, "agent_session_id") : null,
                version == 3 ? S(v, "transcript") : null);
            var h = Chain.EventHash(prev, row, version);
            Assert.Equal(S(v, "hash"), Chain.ToHex(h));
            prev = h;
        }
    }

    [Fact]
    public void CatalogVectorsMatchTheRustImplementation()
    {
        var f = File_().GetProperty("catalog_v1");
        Assert.Equal(Chain.CatalogDomain, f.GetProperty("domain").GetString());
        var prev = Chain.Genesis.ToArray();
        foreach (var v in f.GetProperty("rows").EnumerateArray())
        {
            var e = new CatalogEntry(
                L(v, "seq")!.Value, L(v, "at_us")!.Value, S(v, "kind")!, S(v, "segment"),
                L(v, "first_seq"), L(v, "last_seq"), S(v, "first_prev_hash"), S(v, "last_hash"),
                L(v, "last_ts_us"), L(v, "rows"), L(v, "bytes"), S(v, "reason"), S(v, "detail"),
                L(v, "from_us"), L(v, "to_us"), L(v, "missed"));
            var h = Chain.CatalogHash(prev, e);
            Assert.Equal(S(v, "hash"), Chain.ToHex(h));
            prev = h;
        }
    }

    [Theory]
    [InlineData("", null)]
    [InlineData(null, "")]
    [InlineData("agent-1", "text")]
    public void V2RejectsAgentFields(string? agentSessionId, string? transcript)
    {
        var row = new EventRow(1, "e", 1, "tool-a", null, null, 1, "/bin/tool-a", "command", "exec", "x",
            "allowed", null, null, null, null, "", 1, "", "agent", agentSessionId, transcript);
        Assert.Throws<ArgumentException>(() => Chain.EventHash(Chain.Genesis.Span, row, 2));
    }

    [Fact]
    public void NullAndEmptyTextHashDifferently()
    {
        var a = new EventRow(1, "e", 1, "t", null, null, 1, "/p", "file", "read", "x", "allowed",
            null, null, null, null, "", 1, "", "os");
        var b = a with { Project = "" };
        Assert.NotEqual(Chain.ToHex(Chain.EventHash(Chain.Genesis.Span, a, 3)),
            Chain.ToHex(Chain.EventHash(Chain.Genesis.Span, a with { AgentSessionId = "" }, 3)));
        Assert.NotEqual(Chain.ToHex(Chain.EventHash(Chain.Genesis.Span, a, 3)),
            Chain.ToHex(Chain.EventHash(Chain.Genesis.Span, a with { Transcript = "" }, 3)));
        Assert.NotEqual(Chain.ToHex(Chain.EventHash(Chain.Genesis.Span, a, 2)), Chain.ToHex(Chain.EventHash(Chain.Genesis.Span, b, 2)));
    }
}
