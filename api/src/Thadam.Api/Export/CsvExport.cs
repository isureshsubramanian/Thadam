using System.Globalization;
using System.Text;
using Thadam.Store.Queries;

namespace Thadam.Api.Export;

/// <summary>
/// The <c>thadam.export.v1</c> CSV format (ADR-012 Decisions 2 and 3): a fixed header, RFC 4180
/// quoting, CRLF line ends, UTF-8 with a BOM, and the spreadsheet-formula guard on text cells.
/// </summary>
public static class CsvExport
{
    public const string Contract = "thadam.export.v1";

    /// <summary>Most rows one export holds (ADR-012 Decision 4: about 65 MB, an estimate).</summary>
    public const int MaxRows = 100_000;

    /// <summary>The header, in contract order. A change here is a new contract version.</summary>
    public static readonly IReadOnlyList<string> Columns =
    [
        "seq", "event_id", "ts", "tool", "tool_name", "session_id", "parent_session_id", "pid", "process_path",
        "category", "action", "target", "outcome", "size_bytes", "bytes_out", "bytes_in", "project", "flags", "count",
        "detections", "source", "severity", "rule", "agent_session_id", "transcript", "hash",
    ];

    /// <summary>The bytes a file starts with, so spreadsheets read it as UTF-8.</summary>
    public static ReadOnlySpan<byte> Bom => [0xEF, 0xBB, 0xBF];

    /// <summary>Encoding for the rows; the BOM is written once, by the caller, from <see cref="Bom"/>.</summary>
    public static readonly Encoding Utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    public static string HeaderLine() => string.Join(',', Columns) + "\r\n";

    public static string Line(ExportRow row, Func<string, string> toolName)
    {
        ArgumentNullException.ThrowIfNull(row);
        ArgumentNullException.ThrowIfNull(toolName);
        var e = row.Event;
        string?[] cells =
        [
            Number(e.Seq), Text(e.EventId), Values.Time(e.TsUs), Text(e.Tool), Text(toolName(e.Tool)),
            Text(e.SessionId), Text(e.ParentSessionId), Number(e.Pid), Text(e.ProcessPath),
            Text(e.Category), Text(e.Action), Text(e.Target), Text(e.Outcome),
            Number(e.SizeBytes), Number(e.BytesOut), Number(e.BytesIn), Text(e.Project),
            Text(string.Join(';', e.Flags.Order(StringComparer.Ordinal))), Number(e.Count),
            Text(string.Join(';', e.Detections.OrderBy(d => d.Key, StringComparer.Ordinal).Select(d => $"{d.Key}={d.Value}"))),
            Text(e.Source), Text(e.Severity is { } s ? SeverityRule.WireName(s) : null), Text(e.Rule),
            Text(e.AgentSessionId), Text(e.Transcript), row.Hash,
        ];
        return string.Join(',', cells.Select(Quote)) + "\r\n";
    }

    /// <summary>
    /// A text cell with the formula guard (OWASP CSV injection): a leading <c>=</c>, <c>+</c>,
    /// <c>-</c>, <c>@</c>, tab or carriage return gets a <c>'</c> in front, so a spreadsheet shows
    /// the text instead of running it. Numbers, times and hashes never pass through here.
    /// </summary>
    internal static string? Text(string? value) =>
        value is { Length: > 0 } && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r' ? "'" + value : value;

    private static string Number(long? n) => n?.ToString(CultureInfo.InvariantCulture) ?? "";

    /// <summary>RFC 4180: quote a cell holding a comma, quote, CR or LF; double its quotes.</summary>
    internal static string Quote(string? cell) =>
        cell is null ? ""
        : cell.AsSpan().IndexOfAny(",\"\r\n") >= 0 ? "\"" + cell.Replace("\"", "\"\"", StringComparison.Ordinal) + "\""
        : cell;
}
