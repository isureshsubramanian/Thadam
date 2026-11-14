using System.Data.Common;

namespace Thadam.Store.Queries;

/// <summary>
/// One host's rows added up across segments. Its "unknown" follows the newest row, which was
/// classified with the registry in force when it was written, not any row: a host listed as
/// known later stops showing as unknown, while <see cref="Flagged"/> keeps the older flags visible.
/// </summary>
internal sealed class HostTally
{
    /// <summary>
    /// The aggregate columns, in this order: flows, bytes out, bytes in, newest seq, newest row
    /// unknown, flagged flows. Relies on SQLite's rule that with exactly one min()/max() in a
    /// select, plain columns come from the row holding it: keep max(seq) the only one.
    /// </summary>
    public const string Columns = """
        sum(count), sum(coalesce(bytes_out, 0)), sum(coalesce(bytes_in, 0)),
        max(seq), instr(',' || flags || ',', ',unknown_host,') > 0,
        sum(CASE WHEN instr(',' || flags || ',', ',unknown_host,') > 0 THEN count ELSE 0 END)
        """;

    private long _newestSeq = -1;

    public long Flows { get; private set; }

    public long BytesOut { get; private set; }

    public long BytesIn { get; private set; }

    public bool Unknown { get; private set; }

    public long Flagged { get; private set; }

    /// <summary>Adds one segment's group, read from <see cref="Columns"/> starting at <paramref name="at"/>.</summary>
    public void Add(DbDataReader r, int at)
    {
        ArgumentNullException.ThrowIfNull(r);
        Flows += r.GetInt64(at);
        BytesOut += r.GetInt64(at + 1);
        BytesIn += r.GetInt64(at + 2);
        var seq = r.GetInt64(at + 3);
        if (seq > _newestSeq)
        {
            _newestSeq = seq;
            Unknown = r.GetInt64(at + 4) != 0;
        }
        Flagged += r.GetInt64(at + 5);
    }

    public HostStats ToStats(string target, string category) =>
        new(target, category, Flows, BytesOut, BytesIn, Unknown, Flagged);
}
