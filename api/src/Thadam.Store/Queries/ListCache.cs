namespace Thadam.Store.Queries;

/// <summary>
/// The grouped Sessions and Flagged lists, kept between pages (ADR-016). An entry is brought up
/// to date by folding in only the rows written after it was built, so it always equals a full
/// rebuild. Hidden coupling: that holds only while store rows are never changed or removed
/// except by dropping whole segments, and <c>seq</c> only grows (the append-only triggers in
/// crates/thadam-store/src/schema.rs). If either changes, these lists go wrong silently.
/// </summary>
internal sealed class ListCache<TState>(TimeProvider time, int maxGroups = ListCache<TState>.MaxGroups) where TState : class
{
    /// <summary>Lists kept per kind, least recently used dropped first (ADR-016 Decision 3).</summary>
    public const int MaxEntries = 4;
    /// <summary>A larger list is built per page instead of kept (Decision 3: 209,389 measured, plus headroom).</summary>
    public const int MaxGroups = 250_000;
    /// <summary>An entry unused this long is dropped (Decision 3, an estimate).</summary>
    public static readonly TimeSpan Idle = TimeSpan.FromMinutes(10);

    /// <summary>The size bound this cache keeps to (smaller in tests).</summary>
    public int KeepUpTo => maxGroups;

    private readonly Lock _gate = new();
    private readonly Dictionary<Filter, Entry> _entries = [];

    /// <summary>One cached list. Read and changed only while holding <see cref="Turn"/>.</summary>
    internal sealed class Entry
    {
        public SemaphoreSlim Turn { get; } = new(1, 1);
        public TState? State { get; set; }
        /// <summary>The highest seq folded in.</summary>
        public long UpTo { get; set; }
        /// <summary>The kept segments when it was built; any change means a rebuild.</summary>
        public string Segments { get; set; } = "";
        public DateTimeOffset Used { get; set; }
    }

    /// <summary>The entry for <paramref name="key"/>, created empty when there is none.</summary>
    public Entry Get(Filter key)
    {
        var now = time.GetUtcNow();
        lock (_gate)
        {
            foreach (var idle in _entries.Where(e => now - e.Value.Used > Idle).Select(e => e.Key).ToList())
            {
                _entries.Remove(idle);
            }
            if (!_entries.TryGetValue(key, out var entry))
            {
                if (_entries.Count >= MaxEntries)
                {
                    _entries.Remove(_entries.MinBy(e => e.Value.Used).Key);
                }
                _entries[key] = entry = new Entry();
            }
            entry.Used = now;
            return entry;
        }
    }

    /// <summary>Stops keeping <paramref name="entry"/> (over <see cref="MaxGroups"/>).</summary>
    public void Drop(Filter key, Entry entry)
    {
        lock (_gate)
        {
            if (_entries.TryGetValue(key, out var kept) && kept == entry)
            {
                _entries.Remove(key);
            }
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _entries.Clear();
        }
    }

    internal int Count
    {
        get
        {
            lock (_gate)
            {
                return _entries.Count;
            }
        }
    }
}
