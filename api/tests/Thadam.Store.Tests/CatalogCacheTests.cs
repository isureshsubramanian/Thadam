namespace Thadam.Store.Tests;

/// <summary>Queries read only new catalog entries, and never trust a catalog that changed under them.</summary>
public sealed class CatalogCacheTests : IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private readonly CoverageStore store = new();

    [Fact]
    public async Task NewEntriesAreReadAndCheckedAsTheFullReadDoes()
    {
        await store.CreateAsync(2, Ct);
        var folder = store.Folder;
        var first = await folder.CatalogAsync(Ct);
        Assert.Equal(6, first.Entries.Count);
        Assert.Same(first, await folder.CatalogAsync(Ct));

        await store.AppendAsync("gap", "dropped", "agent", 50, 60, 4, Ct);
        var more = await folder.CatalogAsync(Ct);
        Assert.Equal(7, more.Entries.Count);
        Assert.Null(more.BrokenAt);
        Assert.Equal((await folder.ReadCatalogAsync(Ct)).Entries, more.Entries);
        Assert.Equal(6, first.Entries.Count);
    }

    [Fact]
    public async Task ABrokenNewEntryIsReported()
    {
        await store.CreateAsync(2, Ct);
        var folder = store.Folder;
        await folder.CatalogAsync(Ct);
        await store.AppendAsync("gap", "dropped", "agent", 50, 60, 4, Ct);
        await store.ExecAsync("UPDATE catalog SET missed = 99 WHERE seq = 7", Ct);
        var read = await folder.CatalogAsync(Ct);
        Assert.Equal(7, read.BrokenAt);
        Assert.Equal(6, read.Entries.Count);
    }

    [Fact]
    public async Task AChangedLastEntryMeansAFullReadAgain()
    {
        await store.CreateAsync(2, Ct);
        var folder = store.Folder;
        await folder.CatalogAsync(Ct);
        // An earlier entry changed: only the full walk can find it, so the last entry's hash is
        // rewritten too, as a forger would have to, and the cache must not take it on trust.
        await store.ExecAsync("UPDATE catalog SET missed = 99 WHERE seq = 1", Ct);
        await store.ExecAsync("UPDATE catalog SET hash = zeroblob(32) WHERE seq = 6", Ct);
        Assert.Equal(1, (await folder.CatalogAsync(Ct)).BrokenAt);
    }

    public void Dispose() => store.Dispose();
}
