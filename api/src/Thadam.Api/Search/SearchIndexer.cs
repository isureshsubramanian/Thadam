using Thadam.Store.Queries;

namespace Thadam.Api.Search;

/// <summary>
/// Keeps <see cref="SearchIndex"/> current: the first pass at start builds it (a missing
/// file was created empty), then new rows every 5 seconds (ADR-008 Decision 5, an
/// estimate). Rows not yet indexed are still found: the search scans them.
/// </summary>
public sealed partial class SearchIndexer(SearchIndex index, SegmentIndex segments, ILogger<SearchIndexer> log) : BackgroundService
{
    public static readonly TimeSpan Every = TimeSpan.FromSeconds(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Every);
        do
        {
            try
            {
                await index.TailAsync(segments, stoppingToken).ConfigureAwait(false);
            }
            catch (Exception e) when (e is Microsoft.Data.Sqlite.SqliteException or IOException or Thadam.Store.StoreLayoutException)
            {
                // The type only: messages can carry paths.
                LogFailed(log, e.GetType().Name);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "search index update failed: {Kind}")]
    private static partial void LogFailed(ILogger log, string kind);
}
