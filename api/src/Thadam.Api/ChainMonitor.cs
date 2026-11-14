using Thadam.Store;

namespace Thadam.Api;

/// <summary>
/// Keeps the header's chain status current (ADR-008 Decision 8): a full walk at start-up,
/// then new rows once a minute. On a break it logs one line with the segment and seq only.
/// </summary>
public sealed partial class ChainMonitor(StoreFolder folder, ILogger<ChainMonitor> log) : BackgroundService
{
    private static readonly TimeSpan Every = TimeSpan.FromMinutes(1);
    private readonly ChainVerifier _verifier = new(folder);
    private volatile ChainState _state = ChainState.Pending;

    public ChainState State => _state;

    /// <summary>Runs one verification now (start-up, tests).</summary>
    public async Task<ChainState> CheckAsync(CancellationToken ct)
    {
        ChainState next;
        try
        {
            var status = await _verifier.VerifyAsync(ct).ConfigureAwait(false);
            next = new ChainState(status, null);
            if (status.Broken is { } b && _state.Status?.Broken != b)
            {
                LogBroken(log, b.Kind, b.Segment ?? "-", b.Seq ?? 0);
            }
        }
        catch (Exception e) when (e is StoreLayoutException or Microsoft.Data.Sqlite.SqliteException or IOException)
        {
            // The type only: messages can carry paths.
            next = new ChainState(null, e.GetType().Name);
            LogUnreadable(log, e.GetType().Name);
        }
        _state = next;
        return next;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Every);
        do
        {
            await CheckAsync(stoppingToken).ConfigureAwait(false);
        }
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "chain broken: {Kind} in {Segment} at seq {Seq}")]
    private static partial void LogBroken(ILogger logger, ChainBreakKind kind, string segment, long seq);

    [LoggerMessage(Level = LogLevel.Warning, Message = "store not readable: {Error}")]
    private static partial void LogUnreadable(ILogger logger, string error);
}

/// <summary>The last check: a status, or why the store could not be read, or not yet run.</summary>
public sealed record ChainState(ChainStatus? Status, string? Error)
{
    public static ChainState Pending { get; } = new(null, null);
}
