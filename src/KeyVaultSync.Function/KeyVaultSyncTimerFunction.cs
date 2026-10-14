using KeyVaultSync.Runner;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace KeyVaultSync.Function;

/// <summary>Adapts an Azure Functions timer invocation to one shared synchronization cycle.</summary>
/// <param name="runner">Host-managed runner reused across invocations; it owns orchestration, not scheduling.</param>
/// <param name="logger">Worker logger that carries invocation scopes into the configured telemetry providers.</param>
/// <remarks>
/// The timer schedule comes from application settings. This wrapper only captures host binding metadata; the runner's
/// timer invocation handler owns the structured start/completion records (events 6000/6001), invocation trace tags,
/// and the mapping from aggregate run status to invocation outcome. The runner persists detailed pair and plan-item
/// results in the run-history blob. No automatic retry policy or per-object mutation logic is added here.
/// </remarks>
public sealed class KeyVaultSyncTimerFunction(RunnerApplication runner, ILogger<KeyVaultSyncTimerFunction> logger)
{
    private const string TimerScheduleSettingName = "KEYVAULTSYNC_TIMER_SCHEDULE";

    /// <summary>Runs one scheduled cycle, reporting partial work as a warning and failing the invocation on a run failure.</summary>
    /// <param name="timerInfo">Host-provided schedule metadata, including whether this invocation is past due.</param>
    /// <param name="functionContext">Invocation identity and cancellation supplied by the isolated worker.</param>
    /// <returns>A task completing when the shared runner and outcome reporting have finished.</returns>
    /// <exception cref="InvalidOperationException">The runner returned an aggregate Failed result.</exception>
    /// <exception cref="OperationCanceledException">The host cancelled the operation or the runner returned Cancelled.</exception>
    /// <remarks>
    /// <para>Each invocation logs one start record and exactly one completion record. The completion record carries the
    /// invocation outcome, RunId, aggregate run status, value-free counts, and the run-history blob URI. Other
    /// initialization, Azure, or persistence exceptions are logged once and propagate to the host. Partial and
    /// NoConfiguredPairs are not thrown as invocation failures; operators must still inspect warnings and run records.</para>
    /// <para>UseMonitor persists timer schedule tracking, not pair state. RunOnStartup disables an extra startup
    /// invocation, but a normally due or past-due schedule can still run when the host starts.</para>
    /// </remarks>
    [Function(nameof(KeyVaultSyncTimerFunction))]
    public async Task Run(
        [TimerTrigger("%KEYVAULTSYNC_TIMER_SCHEDULE%", RunOnStartup = false, UseMonitor = true)] TimerInfo timerInfo,
        FunctionContext functionContext)
    {
        var invocation = new TimerInvocationContext(
            nameof(KeyVaultSyncTimerFunction),
            functionContext.InvocationId,
            timerInfo.IsPastDue,
            timerInfo.ScheduleStatus?.Last,
            timerInfo.ScheduleStatus?.Next,
            timerInfo.ScheduleStatus?.LastUpdated,
            Environment.GetEnvironmentVariable(TimerScheduleSettingName));
        await TimerInvocationHandler.ExecuteAsync(
            logger,
            invocation,
            runner.ExecuteScheduledRunAsync,
            functionContext.CancellationToken);
    }
}