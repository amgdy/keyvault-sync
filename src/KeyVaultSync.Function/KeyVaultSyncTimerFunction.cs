using KeyVaultSync.Runner;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace KeyVaultSync.Function;

/// <summary>Adapts an Azure Functions timer invocation to one shared synchronization cycle.</summary>
/// <param name="runner">Host-managed runner reused across invocations; it owns orchestration, not scheduling.</param>
/// <param name="logger">Worker logger that carries invocation scopes into the configured telemetry providers.</param>
/// <remarks>
/// The timer schedule comes from application settings. This wrapper reports aggregate outcomes while the
/// runner persists detailed pair/secret results. It adds no automatic retry policy or per-object mutation logic.
/// </remarks>
public sealed class KeyVaultSyncTimerFunction(RunnerApplication runner, ILogger<KeyVaultSyncTimerFunction> logger)
{
    private static readonly EventId TimerInvocationStartedEventId = new(6000, "TimerInvocationStarted");
    private static readonly EventId TimerInvocationCompletedEventId = new(6001, "TimerInvocationCompleted");

    /// <summary>Runs one scheduled cycle, reporting partial work as a warning and failing the invocation on a run failure.</summary>
    /// <param name="timerInfo">Host-provided schedule metadata, including whether this invocation is past due.</param>
    /// <param name="functionContext">Invocation identity and cancellation supplied by the isolated worker.</param>
    /// <returns>A task completing when the shared runner and outcome reporting have finished.</returns>
    /// <exception cref="InvalidOperationException">The runner returned an aggregate Failed result.</exception>
    /// <exception cref="OperationCanceledException">The host cancelled the operation or the runner returned Cancelled.</exception>
    /// <remarks>
    /// <para>Other initialization, Azure, or persistence exceptions propagate to the host. Partial and
    /// NoConfiguredPairs are not thrown as invocation failures; operators must still inspect warnings and run records.</para>
    /// <para>UseMonitor persists timer schedule tracking, not pair state. RunOnStartup disables an extra startup
    /// invocation, but a normally due or past-due schedule can still run when the host starts.</para>
    /// </remarks>
    [Function(nameof(KeyVaultSyncTimerFunction))]
    public async Task Run(
        [TimerTrigger("%KEYVAULTSYNC_TIMER_SCHEDULE%", RunOnStartup = false, UseMonitor = true)] TimerInfo timerInfo,
        FunctionContext functionContext)
    {
        // The invocation ID joins host telemetry to the runner's separately generated RunId.
        // Child services inherit this scope through the worker's shared logging pipeline.
        using var invocationScope = logger.BeginScope(new Dictionary<string, object?>
        {
            ["FunctionName"] = nameof(KeyVaultSyncTimerFunction),
            ["FunctionInvocationId"] = functionContext.InvocationId,
        });
        var cancellationToken = functionContext.CancellationToken;
        logger.LogInformation(TimerInvocationStartedEventId,
            "KeyVaultSync timer invocation started. {FunctionInvocationId}; past due: {IsPastDue}; next schedule: {NextSchedule}.",
            functionContext.InvocationId,
            timerInfo.IsPastDue, timerInfo.ScheduleStatus?.Next);
        logger.LogTrace("Timer schedule diagnostics. Last schedule: {LastSchedule}; next schedule: {NextSchedule}; past due: {IsPastDue}.",
            timerInfo.ScheduleStatus?.Last, timerInfo.ScheduleStatus?.Next, timerInfo.IsPastDue);
        if (timerInfo.IsPastDue)
        {
            logger.LogWarning("KeyVaultSync timer invocation {FunctionInvocationId} is past due.", functionContext.InvocationId);
        }

        try
        {
            logger.LogDebug("KeyVaultSync runner execution starting for function invocation {FunctionInvocationId}.",
                functionContext.InvocationId);
            var run = await runner.ExecuteScheduledRunAsync(cancellationToken);
            if (run.Status == "Failed")
            {
                logger.LogCritical(TimerInvocationCompletedEventId,
                    "KeyVaultSync scheduled run failed. {FunctionInvocationId}; run {RunId}; status {Status}.",
                    functionContext.InvocationId, run.RunId, run.Status);
                throw new InvalidOperationException($"KeyVaultSync timer run {run.RunId} finished with status {run.Status}.");
            }

            if (run.Status == "Cancelled")
            {
                // Defensive handling for an explicit result. Today the runner normally propagates
                // host cancellation as an exception before it can return a Cancelled result.
                logger.LogWarning(TimerInvocationCompletedEventId,
                    "KeyVaultSync scheduled run was cancelled. {FunctionInvocationId}; run {RunId}.",
                    functionContext.InvocationId, run.RunId);
                throw new OperationCanceledException("KeyVaultSync scheduled run was cancelled.", cancellationToken);
            }

            if (run.Status is not "Complete" and not "NoConfiguredPairs")
            {
                // Blocked, skipped, or unsupported work needs operator attention, but retrying a
                // timer invocation is not a recovery strategy for ambiguous Key Vault writes.
                logger.LogWarning(TimerInvocationCompletedEventId,
                    "KeyVaultSync scheduled run completed with a non-success status. {FunctionInvocationId}; run {RunId}; status {Status}; inspect the persisted run record.",
                    functionContext.InvocationId, run.RunId, run.Status);
                return;
            }

            logger.LogInformation(TimerInvocationCompletedEventId,
                "KeyVaultSync scheduled run completed. {FunctionInvocationId}; run {RunId}; status {Status}.",
                functionContext.InvocationId, run.RunId, run.Status);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("KeyVaultSync timer run was cancelled during host shutdown.");
            throw;
        }
        catch (Exception exception)
        {
            // Preserve the failure for host diagnostics. Throwing signals invocation failure;
            // it must not be documented as configuring a retry policy for this timer trigger.
            logger.LogError(exception, "KeyVaultSync timer invocation failed. {FunctionInvocationId}.", functionContext.InvocationId);
            throw;
        }
    }
}