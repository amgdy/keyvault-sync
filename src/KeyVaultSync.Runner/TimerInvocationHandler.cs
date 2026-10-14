using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using Microsoft.Extensions.Logging;

namespace KeyVaultSync.Runner;

/// <summary>Timer metadata captured by the Function adapter for one invocation.</summary>
/// <param name="FunctionName">Function name registered with the host.</param>
/// <param name="InvocationId">Host-assigned invocation ID that also appears in host request telemetry.</param>
/// <param name="IsPastDue">Whether the host started the invocation later than its schedule.</param>
/// <param name="LastScheduledOccurrence">Last scheduled occurrence recorded by the timer monitor, when available.</param>
/// <param name="NextScheduledOccurrence">Next scheduled occurrence recorded by the timer monitor, when available.</param>
/// <param name="ScheduleStatusUpdatedAt">Time the timer monitor last updated its schedule status, when available.</param>
/// <param name="Schedule">Configured NCRONTAB expression, when the application setting is visible to the worker.</param>
internal sealed record TimerInvocationContext(
    string FunctionName,
    string InvocationId,
    bool IsPastDue,
    DateTime? LastScheduledOccurrence,
    DateTime? NextScheduledOccurrence,
    DateTime? ScheduleStatusUpdatedAt,
    string? Schedule);

/// <summary>Reports one timer invocation as exactly one structured start record and one structured completion record.</summary>
/// <remarks>
/// <para>The handler owns invocation-level telemetry so the Function stays a thin adapter and the behavior is testable.
/// It tags the worker's current invocation activity with string-valued run identity and value-free counts, which the
/// worker exports and newer Functions hosts can copy to the host request record.</para>
/// <para>It adds no retry policy. A Failed or Cancelled result is rethrown as an invocation failure after logging;
/// Partial and other attention statuses return normally and are reported as warnings.</para>
/// </remarks>
internal static class TimerInvocationHandler
{
    internal static readonly EventId TimerInvocationStartedEventId = new(6000, "TimerInvocationStarted");
    internal static readonly EventId TimerInvocationCompletedEventId = new(6001, "TimerInvocationCompleted");

    internal const string SucceededOutcome = "Succeeded";
    internal const string CompletedWithWarningsOutcome = "CompletedWithWarnings";
    internal const string FailedOutcome = "Failed";
    internal const string CancelledOutcome = "Cancelled";

    private const string Unavailable = "unavailable";

    private static readonly string AppVersion =
        typeof(TimerInvocationHandler).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? "unknown";

    /// <summary>Runs one cycle and logs exactly one completion record for every result or exception path.</summary>
    /// <param name="logger">Invocation logger; scopes added here flow to runner logs through the shared pipeline.</param>
    /// <param name="invocation">Timer metadata captured from the host binding.</param>
    /// <param name="executeRun">The runner entry point, normally <see cref="RunnerApplication.ExecuteScheduledRunAsync"/>.</param>
    /// <param name="cancellationToken">Host cancellation for the invocation.</param>
    /// <returns>The runner result for Complete, NoConfiguredPairs, Partial, and other non-terminal attention statuses.</returns>
    /// <exception cref="InvalidOperationException">The runner returned an aggregate Failed result.</exception>
    /// <exception cref="OperationCanceledException">The runner returned Cancelled or propagated host cancellation.</exception>
    /// <remarks>Other runner exceptions are logged once with their run context, when available, and rethrown unchanged.</remarks>
    internal static async Task<RunnerExecutionResult> ExecuteAsync(
        ILogger logger,
        TimerInvocationContext invocation,
        Func<CancellationToken, Task<RunnerExecutionResult>> executeRun,
        CancellationToken cancellationToken)
    {
        // Capture the worker's invocation span before the runner starts child spans that become Activity.Current.
        var invocationActivity = Activity.Current;
        using var invocationScope = logger.BeginScope(new Dictionary<string, object?>
        {
            ["FunctionName"] = invocation.FunctionName,
            ["FunctionInvocationId"] = invocation.InvocationId,
        });
        invocationActivity?.SetTag("timer.is_past_due", invocation.IsPastDue ? "true" : "false");
        LogStarted(logger, invocation);

        var invocationTimer = Stopwatch.StartNew();
        RunnerExecutionResult result;
        try
        {
            result = await executeRun(cancellationToken);
        }
        catch (Exception exception)
        {
            invocationTimer.Stop();
            ReportException(logger, invocationActivity, invocation, exception, invocationTimer.Elapsed, cancellationToken);
            throw;
        }

        invocationTimer.Stop();
        var outcome = ClassifyOutcome(result.Status);
        TagResult(invocationActivity, outcome, result);
        LogResult(logger, invocation, outcome, result, invocationTimer.Elapsed);
        return outcome switch
        {
            FailedOutcome => throw new InvalidOperationException(
                $"KeyVaultSync run {result.RunId} finished with status {result.Status}. Inspect run record {result.RunRecordLocation.BlobUri}."),
            // Defensive: the runner normally propagates host cancellation as an exception instead of returning it.
            CancelledOutcome => throw new OperationCanceledException(
                $"KeyVaultSync run {result.RunId} was cancelled. Inspect run record {result.RunRecordLocation.BlobUri}.",
                cancellationToken),
            _ => result,
        };
    }

    /// <summary>Maps an aggregate run status to the invocation outcome reported by event 6001.</summary>
    internal static string ClassifyOutcome(string runStatus) => runStatus switch
    {
        "Complete" or "NoConfiguredPairs" => SucceededOutcome,
        "Failed" => FailedOutcome,
        "Cancelled" => CancelledOutcome,
        // Partial and any future status require operator review but are not retried as invocation failures.
        _ => CompletedWithWarningsOutcome,
    };

    private static void LogStarted(ILogger logger, TimerInvocationContext invocation)
    {
        logger.Log(
            invocation.IsPastDue ? LogLevel.Warning : LogLevel.Information,
            TimerInvocationStartedEventId,
            "KeyVaultSync timer invocation {FunctionInvocationId} started for function {FunctionName}. App version {AppVersion}; past due {IsPastDue}; schedule {TimerSchedule}; last scheduled {LastScheduledOccurrence}; next scheduled {NextScheduledOccurrence}; schedule status updated {ScheduleStatusUpdatedAt}.",
            invocation.InvocationId,
            invocation.FunctionName,
            AppVersion,
            invocation.IsPastDue,
            string.IsNullOrWhiteSpace(invocation.Schedule) ? Unavailable : invocation.Schedule,
            FormatTimestamp(invocation.LastScheduledOccurrence),
            FormatTimestamp(invocation.NextScheduledOccurrence),
            FormatTimestamp(invocation.ScheduleStatusUpdatedAt));
    }

    private static void LogResult(
        ILogger logger,
        TimerInvocationContext invocation,
        string outcome,
        RunnerExecutionResult result,
        TimeSpan elapsed)
    {
        var summary = result.Summary;
        using var runScope = BeginRunScope(logger, result.RunId, result.RunRecordLocation.ContainerName, result.RunRecordLocation.BlobName);
        logger.Log(
            GetLevel(outcome),
            TimerInvocationCompletedEventId,
            "KeyVaultSync timer invocation {FunctionInvocationId} finished with outcome {InvocationOutcome} in {DurationMs} ms. Run {RunId} ended with status {RunStatus}; discovered vaults {DiscoveredVaultCount}; enabled pairs {EnabledPairCount}; attempted pairs {AttemptedPairCount}; completed pairs {CompletedPairCount}; pairs needing attention {AttentionPairCount}; failed pairs {FailedPairCount}; discovery issues {DiscoveryIssueCount}; plan items {PlanItemCount}; attention items {AttentionItemCount}; verified object changes {VerifiedObjectChangeCount}; verified RBAC changes {VerifiedRbacChangeCount}; run record {RunRecordUri}.",
            invocation.InvocationId,
            outcome,
            ToMilliseconds(elapsed),
            result.RunId,
            result.Status,
            summary.DiscoveredVaultCount,
            summary.EnabledPairCount,
            summary.AttemptedPairCount,
            summary.CompletedPairCount,
            summary.AttentionPairCount,
            summary.FailedPairCount,
            summary.DiscoveryIssueCount,
            summary.PlanItemCount,
            summary.AttentionItemCount,
            summary.VerifiedObjectChangeCount,
            summary.VerifiedRbacChangeCount,
            result.RunRecordLocation.BlobUri);
    }

    private static void ReportException(
        ILogger logger,
        Activity? invocationActivity,
        TimerInvocationContext invocation,
        Exception exception,
        TimeSpan elapsed,
        CancellationToken cancellationToken)
    {
        var cancelled = exception is OperationCanceledException && cancellationToken.IsCancellationRequested;
        var outcome = cancelled ? CancelledOutcome : FailedOutcome;
        var errorType = exception.GetType().Name;
        var runDetails = RunExceptionContext.Read(exception);
        invocationActivity?.SetTag("sync.invocation.outcome", outcome);
        invocationActivity?.SetTag("error.type", errorType);
        if (runDetails is not null)
        {
            invocationActivity?.SetTag("sync.run_id", runDetails.RunId);
            invocationActivity?.SetTag("sync.status", runDetails.RunStatus);
            invocationActivity?.SetTag("sync.run_record.container", runDetails.RunRecordContainer);
            invocationActivity?.SetTag("sync.run_record.blob", runDetails.RunRecordBlobName);
            invocationActivity?.SetTag("sync.run_record.uri", runDetails.RunRecordUri);
        }

        // Host shutdown is expected operational noise; attaching the exception would file it as an application exception.
        var level = cancelled ? LogLevel.Warning : LogLevel.Error;
        var loggedException = cancelled ? null : exception;
        if (runDetails is null)
        {
            logger.Log(
                level,
                TimerInvocationCompletedEventId,
                loggedException,
                "KeyVaultSync timer invocation {FunctionInvocationId} finished with outcome {InvocationOutcome} in {DurationMs} ms because the runner raised {ErrorType}. No run record was created for this invocation.",
                invocation.InvocationId,
                outcome,
                ToMilliseconds(elapsed),
                errorType);
            return;
        }

        using var runScope = BeginRunScope(logger, runDetails.RunId, runDetails.RunRecordContainer, runDetails.RunRecordBlobName);
        logger.Log(
            level,
            TimerInvocationCompletedEventId,
            loggedException,
            "KeyVaultSync timer invocation {FunctionInvocationId} finished with outcome {InvocationOutcome} in {DurationMs} ms because the runner raised {ErrorType}. Run {RunId} ended with status {RunStatus}; run record {RunRecordUri}.",
            invocation.InvocationId,
            outcome,
            ToMilliseconds(elapsed),
            errorType,
            runDetails.RunId,
            runDetails.RunStatus,
            runDetails.RunRecordUri);
    }

    // The worker forwards only string-valued tags to the host request record, so counts are formatted invariantly.
    private static void TagResult(Activity? activity, string outcome, RunnerExecutionResult result)
    {
        if (activity is null)
        {
            return;
        }

        var summary = result.Summary;
        activity.SetTag("sync.invocation.outcome", outcome);
        activity.SetTag("sync.run_id", result.RunId);
        activity.SetTag("sync.status", result.Status);
        activity.SetTag("sync.run_record.container", result.RunRecordLocation.ContainerName);
        activity.SetTag("sync.run_record.blob", result.RunRecordLocation.BlobName);
        activity.SetTag("sync.run_record.uri", result.RunRecordLocation.BlobUri);
        activity.SetTag("sync.pair.enabled_count", FormatCount(summary.EnabledPairCount));
        activity.SetTag("sync.pair.attempted_count", FormatCount(summary.AttemptedPairCount));
        activity.SetTag("sync.pair.completed_count", FormatCount(summary.CompletedPairCount));
        activity.SetTag("sync.pair.attention_count", FormatCount(summary.AttentionPairCount));
        activity.SetTag("sync.pair.failed_count", FormatCount(summary.FailedPairCount));
        activity.SetTag("sync.plan.item_count", FormatCount(summary.PlanItemCount));
        activity.SetTag("sync.plan.attention_item_count", FormatCount(summary.AttentionItemCount));
        activity.SetTag("sync.object.verified_change_count", FormatCount(summary.VerifiedObjectChangeCount));
        activity.SetTag("sync.rbac.verified_change_count", FormatCount(summary.VerifiedRbacChangeCount));
    }

    // Matches the runner's run scope so invocation records group with run logs by RunId and run-record blob.
    private static IDisposable? BeginRunScope(ILogger logger, string runId, string containerName, string runRecordBlobName) =>
        logger.BeginScope(new Dictionary<string, object?>
        {
            ["RunId"] = runId,
            ["RunRecordContainer"] = containerName,
            ["RunRecordBlobName"] = runRecordBlobName,
        });

    private static LogLevel GetLevel(string outcome) => outcome switch
    {
        SucceededOutcome => LogLevel.Information,
        FailedOutcome => LogLevel.Critical,
        _ => LogLevel.Warning,
    };

    // The timer monitor reports default(DateTime) when it has no schedule history; treat that as unavailable.
    private static string FormatTimestamp(DateTime? value) =>
        value is { } timestamp && timestamp != default
            ? timestamp.ToString("O", CultureInfo.InvariantCulture)
            : Unavailable;

    private static string FormatCount(int value) => value.ToString(CultureInfo.InvariantCulture);

    private static long ToMilliseconds(TimeSpan elapsed) => (long)Math.Round(elapsed.TotalMilliseconds);
}
