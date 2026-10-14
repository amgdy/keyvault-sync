using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using static KeyVaultSync.Runner.Tests.TelemetryTestData;

namespace KeyVaultSync.Runner.Tests;

public sealed class TimerInvocationHandlerTests
{
    private const string FunctionName = "KeyVaultSyncTimerFunction";
    private const string InvocationId = "11111111-2222-3333-4444-555555555555";

    [Theory]
    [InlineData("Complete", "Succeeded", LogLevel.Information)]
    [InlineData("NoConfiguredPairs", "Succeeded", LogLevel.Information)]
    [InlineData("Partial", "CompletedWithWarnings", LogLevel.Warning)]
    public async Task ExecuteAsync_ReturnedRunLogsOneStartAndOneCompletionInTheRunScope(
        string runStatus,
        string expectedOutcome,
        LogLevel expectedLevel)
    {
        var logger = new CapturingLogger();
        var result = Result(runStatus);

        var returned = await TimerInvocationHandler.ExecuteAsync(
            logger,
            Invocation(),
            _ => Task.FromResult(result),
            CancellationToken.None);

        Assert.Same(result, returned);
        Assert.Equal(2, logger.Entries.Count);
        var started = Assert.Single(logger.WithEventId(6000));
        Assert.Equal(LogLevel.Information, started.Level);
        Assert.Equal(InvocationId, started.Scopes["FunctionInvocationId"]);
        Assert.Equal(FunctionName, started.Scopes["FunctionName"]);
        Assert.False(started.Scopes.ContainsKey("RunId"));
        Assert.Equal("unavailable", started.Properties["TimerSchedule"]);
        var completed = Assert.Single(logger.WithEventId(6001));
        Assert.Equal(expectedLevel, completed.Level);
        Assert.Null(completed.Exception);
        Assert.Equal(expectedOutcome, completed.Properties["InvocationOutcome"]);
        Assert.Equal(RunId, completed.Properties["RunId"]);
        Assert.Equal(runStatus, completed.Properties["RunStatus"]);
        Assert.Equal(2, completed.Properties["AttemptedPairCount"]);
        Assert.Equal(1, completed.Properties["FailedPairCount"]);
        Assert.Equal(3, completed.Properties["PlanItemCount"]);
        Assert.Equal(1, completed.Properties["VerifiedObjectChangeCount"]);
        Assert.Equal(RunRecordUri, completed.Properties["RunRecordUri"]);
        Assert.Equal(InvocationId, completed.Scopes["FunctionInvocationId"]);
        Assert.Equal(RunId, completed.Scopes["RunId"]);
        Assert.Equal(RunRecordContainer, completed.Scopes["RunRecordContainer"]);
        Assert.Equal(RunRecordBlobName, completed.Scopes["RunRecordBlobName"]);
        Assert.EndsWith($"run record {RunRecordUri}.", completed.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExecuteAsync_FailedRunLogsCriticalThenFailsTheInvocation()
    {
        var logger = new CapturingLogger();

        var invocationFailure = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            TimerInvocationHandler.ExecuteAsync(
                logger,
                Invocation(),
                _ => Task.FromResult(Result("Failed")),
                CancellationToken.None));

        Assert.Contains(RunId, invocationFailure.Message, StringComparison.Ordinal);
        Assert.Contains(RunRecordUri, invocationFailure.Message, StringComparison.Ordinal);
        var completed = Assert.Single(logger.WithEventId(6001));
        Assert.Equal(LogLevel.Critical, completed.Level);
        Assert.Equal(TimerInvocationHandler.FailedOutcome, completed.Properties["InvocationOutcome"]);
        Assert.Equal(RunId, completed.Scopes["RunId"]);
    }

    [Fact]
    public async Task ExecuteAsync_CancelledResultFailsTheInvocationAsCancelled()
    {
        var logger = new CapturingLogger();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            TimerInvocationHandler.ExecuteAsync(
                logger,
                Invocation(),
                _ => Task.FromResult(Result("Cancelled")),
                CancellationToken.None));

        var completed = Assert.Single(logger.WithEventId(6001));
        Assert.Equal(LogLevel.Warning, completed.Level);
        Assert.Equal(TimerInvocationHandler.CancelledOutcome, completed.Properties["InvocationOutcome"]);
    }

    [Fact]
    public async Task ExecuteAsync_EscapingExceptionWithRunContextIsLoggedOnceInTheRunScopeAndRethrown()
    {
        var logger = new CapturingLogger();
        var failure = new InvalidOperationException("Final run-record write failed.");
        RunExceptionContext.Attach(failure, Run("Failed"), Location());

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            TimerInvocationHandler.ExecuteAsync(
                logger,
                Invocation(),
                _ => Task.FromException<RunnerExecutionResult>(failure),
                CancellationToken.None));

        Assert.Same(failure, thrown);
        var completed = Assert.Single(logger.WithEventId(6001));
        Assert.Equal(LogLevel.Error, completed.Level);
        Assert.Same(failure, completed.Exception);
        Assert.Equal(TimerInvocationHandler.FailedOutcome, completed.Properties["InvocationOutcome"]);
        Assert.Equal(nameof(InvalidOperationException), completed.Properties["ErrorType"]);
        Assert.Equal("Failed", completed.Properties["RunStatus"]);
        Assert.Equal(RunRecordUri, completed.Properties["RunRecordUri"]);
        Assert.Equal(RunId, completed.Scopes["RunId"]);
        Assert.Equal(RunRecordBlobName, completed.Scopes["RunRecordBlobName"]);
    }

    [Fact]
    public async Task ExecuteAsync_FailureBeforeTheRunStartsReportsThatNoRunRecordExists()
    {
        var logger = new CapturingLogger();
        var failure = new InvalidOperationException("Storage initialization failed.");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            TimerInvocationHandler.ExecuteAsync(
                logger,
                Invocation(),
                _ => Task.FromException<RunnerExecutionResult>(failure),
                CancellationToken.None));

        var completed = Assert.Single(logger.WithEventId(6001));
        Assert.Equal(LogLevel.Error, completed.Level);
        Assert.Same(failure, completed.Exception);
        Assert.EndsWith("No run record was created for this invocation.", completed.Message, StringComparison.Ordinal);
        Assert.False(completed.Scopes.ContainsKey("RunId"));
    }

    [Fact]
    public async Task ExecuteAsync_HostCancellationIsAWarningWithoutAnAttachedException()
    {
        var logger = new CapturingLogger();
        using var hostCancellation = new CancellationTokenSource();
        await hostCancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            TimerInvocationHandler.ExecuteAsync(
                logger,
                Invocation(),
                cancellationToken => Task.FromCanceled<RunnerExecutionResult>(cancellationToken),
                hostCancellation.Token));

        var completed = Assert.Single(logger.WithEventId(6001));
        Assert.Equal(LogLevel.Warning, completed.Level);
        Assert.Null(completed.Exception);
        Assert.Equal(TimerInvocationHandler.CancelledOutcome, completed.Properties["InvocationOutcome"]);
    }

    [Fact]
    public async Task ExecuteAsync_TimeoutWithoutHostCancellationIsAFailure()
    {
        var logger = new CapturingLogger();
        var timeout = new TaskCanceledException("The HTTP request timed out.");

        await Assert.ThrowsAsync<TaskCanceledException>(() =>
            TimerInvocationHandler.ExecuteAsync(
                logger,
                Invocation(),
                _ => Task.FromException<RunnerExecutionResult>(timeout),
                CancellationToken.None));

        var completed = Assert.Single(logger.WithEventId(6001));
        Assert.Equal(LogLevel.Error, completed.Level);
        Assert.Same(timeout, completed.Exception);
        Assert.Equal(TimerInvocationHandler.FailedOutcome, completed.Properties["InvocationOutcome"]);
    }

    [Fact]
    public async Task ExecuteAsync_PastDueStartWarnsAndFormatsScheduleMetadata()
    {
        var logger = new CapturingLogger();
        var invocation = Invocation() with
        {
            IsPastDue = true,
            LastScheduledOccurrence = default(DateTime),
            NextScheduledOccurrence = null,
            ScheduleStatusUpdatedAt = new DateTime(2025, 1, 2, 1, 30, 0, DateTimeKind.Utc),
            Schedule = "0 */30 * * * *",
        };

        await TimerInvocationHandler.ExecuteAsync(
            logger,
            invocation,
            _ => Task.FromResult(Result("Complete")),
            CancellationToken.None);

        var started = Assert.Single(logger.WithEventId(6000));
        Assert.Equal(LogLevel.Warning, started.Level);
        Assert.True(Assert.IsType<bool>(started.Properties["IsPastDue"]));
        Assert.Equal("0 */30 * * * *", started.Properties["TimerSchedule"]);
        Assert.Equal("unavailable", started.Properties["LastScheduledOccurrence"]);
        Assert.Equal("unavailable", started.Properties["NextScheduledOccurrence"]);
        Assert.Equal("2025-01-02T01:30:00.0000000Z", started.Properties["ScheduleStatusUpdatedAt"]);
    }

    [Fact]
    public async Task ExecuteAsync_TagsTheInvocationActivityWithStringValues()
    {
        using var invocationActivity = new Activity($"function {FunctionName}").Start();

        await TimerInvocationHandler.ExecuteAsync(
            new CapturingLogger(),
            Invocation(),
            _ => Task.FromResult(Result("Partial")),
            CancellationToken.None);

        var tags = invocationActivity.TagObjects.ToDictionary(tag => tag.Key, tag => tag.Value, StringComparer.Ordinal);
        Assert.All(tags.Values, value => Assert.IsType<string>(value));
        Assert.Equal("false", tags["timer.is_past_due"]);
        Assert.Equal(TimerInvocationHandler.CompletedWithWarningsOutcome, tags["sync.invocation.outcome"]);
        Assert.Equal(RunId, tags["sync.run_id"]);
        Assert.Equal("Partial", tags["sync.status"]);
        Assert.Equal(RunRecordContainer, tags["sync.run_record.container"]);
        Assert.Equal(RunRecordBlobName, tags["sync.run_record.blob"]);
        Assert.Equal(RunRecordUri, tags["sync.run_record.uri"]);
        Assert.Equal("2", tags["sync.pair.attempted_count"]);
        Assert.Equal("1", tags["sync.pair.failed_count"]);
        Assert.Equal("1", tags["sync.object.verified_change_count"]);
    }

    [Fact]
    public async Task ExecuteAsync_TagsTheInvocationActivityFromAnEscapingRunException()
    {
        using var invocationActivity = new Activity($"function {FunctionName}").Start();
        var failure = new InvalidOperationException("Final run-record write failed.");
        RunExceptionContext.Attach(failure, Run("Failed"), Location());

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            TimerInvocationHandler.ExecuteAsync(
                new CapturingLogger(),
                Invocation(),
                _ => Task.FromException<RunnerExecutionResult>(failure),
                CancellationToken.None));

        Assert.Equal(TimerInvocationHandler.FailedOutcome, invocationActivity.GetTagItem("sync.invocation.outcome"));
        Assert.Equal(nameof(InvalidOperationException), invocationActivity.GetTagItem("error.type"));
        Assert.Equal(RunId, invocationActivity.GetTagItem("sync.run_id"));
        Assert.Equal("Failed", invocationActivity.GetTagItem("sync.status"));
        Assert.Equal(RunRecordUri, invocationActivity.GetTagItem("sync.run_record.uri"));
    }

    [Theory]
    [InlineData("Complete", "Succeeded")]
    [InlineData("NoConfiguredPairs", "Succeeded")]
    [InlineData("Partial", "CompletedWithWarnings")]
    [InlineData("Running", "CompletedWithWarnings")]
    [InlineData("Failed", "Failed")]
    [InlineData("Cancelled", "Cancelled")]
    public void ClassifyOutcome_MapsRunStatusToInvocationOutcome(string runStatus, string expectedOutcome) =>
        Assert.Equal(expectedOutcome, TimerInvocationHandler.ClassifyOutcome(runStatus));

    [Fact]
    public async Task ExecuteAsync_RunnerPrerequisiteFailureReportsNoRunRecordWithoutContactingStorage()
    {
        // The .invalid host can never resolve; the credential fails before any storage request is sent.
        var options = new RunnerOptions
        {
            SubscriptionIds = ["00000000-0000-0000-0000-000000000000"],
            StorageAccountUri = new Uri("https://account.blob.core.windows.invalid"),
        };
        var credential = new CountingFailingTokenCredential();
        var runner = new RunnerApplication(options, credential, NullLoggerFactory.Instance);
        var logger = new CapturingLogger();

        var failure = await Assert.ThrowsAnyAsync<Exception>(() =>
            TimerInvocationHandler.ExecuteAsync(
                logger,
                Invocation(),
                runner.ExecuteScheduledRunAsync,
                CancellationToken.None));

        Assert.True(credential.TokenRequestCount > 0);
        Assert.Null(RunExceptionContext.Read(failure));
        var completed = Assert.Single(logger.WithEventId(6001));
        Assert.Equal(LogLevel.Error, completed.Level);
        Assert.Same(failure, completed.Exception);
        Assert.Equal(TimerInvocationHandler.FailedOutcome, completed.Properties["InvocationOutcome"]);
        Assert.EndsWith("No run record was created for this invocation.", completed.Message, StringComparison.Ordinal);
    }

    private static TimerInvocationContext Invocation() =>
        new(FunctionName, InvocationId, IsPastDue: false, null, null, null, Schedule: null);

    private static RunnerExecutionResult Result(string runStatus)
    {
        var run = Run(runStatus);
        run.Pairs.Add(Pair("pair-completed", "SyncCompleted", "OBJECT_REPLICATED_AND_VERIFIED", "RBAC_ASSIGNMENT_IN_SYNC"));
        run.Pairs.Add(Pair("pair-failed", "Failed", "CONFLICT_EXTERNALLY_MODIFIED"));
        return new RunnerExecutionResult(RunId, runStatus)
        {
            RunRecordLocation = Location(),
            Summary = RunExecutionSummary.Create(run),
        };
    }
}
