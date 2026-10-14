using System.Collections;
using System.Collections.ObjectModel;
using System.Diagnostics;
using Azure.Storage.Blobs;
using KeyVaultSync.Runner.State;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using static KeyVaultSync.Runner.Tests.TelemetryTestData;

namespace KeyVaultSync.Runner.Tests;

public sealed class RunTelemetryTests
{
    [Fact]
    public void GetRunRecordBlobName_PartitionsByUtcStartDate()
    {
        // 00:30 at UTC+02:00 is 22:30 on the previous UTC day.
        var run = Run("Running", new DateTimeOffset(2025, 1, 2, 0, 30, 0, TimeSpan.FromHours(2)));

        Assert.Equal($"runs/2025/01/01/{RunId}.json", BlobStateStore.GetRunRecordBlobName(run));
    }

    [Fact]
    public void SanitizeUri_RemovesUserInformationQueryAndFragment()
    {
        var configuredUri = new Uri(
            "https://user:password@account.blob.core.windows.net/keyvaultsync-runs/runs/2025/01/02/run.json?sv=2024-11-04&sig=signature#fragment");

        Assert.Equal(
            "https://account.blob.core.windows.net/keyvaultsync-runs/runs/2025/01/02/run.json",
            RunRecordLocation.SanitizeUri(configuredUri));
    }

    [Fact]
    public void GetRunRecordLocation_DescribesConfiguredContainerWithoutContactingStorage()
    {
        var options = new RunnerOptions
        {
            SubscriptionIds = ["subscription-a"],
            StorageAccountUri = new Uri("https://account.blob.core.windows.net"),
            RunsContainer = "custom-runs",
        };
        var credential = new CountingFailingTokenCredential();
        var stateStore = new BlobStateStore(
            new BlobServiceClient(options.StorageAccountUri, credential),
            options,
            NullLoggerFactory.Instance);

        var location = stateStore.GetRunRecordLocation(Run("Running"));

        Assert.Equal("account", location.StorageAccountName);
        Assert.Equal("custom-runs", location.ContainerName);
        Assert.Equal(RunRecordBlobName, location.BlobName);
        Assert.Equal($"https://account.blob.core.windows.net/custom-runs/{RunRecordBlobName}", location.BlobUri);
        Assert.Equal(0, credential.TokenRequestCount);
    }

    [Fact]
    public void RunExecutionSummary_CountsOutcomesWithoutCopyingIdentifiers()
    {
        var run = Run("Partial");
        run.CompletedAt = run.StartedAt.AddMinutes(2);
        run.DiscoveredVaultCount = 6;
        run.TaggedPairCount = 3;
        run.DisabledPairCount = 1;
        run.UnmappedVaultCount = 2;
        run.DiscoveryIssues.Add("Target vault-unreadable maps to a source that could not be read.");
        run.Pairs.Add(Pair(
            "pair-completed",
            "SyncCompleted",
            "OBJECT_REPLICATED_AND_VERIFIED",
            "OBJECT_SOFT_DELETED_AND_VERIFIED",
            "RBAC_ASSIGNMENT_CREATED_AND_VERIFIED",
            "IN_SYNC_SIGNATURE_VERIFIED"));
        run.Pairs.Add(Pair("pair-failed", "Failed", "CONFLICT_EXTERNALLY_MODIFIED"));
        run.Pairs.Add(Pair("pair-locked", "SkippedPairAlreadyLocked"));

        var summary = RunExecutionSummary.Create(run);

        Assert.Equal("Partial", summary.Status);
        Assert.Equal(run.StartedAt, summary.StartedAt);
        Assert.Equal(run.CompletedAt, summary.CompletedAt);
        Assert.Equal(2, summary.SubscriptionCount);
        Assert.Equal(6, summary.DiscoveredVaultCount);
        Assert.Equal(3, summary.EnabledPairCount);
        Assert.Equal(1, summary.DisabledPairCount);
        Assert.Equal(2, summary.UnmappedVaultCount);
        Assert.Equal(1, summary.DiscoveryIssueCount);
        Assert.Equal(3, summary.AttemptedPairCount);
        Assert.Equal(1, summary.CompletedPairCount);
        Assert.Equal(2, summary.AttentionPairCount);
        Assert.Equal(1, summary.FailedPairCount);
        Assert.Equal("Failed=1, SkippedPairAlreadyLocked=1, SyncCompleted=1", summary.PairStatusCounts);
        Assert.Equal(5, summary.PlanItemCount);
        Assert.Equal(1, summary.AttentionItemCount);
        Assert.Equal(2, summary.VerifiedObjectChangeCount);
        Assert.Equal(1, summary.VerifiedRbacChangeCount);
        var renderedSummary = summary.ToString();
        Assert.DoesNotContain("subscription-a", renderedSummary, StringComparison.Ordinal);
        Assert.DoesNotContain("pair-completed", renderedSummary, StringComparison.Ordinal);
        Assert.DoesNotContain("vault-unreadable", renderedSummary, StringComparison.Ordinal);
    }

    [Fact]
    public void RunExecutionSummary_ReportsNoneWhenNoPairWasAttempted()
    {
        var summary = RunExecutionSummary.Create(Run("NoConfiguredPairs"));

        Assert.Equal("none", summary.PairStatusCounts);
        Assert.Equal(0, summary.AttemptedPairCount);
        Assert.Equal(0, summary.PlanItemCount);
        Assert.Null(summary.CompletedAt);
    }

    [Fact]
    public void RunExceptionContext_RoundTripsRunIdentityOnTheOriginalException()
    {
        var failure = new InvalidOperationException("Final run-record write failed.");

        RunExceptionContext.Attach(failure, Run("Failed"), Location());
        var details = RunExceptionContext.Read(failure);

        Assert.NotNull(details);
        Assert.Equal(RunId, details.RunId);
        Assert.Equal("Failed", details.RunStatus);
        Assert.Equal(RunRecordContainer, details.RunRecordContainer);
        Assert.Equal(RunRecordBlobName, details.RunRecordBlobName);
        Assert.Equal(RunRecordUri, details.RunRecordUri);
    }

    [Fact]
    public void RunExceptionContext_ReturnsNullForFailuresBeforeTheRunStarted() =>
        Assert.Null(RunExceptionContext.Read(new InvalidOperationException("Storage initialization failed.")));

    [Fact]
    public void RunExceptionContext_DefaultsMissingFieldsAndLeavesReadOnlyDataUntouched()
    {
        var partiallyAnnotated = new InvalidOperationException("Annotated by an older build.");
        partiallyAnnotated.Data[RunExceptionContext.RunIdKey] = RunId;
        var readOnlyData = new ReadOnlyDataException();

        var partialDetails = RunExceptionContext.Read(partiallyAnnotated);
        RunExceptionContext.Attach(readOnlyData, Run("Failed"), Location());

        Assert.NotNull(partialDetails);
        Assert.Equal("Unknown", partialDetails.RunStatus);
        Assert.Equal("unavailable", partialDetails.RunRecordContainer);
        Assert.Equal("unavailable", partialDetails.RunRecordBlobName);
        Assert.Equal("unavailable", partialDetails.RunRecordUri);
        Assert.Null(RunExceptionContext.Read(readOnlyData));
    }

    [Fact]
    public void StartRunActivity_IsAnInternalChildSpanTaggedWithTheRunRecord()
    {
        using var listener = ListenToRunnerActivities();

        using var runActivity = RunnerApplication.StartRunActivity(Run("Running"), Location());

        Assert.NotNull(runActivity);
        Assert.Equal("sync.run", runActivity.OperationName);
        Assert.Equal(ActivityKind.Internal, runActivity.Kind);
        Assert.Equal(RunId, runActivity.GetTagItem("sync.run_id"));
        Assert.Equal(RunRecordContainer, runActivity.GetTagItem("sync.run_record.container"));
        Assert.Equal(RunRecordBlobName, runActivity.GetTagItem("sync.run_record.blob"));
        Assert.Equal(runActivity.TraceId.ToHexString(), RunnerApplication.GetTraceId(runActivity));
    }

    [Theory]
    [InlineData("Complete", null, ActivityStatusCode.Ok, null)]
    [InlineData("NoConfiguredPairs", null, ActivityStatusCode.Ok, null)]
    [InlineData("Partial", null, ActivityStatusCode.Error, "Partial")]
    [InlineData("Cancelled", null, ActivityStatusCode.Error, "Cancelled")]
    [InlineData("Failed", "RequestFailedException", ActivityStatusCode.Error, "RequestFailedException")]
    public void CompleteRunActivity_SetsStatusFromTheRunOutcome(
        string runStatus,
        string? existingErrorDescription,
        ActivityStatusCode expectedStatus,
        string? expectedDescription)
    {
        using var runActivity = new Activity("sync.run").Start();
        if (existingErrorDescription is not null)
        {
            runActivity.SetStatus(ActivityStatusCode.Error, existingErrorDescription);
        }

        var run = Run(runStatus);
        run.Pairs.Add(Pair("pair", "SyncCompleted", "RBAC_ASSIGNMENT_DELETED_AND_VERIFIED"));

        RunnerApplication.CompleteRunActivity(runActivity, run, RunExecutionSummary.Create(run));

        Assert.Equal(expectedStatus, runActivity.Status);
        Assert.Equal(expectedDescription, runActivity.StatusDescription);
        Assert.Equal(runStatus, runActivity.GetTagItem("sync.status"));
        Assert.Equal(1, runActivity.GetTagItem("sync.pair.attempted_count"));
        Assert.Equal(1, runActivity.GetTagItem("sync.rbac.verified_change_count"));
    }

    [Fact]
    public void GetTraceId_ReturnsTheOperationIdOnlyForW3CActivities()
    {
        using (var w3cActivity = new Activity("w3c").SetIdFormat(ActivityIdFormat.W3C).Start())
        {
            Assert.Equal(w3cActivity.TraceId.ToHexString(), RunnerApplication.GetTraceId(w3cActivity));
        }

        using (var hierarchicalActivity = new Activity("hierarchical").SetIdFormat(ActivityIdFormat.Hierarchical).Start())
        {
            Assert.Null(RunnerApplication.GetTraceId(hierarchicalActivity));
        }

        Assert.Null(RunnerApplication.GetTraceId(null));
    }

    [Fact]
    public void LogRunStarted_ReportsTraceAndRunRecordLocation()
    {
        var logger = new CapturingLogger();
        var run = Run("Running");

        RunnerApplication.LogRunStarted(logger, run, Location());
        run.TraceId = "4bf92f3577b34da6a3ce929d0e0e4736";
        RunnerApplication.LogRunStarted(logger, run, Location());

        Assert.All(logger.Entries, entry =>
        {
            Assert.Equal(RunnerApplication.RunStartedEventId, entry.EventId);
            Assert.Equal(LogLevel.Information, entry.Level);
            Assert.Equal(RunId, entry.Properties["RunId"]);
            Assert.Equal(2, entry.Properties["SubscriptionCount"]);
            Assert.Equal(RunRecordUri, entry.Properties["RunRecordUri"]);
        });
        Assert.Equal("unavailable", logger.Entries[0].Properties["TraceId"]);
        Assert.Equal("4bf92f3577b34da6a3ce929d0e0e4736", logger.Entries[1].Properties["TraceId"]);
        Assert.DoesNotContain("subscription-a", logger.Entries[1].Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Complete", LogLevel.Information)]
    [InlineData("NoConfiguredPairs", LogLevel.Information)]
    [InlineData("Partial", LogLevel.Warning)]
    [InlineData("Cancelled", LogLevel.Warning)]
    [InlineData("Failed", LogLevel.Critical)]
    public void LogRunCompleted_UsesStatusSeverityAndKeepsTheAnalyzerPrefix(string runStatus, LogLevel expectedLevel)
    {
        var logger = new CapturingLogger();
        var run = Run(runStatus);

        RunnerApplication.LogRunCompleted(
            logger,
            run,
            RunExecutionSummary.Create(run),
            TimeSpan.FromMilliseconds(1234.4),
            Location());

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(RunnerApplication.RunCompletedEventId, entry.EventId);
        Assert.Equal(expectedLevel, entry.Level);
        Assert.StartsWith($"Run {RunId} completed with status {runStatus} in 1234 ms.", entry.Message, StringComparison.Ordinal);
        Assert.Equal(runStatus, entry.Properties["RunStatus"]);
        Assert.Equal(1234L, entry.Properties["DurationMs"]);
        Assert.Equal("none", entry.Properties["PairStatusCounts"]);
        Assert.Equal(RunRecordUri, entry.Properties["RunRecordUri"]);
    }

    [Fact]
    public void StartExecutionPhaseActivity_SkipsEmptyPhasesAndNamesPhasesWithWork()
    {
        using var listener = ListenToRunnerActivities();

        var emptyPhaseActivity = RunnerApplication.StartExecutionPhaseActivity(RunnerApplication.ObjectDeletePhase, 0);
        using var phaseActivity = RunnerApplication.StartExecutionPhaseActivity(RunnerApplication.ObjectCreateReconcilePhase, 3);

        Assert.Null(emptyPhaseActivity);
        Assert.NotNull(phaseActivity);
        Assert.Equal("sync.execute-phase", phaseActivity.OperationName);
        Assert.Equal("sync.execute-phase ObjectCreateReconcile", phaseActivity.DisplayName);
        Assert.Equal(RunnerApplication.ObjectCreateReconcilePhase, phaseActivity.GetTagItem("sync.phase"));
        Assert.Equal(3, phaseActivity.GetTagItem("sync.phase.item_count"));
    }

    public static TheoryData<string[], string, LogLevel, int, int, int> PhaseOutcomes => new()
    {
        { [], "NoItems", LogLevel.Debug, 0, 0, 0 },
        {
            ["OBJECT_REPLICATED_AND_VERIFIED", "IN_SYNC_SIGNATURE_VERIFIED", "RBAC_ASSIGNMENT_CREATED_AND_VERIFIED"],
            "Completed", LogLevel.Information, 2, 1, 0
        },
        {
            ["OBJECT_SOFT_DELETED_AND_VERIFIED", "CONFLICT_EXTERNALLY_MODIFIED"],
            "CompletedWithAttention", LogLevel.Warning, 1, 0, 1
        },
    };

    [Theory]
    [MemberData(nameof(PhaseOutcomes))]
    public void ReportExecutionPhaseCompleted_ClassifiesVerifiedNoChangeAndAttentionResults(
        string[] resultStatuses,
        string expectedOutcome,
        LogLevel expectedLevel,
        int expectedVerifiedChanges,
        int expectedNoChange,
        int expectedAttention)
    {
        var logger = new CapturingLogger();
        using var phaseActivity = resultStatuses.Length == 0 ? null : new Activity("sync.execute-phase").Start();
        var results = resultStatuses.Select(Item).ToArray();

        RunnerApplication.ReportExecutionPhaseCompleted(
            logger,
            phaseActivity,
            RunnerApplication.VaultRbacCreatePhase,
            resultStatuses.Length,
            results,
            TimeSpan.FromMilliseconds(5));

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(RunnerApplication.ExecutionPhaseCompletedEventId, entry.EventId);
        Assert.Equal(expectedLevel, entry.Level);
        Assert.Equal(RunnerApplication.VaultRbacCreatePhase, entry.Properties["ExecutionPhase"]);
        Assert.Equal(expectedOutcome, entry.Properties["PhaseOutcome"]);
        Assert.Equal(expectedVerifiedChanges, entry.Properties["PhaseVerifiedChangeCount"]);
        Assert.Equal(expectedNoChange, entry.Properties["PhaseNoChangeCount"]);
        Assert.Equal(expectedAttention, entry.Properties["PhaseAttentionCount"]);
        if (phaseActivity is not null)
        {
            Assert.Equal(expectedAttention > 0 ? ActivityStatusCode.Error : ActivityStatusCode.Ok, phaseActivity.Status);
            Assert.Equal(expectedOutcome, phaseActivity.GetTagItem("sync.phase.outcome"));
        }
    }

    [Theory]
    [InlineData(false, "Failed", LogLevel.Error)]
    [InlineData(true, "Cancelled", LogLevel.Warning)]
    public void ReportExecutionPhaseInterrupted_MarksThePhaseWithoutLoggingTheExceptionAgain(
        bool cancelled,
        string expectedOutcome,
        LogLevel expectedLevel)
    {
        var logger = new CapturingLogger();
        using var phaseActivity = new Activity("sync.execute-phase").Start();
        Exception interruption = cancelled
            ? new OperationCanceledException()
            : new InvalidOperationException("Executor failed.");

        RunnerApplication.ReportExecutionPhaseInterrupted(
            logger,
            phaseActivity,
            RunnerApplication.ObjectRbacDeletePhase,
            2,
            interruption,
            cancelled,
            TimeSpan.FromMilliseconds(7));

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(RunnerApplication.ExecutionPhaseCompletedEventId, entry.EventId);
        Assert.Equal(expectedLevel, entry.Level);
        Assert.Null(entry.Exception);
        Assert.Equal(expectedOutcome, entry.Properties["PhaseOutcome"]);
        Assert.Equal(interruption.GetType().Name, entry.Properties["ErrorType"]);
        Assert.Equal(ActivityStatusCode.Error, phaseActivity.Status);
        Assert.Equal(expectedOutcome, phaseActivity.GetTagItem("sync.phase.outcome"));
        Assert.Equal(cancelled ? 0 : 1, phaseActivity.Events.Count(activityEvent => activityEvent.Name == "exception"));
    }

    private static ActivityListener ListenToRunnerActivities()
    {
        var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == RunnerTelemetry.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
        };
        ActivitySource.AddActivityListener(listener);
        return listener;
    }

    private sealed class ReadOnlyDataException : Exception
    {
        private readonly IDictionary _data = new ReadOnlyDictionary<object, object?>(new Dictionary<object, object?>());

        public override IDictionary Data => _data;
    }
}
