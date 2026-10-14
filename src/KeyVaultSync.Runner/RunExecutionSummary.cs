using System.Collections;
using System.Globalization;

namespace KeyVaultSync.Runner;

/// <summary>Identifies the private run-history blob that holds one cycle's detailed JSON report.</summary>
/// <param name="StorageAccountName">Storage account that hosts the run-history container.</param>
/// <param name="ContainerName">Private run-history container, <c>keyvaultsync-runs</c> unless overridden.</param>
/// <param name="BlobName">Container-relative name, <c>runs/yyyy/MM/dd/RunId.json</c>, partitioned by the UTC start date.</param>
/// <param name="BlobUri">Blob endpoint without query string, fragment, or user information.</param>
/// <remarks>
/// The location is computed from the run identity without contacting storage, so it can be logged before the first
/// write succeeds. It grants no access: reading the document still requires Azure RBAC on the storage account. The
/// document contains vault, principal, and role identifiers but never secret values, private keys, or HMAC keys.
/// </remarks>
public sealed record RunRecordLocation(string StorageAccountName, string ContainerName, string BlobName, string BlobUri)
{
    /// <summary>Removes credentials and SAS tokens that a configured endpoint could otherwise carry into logs.</summary>
    internal static string SanitizeUri(Uri uri)
    {
        var builder = new UriBuilder(uri)
        {
            Query = string.Empty,
            Fragment = string.Empty,
            UserName = string.Empty,
            Password = string.Empty,
        };
        return builder.Uri.AbsoluteUri;
    }
}

/// <summary>Value-free aggregate counts that summarize one cycle for invocation logs, traces, and host callers.</summary>
/// <remarks>
/// Counts are derived from the run record when the summary is created. They contain no subscription IDs, vault names,
/// object names, principal IDs, secret values, or fingerprints. Use the run record for per-pair and per-item evidence.
/// </remarks>
public sealed record RunExecutionSummary
{
    private static readonly string[] VerifiedObjectChangeStatuses =
        ["OBJECT_REPLICATED_AND_VERIFIED", "OBJECT_SOFT_DELETED_AND_VERIFIED"];

    private static readonly string[] VerifiedRbacChangeStatuses =
        ["RBAC_ASSIGNMENT_CREATED_AND_VERIFIED", "RBAC_ASSIGNMENT_DELETED_AND_VERIFIED"];

    /// <summary>Gets the aggregate status: Complete, NoConfiguredPairs, Partial, Failed, Cancelled, or Running if unfinished.</summary>
    public required string Status { get; init; }

    /// <summary>Gets the UTC time the cycle started, after state and HMAC initialization succeeded.</summary>
    public required DateTimeOffset StartedAt { get; init; }

    /// <summary>Gets the UTC time the cycle finished, or null when it had not finished when summarized.</summary>
    public DateTimeOffset? CompletedAt { get; init; }

    /// <summary>Gets the number of configured discovery subscriptions; the identifiers themselves are omitted.</summary>
    public required int SubscriptionCount { get; init; }

    /// <summary>Gets the number of Key Vaults discovered across the configured subscriptions.</summary>
    public required int DiscoveredVaultCount { get; init; }

    /// <summary>Gets the number of enabled source/target pairs admitted by discovery.</summary>
    public required int EnabledPairCount { get; init; }

    /// <summary>Gets the number of mapped pairs suppressed by a disable tag.</summary>
    public required int DisabledPairCount { get; init; }

    /// <summary>Gets the number of discovered vaults that are neither a mapped source nor a mapped target.</summary>
    public required int UnmappedVaultCount { get; init; }

    /// <summary>Gets the number of mapping issues, including any run-level failure or cancellation explanation.</summary>
    public required int DiscoveryIssueCount { get; init; }

    /// <summary>Gets the number of pairs that have a pair report, including lease-contention skips.</summary>
    public required int AttemptedPairCount { get; init; }

    /// <summary>Gets the number of attempted pairs that finished with status SyncCompleted.</summary>
    public required int CompletedPairCount { get; init; }

    /// <summary>Gets the number of attempted pairs with any status other than SyncCompleted.</summary>
    public required int AttentionPairCount { get; init; }

    /// <summary>Gets the number of attempted pairs that finished with status Failed.</summary>
    public required int FailedPairCount { get; init; }

    /// <summary>Gets a deterministic, ordinal-sorted <c>Status=Count</c> list of pair statuses, or <c>none</c>.</summary>
    public required string PairStatusCounts { get; init; }

    /// <summary>Gets the number of plan items across all attempted pairs, with executed items replaced by outcomes.</summary>
    public required int PlanItemCount { get; init; }

    /// <summary>Gets the number of plan items whose final status requires administrator review.</summary>
    public required int AttentionItemCount { get; init; }

    /// <summary>Gets the number of object writes and soft deletes verified against the target in this cycle.</summary>
    public required int VerifiedObjectChangeCount { get; init; }

    /// <summary>Gets the number of role-assignment creates and deletes verified against the target in this cycle.</summary>
    public required int VerifiedRbacChangeCount { get; init; }

    /// <summary>Counts a run record without copying any identifiers or values from it.</summary>
    internal static RunExecutionSummary Create(RunRecord run)
    {
        var planItems = run.Pairs.SelectMany(pair => pair.Plan).ToArray();
        var pairStatusGroups = run.Pairs
            .GroupBy(pair => pair.Status, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => string.Create(CultureInfo.InvariantCulture, $"{group.Key}={group.Count()}"))
            .ToArray();
        return new RunExecutionSummary
        {
            Status = run.Status,
            StartedAt = run.StartedAt,
            CompletedAt = run.CompletedAt,
            SubscriptionCount = run.SubscriptionIds.Count,
            DiscoveredVaultCount = run.DiscoveredVaultCount,
            EnabledPairCount = run.TaggedPairCount,
            DisabledPairCount = run.DisabledPairCount,
            UnmappedVaultCount = run.UnmappedVaultCount,
            DiscoveryIssueCount = run.DiscoveryIssues.Count,
            AttemptedPairCount = run.Pairs.Count,
            CompletedPairCount = run.Pairs.Count(pair => pair.Status == "SyncCompleted"),
            AttentionPairCount = run.Pairs.Count(pair => pair.Status != "SyncCompleted"),
            FailedPairCount = run.Pairs.Count(pair => pair.Status == "Failed"),
            PairStatusCounts = pairStatusGroups.Length == 0 ? "none" : string.Join(", ", pairStatusGroups),
            PlanItemCount = planItems.Length,
            AttentionItemCount = planItems.Count(item => AdminDiagnostics.RequiresAdminAttention(item.Status)),
            VerifiedObjectChangeCount = CountVerifiedObjectChanges(planItems),
            VerifiedRbacChangeCount = CountVerifiedRbacChanges(planItems),
        };
    }

    /// <summary>Counts executor outcomes that prove an object write or soft delete was verified.</summary>
    internal static int CountVerifiedObjectChanges(IEnumerable<PlanItem> planItems) =>
        planItems.Count(item => VerifiedObjectChangeStatuses.Contains(item.Status, StringComparer.Ordinal));

    /// <summary>Counts executor outcomes that prove a role-assignment create or delete was verified.</summary>
    internal static int CountVerifiedRbacChanges(IEnumerable<PlanItem> planItems) =>
        planItems.Count(item => VerifiedRbacChangeStatuses.Contains(item.Status, StringComparer.Ordinal));
}

/// <summary>Carries value-free run identity on exceptions that escape a recorded cycle to the timer invocation.</summary>
/// <remarks>
/// Only the run ID, aggregate status, and run-record location are stored. Annotation never replaces or wraps the
/// original exception, and a read-only <see cref="Exception.Data"/> dictionary is left untouched.
/// </remarks>
internal static class RunExceptionContext
{
    internal const string RunIdKey = "KeyVaultSync.RunId";
    internal const string RunStatusKey = "KeyVaultSync.RunStatus";
    internal const string RunRecordContainerKey = "KeyVaultSync.RunRecordContainer";
    internal const string RunRecordBlobNameKey = "KeyVaultSync.RunRecordBlobName";
    internal const string RunRecordUriKey = "KeyVaultSync.RunRecordUri";

    /// <summary>Stores run identity on the exception; failures to annotate are ignored so the original error survives.</summary>
    internal static void Attach(Exception exception, RunRecord run, RunRecordLocation location)
    {
        var data = exception.Data;
        if (data.IsReadOnly || data.IsFixedSize)
        {
            return;
        }

        try
        {
            data[RunIdKey] = run.RunId;
            data[RunStatusKey] = run.Status;
            data[RunRecordContainerKey] = location.ContainerName;
            data[RunRecordBlobNameKey] = location.BlobName;
            data[RunRecordUriKey] = location.BlobUri;
        }
        catch (Exception annotationFailure) when (annotationFailure is ArgumentException or NotSupportedException)
        {
            // Annotation is best effort; the escaping exception remains the operator-visible failure.
        }
    }

    /// <summary>Reads run identity previously stored by <see cref="Attach"/>, or null when the failure preceded the run.</summary>
    internal static RunExceptionDetails? Read(Exception exception)
    {
        var runId = ReadString(exception.Data, RunIdKey);
        return string.IsNullOrEmpty(runId)
            ? null
            : new RunExceptionDetails(
                runId,
                ReadString(exception.Data, RunStatusKey) ?? "Unknown",
                ReadString(exception.Data, RunRecordContainerKey) ?? "unavailable",
                ReadString(exception.Data, RunRecordBlobNameKey) ?? "unavailable",
                ReadString(exception.Data, RunRecordUriKey) ?? "unavailable");
    }

    private static string? ReadString(IDictionary data, string key) =>
        data.Contains(key) ? data[key] as string : null;
}

/// <summary>Run identity recovered from an exception that escaped a recorded cycle.</summary>
/// <param name="RunId">Run whose record describes the interrupted cycle.</param>
/// <param name="RunStatus">Aggregate status recorded before the exception escaped.</param>
/// <param name="RunRecordContainer">Private run-history container name.</param>
/// <param name="RunRecordBlobName">Container-relative run-history blob name.</param>
/// <param name="RunRecordUri">Run-history blob endpoint without query string or user information.</param>
internal sealed record RunExceptionDetails(
    string RunId,
    string RunStatus,
    string RunRecordContainer,
    string RunRecordBlobName,
    string RunRecordUri);
