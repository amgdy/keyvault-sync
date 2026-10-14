using System.Diagnostics;
using System.Globalization;
using Azure.Core;
using Azure.Storage.Blobs;
using KeyVaultSync.Runner.Azure;
using KeyVaultSync.Runner.Security;
using KeyVaultSync.Runner.State;
using KeyVaultSync.Runner.Sync;
using Microsoft.Extensions.Logging;

namespace KeyVaultSync.Runner;

/// <summary>Coordinates one discovery, inventory, planning, and mapping-driven synchronization cycle.</summary>
/// <remarks>
/// <para>The isolated Function host uses this implementation. It owns no scheduling loop and creates neither source nor
/// target Key Vaults. Azure clients are reused across calls; pair state is protected by cooperative Blob leases.</para>
/// <para>An enabled target-declared mapping opts that pair into supported synchronization. Supported object writes
/// and soft deletes retain versioned HMAC and intent checks. Direct allowlisted Key Vault RBAC is reconciled at vault,
/// secret, and key scope; unsupported key material and certificate child-scope authorization remain explicit reports.</para>
/// </remarks>
public sealed class RunnerApplication
{
    // These IDs describe orchestration stages. Child services supply their own event IDs while
    // inheriting the RunId/PairId scopes, so operators can correlate work across logger categories.
    private static readonly EventId DiscoveryStartedEventId = new(3000, "DiscoveryStarted");
    private static readonly EventId PairProgressEventId = new(3001, "PairProgress");
    private static readonly EventId PlanningProgressEventId = new(3002, "PlanningProgress");
    private static readonly EventId SecretSyncProgressEventId = new(3003, "SecretSyncProgress");
    internal static readonly EventId RunStartedEventId = new(3004, "RunStarted");
    internal static readonly EventId RunCompletedEventId = new(3005, "RunCompleted");
    internal static readonly EventId ExecutionPhaseCompletedEventId = new(3006, "ExecutionPhaseCompleted");

    // Stable phase names for the ExecutionPhase scope, 3006 records, and sync.phase trace tags.
    // Declaration order mirrors the dependency-safe order used by ExecutePreparedPairAsync.
    internal const string VaultRbacCreatePhase = "VaultRbacCreate";
    internal const string ObjectCreateReconcilePhase = "ObjectCreateReconcile";
    internal const string ObjectRbacCreatePhase = "ObjectRbacCreate";
    internal const string ObjectRbacDeletePhase = "ObjectRbacDelete";
    internal const string ObjectDeletePhase = "ObjectDelete";
    internal const string VaultRbacDeletePhase = "VaultRbacDelete";

    private readonly RunnerOptions _options;
    private readonly TokenCredential _credential;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<RunnerApplication> _logger;
    private readonly ArmResourceClient _arm;
    private readonly VaultInventoryScanner _scanner;
    private readonly ObjectExecutor _objectExecutor;
    private readonly RbacExecutor _rbacExecutor;
    private readonly BlobStateStore _stateStore;

    /// <summary>Creates the hosted runner with an environment-only configuration snapshot.</summary>
    /// <param name="credential">Host-supplied Azure credential shared by ARM, Key Vault, and Blob clients.</param>
    /// <param name="loggerFactory">Host-owned structured logging factory; this class does not dispose it.</param>
    /// <exception cref="ArgumentException">Required configuration is invalid or contains a retired runtime gate.</exception>
    /// <remarks>Used by Function dependency injection. Settings are resolved on construction, not reloaded each cycle.</remarks>
    public RunnerApplication(TokenCredential credential, ILoggerFactory loggerFactory)
        : this(RunnerOptions.Parse([]), credential, loggerFactory)
    {
    }

    /// <summary>Creates the test runner from already resolved options and shared host dependencies.</summary>
    /// <param name="options">Options normally produced by <see cref="RunnerOptions.Parse"/>; no additional parsing occurs here.</param>
    /// <param name="credential">Credential used by the clients; construction does not verify Azure permissions.</param>
    /// <param name="loggerFactory">Factory that routes child service logs through the host's providers.</param>
    internal RunnerApplication(RunnerOptions options, TokenCredential credential, ILoggerFactory loggerFactory)
    {
        _options = options;
        _credential = credential;
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<RunnerApplication>();
        _arm = new ArmResourceClient(credential, loggerFactory.CreateLogger<ArmResourceClient>());
        _scanner = new VaultInventoryScanner(credential, _arm, loggerFactory.CreateLogger<VaultInventoryScanner>());
        _objectExecutor = new ObjectExecutor(
            new ObjectReplicationVaultClientFactory(credential),
            loggerFactory.CreateLogger<ObjectExecutor>());
        _rbacExecutor = new RbacExecutor(
            new ArmRbacClient(credential),
            options.SyncPrincipalId,
            loggerFactory.CreateLogger<RbacExecutor>());
        var blobService = new BlobServiceClient(options.StorageAccountUri, credential, new BlobClientOptions());
        _stateStore = new BlobStateStore(blobService, options, loggerFactory);
        _logger.LogInformation("Runner application configured for {SubscriptionCount} subscriptions, storage host {StorageHost}, and state container {StateContainer}.",
            options.SubscriptionIds.Count, options.StorageAccountUri.Host, options.StateContainer);
    }

    /// <summary>Executes one cycle and persists its discovery, pair reports, plans, and final aggregate outcome.</summary>
    /// <param name="cancellationToken">Host cancellation propagated to Azure reads, writes, and lease work.</param>
    /// <returns>The completed run report, including partial or failed outcomes handled by orchestration.</returns>
    /// <exception cref="OperationCanceledException">The caller cancels; the recorded cancellation is not returned as success.</exception>
    /// <exception cref="InvalidOperationException">Protected HMAC configuration is malformed.</exception>
    /// <remarks>
    /// <para>State/HMAC initialization occurs before the run record is created and can throw directly.
    /// Every admitted pair must finish planning before mutation begins. Pair execution failures normally allow later
    /// already-planned pairs to proceed; failure to persist history can escalate to a run failure.
    /// Final history persistence is outside the run catch block and can itself throw.</para>
    /// <para>Complete means each admitted pair finished with no unapplied work, not that every planned resource type
    /// was synchronized. Inspect pair statuses and plan items, not just the presence of a persisted run record.</para>
    /// <para>An exception that escapes after the run is created carries its RunId, status, and run-record location in
    /// <see cref="Exception.Data"/> so the timer invocation can report where the detailed record lives.</para>
    /// </remarks>
    internal async Task<RunRecord> RunOnceAsync(CancellationToken cancellationToken)
    {
        // These prerequisites are outside the recorded cycle. If they fail, the host receives the
        // exception directly; no synthetic run ID, completion metric, or durable run record exists yet.
        _logger.LogDebug("RunOnce entered; loading optional HMAC configuration.");
        using var hmac = LoadSignatureService();
        _logger.LogDebug("HMAC configuration loaded. Available: {HmacConfigured}; key version: {HmacKeyVersion}.",
            hmac is not null, hmac?.KeyVersion);
        _logger.LogDebug("Initializing state containers.");
        try
        {
            await _stateStore.InitializeAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            AdminDiagnostics.LogSystemFailure(_logger, "StorageInitialization", exception);
            throw;
        }
        var cycleStarted = DateTimeOffset.UtcNow;
        var run = new RunRecord
        {
            RunId = $"{cycleStarted.ToUniversalTime().ToString("yyyyMMdd'T'HHmmssfffffff'Z'", CultureInfo.InvariantCulture)}-{Guid.NewGuid():N}",
            SubscriptionIds = _options.SubscriptionIds,
            StartedAt = cycleStarted,
            Mode = "AutomaticSync",
            Status = "Running",
        };
        var runRecordLocation = _stateStore.GetRunRecordLocation(run);
        try
        {
            return await ExecuteRunAsync(run, runRecordLocation, hmac, cancellationToken);
        }
        catch (Exception exception) when (AttachRunContext(exception, run, runRecordLocation))
        {
            // Unreachable: the filter annotates the exception and returns false, so it propagates unchanged.
            throw;
        }
    }

    private async Task<RunRecord> ExecuteRunAsync(
        RunRecord run,
        RunRecordLocation runRecordLocation,
        ObjectSignatureService? hmac,
        CancellationToken cancellationToken)
    {
        using var runActivity = StartRunActivity(run, runRecordLocation);
        var runTimer = Stopwatch.StartNew();
        run.TraceId = GetTraceId(Activity.Current);
        RunnerTelemetry.RunsStarted.Add(1, new KeyValuePair<string, object?>("sync.mode", run.Mode));
        // Every runner and child-service log in this cycle inherits these keys, so one RunId or blob name
        // groups the complete cycle even when the Application Insights operation ID is not at hand.
        using var runScope = _logger.BeginScope(new Dictionary<string, object?>
        {
            ["RunId"] = run.RunId,
            ["SubscriptionCount"] = run.SubscriptionIds.Count,
            ["Mode"] = run.Mode,
            ["RunRecordContainer"] = runRecordLocation.ContainerName,
            ["RunRecordBlobName"] = runRecordLocation.BlobName,
        });
        LogRunStarted(_logger, run, runRecordLocation);
        AdminDiagnostics.LogLifecycle(_logger, "Run", "Started");

        try
        {
            // Record Running before discovery so an interrupted process leaves evidence of an
            // unfinished attempt. Later writes replace this same run blob with accumulated progress.
            await _stateStore.WriteRunRecordAsync(run, cancellationToken);
            _logger.LogInformation(DiscoveryStartedEventId,
                "Starting complete Key Vault discovery across {SubscriptionCount} configured subscriptions using target-side {MappingTag}.",
                _options.SubscriptionIds.Count, KeyVaultSyncResourceTags.SyncSourceKeyVaultId);
            AdminDiagnostics.LogLifecycle(_logger, "Discovery", "Started");
            using var discoveryActivity = RunnerTelemetry.ActivitySource.StartActivity("sync.discover-vault-pairs");
            var discovery = await _arm.DiscoverPairsAsync(_options, cancellationToken);
            discoveryActivity?.SetTag("vault.discovered_count", discovery.DiscoveredVaultCount);
            discoveryActivity?.SetTag("sync.pair_count", discovery.Pairs.Count);
            discoveryActivity?.SetTag("sync.disabled_pair_count", discovery.DisabledPairCount);
            discoveryActivity?.SetTag("sync.mapping_issue_count", discovery.Issues.Count);
            run.DiscoveredVaultCount = discovery.DiscoveredVaultCount;
            run.TaggedPairCount = discovery.Pairs.Count;
            run.DisabledPairCount = discovery.DisabledPairCount;
            run.DisabledVaultNames.AddRange(discovery.DisabledVaultNames);
            run.UnmappedVaultCount = discovery.UnmappedVaultNames.Count;
            run.DiscoveryIssues.AddRange(discovery.Issues);
            _logger.LogInformation("Discovered {VaultCount} vaults, {PairCount} enabled pairs, {DisabledPairCount} disabled pairs, and {MappingIssueCount} mapping issues.",
                discovery.DiscoveredVaultCount, discovery.Pairs.Count, discovery.DisabledPairCount, discovery.Issues.Count);
            AdminDiagnostics.LogLifecycle(
                _logger,
                "Discovery",
                discovery.Issues.Count == 0 ? "Completed" : "CompletedWithIssues",
                discovery.Issues.Count == 0 ? "Continue" : "ReviewRequired");
            foreach (var issue in discovery.Issues)
            {
                _logger.LogWarning("Key Vault pair discovery issue. {Issue}.", issue);
            }

            if (discovery.Pairs.Count == 0)
            {
                _logger.LogInformation("No enabled Key Vault pairs were found. {DisabledPairCount} pairs were disabled; {UnmappedVaultCount} vaults were unmapped.",
                    discovery.DisabledPairCount, discovery.UnmappedVaultNames.Count);
            }

            // Acquire and retain each pair lease through both passes. This prevents state changes
            // between the persisted plan and execution while guaranteeing that every admitted pair
            // finishes planning before any Key Vault or RBAC mutation begins.
            var preparedPairs = new List<PreparedPair>();
            for (var pairIndex = 0; pairIndex < discovery.Pairs.Count; pairIndex++)
            {
                var pair = discovery.Pairs[pairIndex];
                var pairTimer = Stopwatch.StartNew();
                var pairRun = new PairScanReport
                {
                    PairId = pair.PairId,
                    SourceVaultId = pair.Source.Id,
                    TargetVaultId = pair.Target.Id,
                    Status = "Running",
                    StartedAt = DateTimeOffset.UtcNow,
                };
                using var pairActivity = RunnerTelemetry.ActivitySource.StartActivity("sync.scan-pair");
                pairActivity?.SetTag("sync.pair_id", pair.PairId);
                pairActivity?.SetTag("vault.source.name", pair.Source.Name);
                pairActivity?.SetTag("vault.target.name", pair.Target.Name);
                pairActivity?.SetTag("sync.pair_index", pairIndex + 1);
                pairActivity?.SetTag("sync.pair_count", discovery.Pairs.Count);
                using var pairScope = _logger.BeginScope(new Dictionary<string, object?>
                {
                    ["PairId"] = pair.PairId,
                    ["SourceVaultName"] = pair.Source.Name,
                    ["TargetVaultName"] = pair.Target.Name,
                    ["PairNumber"] = pairIndex + 1,
                    ["PairCount"] = discovery.Pairs.Count,
                });
                _logger.LogInformation(PairProgressEventId,
                    "Starting pair {PairNumber} of {PairCount}: {SourceVaultName} to {TargetVaultName}.",
                    pairIndex + 1, discovery.Pairs.Count, pair.Source.Name, pair.Target.Name);
                run.Pairs.Add(pairRun);
                await _stateStore.WriteRunRecordAsync(run, cancellationToken);

                PairLease? pairLease = null;
                try
                {
                    _logger.LogInformation(PairProgressEventId, "Acquiring the pair state lease.");
                    pairLease = await _stateStore.TryAcquirePairLeaseAsync(pair, cancellationToken);
                    if (pairLease is null)
                    {
                        // Lock contention is a recorded skip, not permission to scan/apply without
                        // state protection. It contributes to the aggregate Partial outcome below.
                        pairRun.Status = "SkippedPairAlreadyLocked";
                        pairRun.CompletedAt = DateTimeOffset.UtcNow;
                        pairRun.Errors.Add("Another runner currently holds this pair's Blob lease.");
                        _logger.LogWarning("Skipped pair {PairId} because another runner holds its state lease.", pair.PairId);
                        await _stateStore.WriteRunRecordAsync(run, cancellationToken);
                        continue;
                    }

                    pairLease.EnsureLeaseHeld();
                    _logger.LogInformation(PairProgressEventId, "Pair lease acquired; scanning source vault {SourceVaultName}.", pair.Source.Name);
                    pairRun.Source = await _scanner.ScanAsync(pair.Source, cancellationToken);
                    AdminDiagnostics.LogInventoryWarnings(_logger, pairRun.Source, "Source");
                    AdminDiagnostics.LogLifecycle(
                        _logger,
                        "SourceInventory",
                        pairRun.Source.Warnings.Count == 0 ? "Completed" : "CompletedWithWarnings",
                        pairRun.Source.Warnings.Count == 0 ? "Continue" : "BlockObjectMutation");
                    _logger.LogInformation(PairProgressEventId, "Source inventory complete for {SourceVaultName}; scanning target vault {TargetVaultName}.",
                        pair.Source.Name, pair.Target.Name);
                    pairRun.Target = await _scanner.ScanAsync(pair.Target, cancellationToken);
                    AdminDiagnostics.LogInventoryWarnings(_logger, pairRun.Target, "Target");
                    AdminDiagnostics.LogLifecycle(
                        _logger,
                        "TargetInventory",
                        pairRun.Target.Warnings.Count == 0 ? "Completed" : "CompletedWithWarnings",
                        pairRun.Target.Warnings.Count == 0 ? "Continue" : "BlockObjectMutation");
                    RunnerTelemetry.RecordInventory(pairRun.Source, "source");
                    RunnerTelemetry.RecordInventory(pairRun.Target, "target");
                    _logger.LogInformation(PairProgressEventId,
                        "Pair inventories complete. Source: {SourceSecretCount} secrets, {SourceKeyCount} keys, {SourceCertificateCount} certificates. Target: {TargetSecretCount} secrets, {TargetKeyCount} keys, {TargetCertificateCount} certificates.",
                        pairRun.Source.Secrets.Count, pairRun.Source.Keys.Count, pairRun.Source.Certificates.Count,
                        pairRun.Target.Secrets.Count, pairRun.Target.Keys.Count, pairRun.Target.Certificates.Count);
                    _logger.LogInformation(PlanningProgressEventId, "Creating the synchronization plan from inventory and committed pair state.");
                    pairRun.Plan.AddRange(ReplicationPlanner.CreatePlan(
                        pair,
                        pairLease.State,
                        pairRun.Source,
                        pairRun.Target,
                        hmac is not null,
                        _options.SyncPrincipalId,
                        DateTimeOffset.UtcNow));

                    var blockedPlanItems = pairRun.Plan.Count(item => item.Status.StartsWith("BLOCKED", StringComparison.Ordinal)
                        || item.Status.StartsWith("CONFLICT", StringComparison.Ordinal));
                    pairActivity?.SetTag("sync.plan.item_count", pairRun.Plan.Count);
                    pairActivity?.SetTag("sync.plan.blocked_item_count", blockedPlanItems);
                    if (blockedPlanItems > 0)
                    {
                        _logger.LogWarning("Pair plan created with blocked or conflicting items. {PlanItemCount} total items; {BlockedItemCount} blocked or conflicting.",
                            pairRun.Plan.Count, blockedPlanItems);
                    }
                    else
                    {
                        _logger.LogInformation("Pair plan created. {PlanItemCount} items; no blocked or conflicting items.", pairRun.Plan.Count);
                    }
                    AdminDiagnostics.LogPlanOutcomeGroups(_logger, pairRun.Plan, "Planning");
                    AdminDiagnostics.LogLifecycle(
                        _logger,
                        "Planning",
                        blockedPlanItems == 0 ? "Completed" : "CompletedWithBlockedItems",
                        blockedPlanItems == 0 ? "Execute" : "ReviewRequired");

                    var complete = pairRun.Source.Warnings.Count == 0 && pairRun.Target.Warnings.Count == 0;
                    if (complete)
                    {
                        pairLease.State.LastCompleteScanAt = DateTimeOffset.UtcNow;
                        pairLease.State.LastCompleteRunId = run.RunId;
                        _logger.LogInformation(PairProgressEventId, "Saving the complete-scan checkpoint for this pair.");
                        await pairLease.SaveStateAsync(cancellationToken);
                        pairRun.Status = "Planned";
                    }
                    else
                    {
                        pairRun.Status = "PartialInventory";
                        pairRun.Errors.Add("One or more inventory/read checks failed. This run cannot be used as deletion evidence.");
                    }

                    pairRun.CompletedAt = DateTimeOffset.UtcNow;
                    await _stateStore.WriteRunRecordAsync(run, cancellationToken);
                    preparedPairs.Add(new PreparedPair(pairIndex, pair, pairRun, pairLease, pairTimer));
                    pairLease = null;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    pairRun.Status = "Cancelled";
                    pairRun.CompletedAt = DateTimeOffset.UtcNow;
                    pairRun.Errors.Add("Function host requested cancellation.");
                    // Attempt the diagnostic write independently of the cancelled operation token.
                    // This is not a retry of any Key Vault write, and storage failure can still surface.
                    await _stateStore.WriteRunRecordAsync(run, CancellationToken.None);
                    throw;
                }
                catch (Exception exception)
                {
                    pairRun.Status = "Failed";
                    pairRun.CompletedAt = DateTimeOffset.UtcNow;
                    pairRun.Errors.Add(SafeError(exception));
                    AdminDiagnostics.LogSystemFailure(_logger, "PairScan", exception);
                    RunnerTelemetry.RecordException(pairActivity, exception);
                    pairActivity?.SetStatus(ActivityStatusCode.Error, exception.GetType().Name);
                    RunnerTelemetry.Failures.Add(1, new("sync.stage", "pair"), new("error.type", exception.GetType().Name));
                    _logger.LogError(exception, "Pair scan failed for {PairId}.", pair.PairId);
                    await _stateStore.WriteRunRecordAsync(run, CancellationToken.None);
                }
                finally
                {
                    if (pairLease is not null)
                    {
                        await pairLease.DisposeAsync();
                    }

                    if (pairRun.Status != "Planned")
                    {
                        pairTimer.Stop();
                    }

                    pairActivity?.SetTag("sync.status", pairRun.Status);
                    if (pairRun.Status is not "Planned" and not "SkippedPairAlreadyLocked")
                    {
                        pairActivity?.SetStatus(ActivityStatusCode.Error, pairRun.Status);
                    }

                    if (pairRun.Status != "Planned")
                    {
                        RecordPairCompletion(pairRun, pairTimer);
                    }
                }
            }

            try
            {
                if (preparedPairs.Count != discovery.Pairs.Count)
                {
                    foreach (var prepared in preparedPairs)
                    {
                        prepared.Report.Status = "ExecutionBlockedPlanningIncomplete";
                        prepared.Report.Errors.Add("At least one admitted pair did not finish planning; no mutations were attempted.");
                        prepared.Report.CompletedAt = DateTimeOffset.UtcNow;
                        prepared.Timer.Stop();
                        RecordPairCompletion(prepared.Report, prepared.Timer);
                    }

                    await _stateStore.WriteRunRecordAsync(run, cancellationToken);
                }
                else
                {
                    foreach (var prepared in preparedPairs)
                    {
                        await ExecutePreparedPairAsync(prepared, run.RunId, hmac, discovery.Pairs.Count, cancellationToken);
                        await _stateStore.WriteRunRecordAsync(run, cancellationToken);
                    }
                }
            }
            finally
            {
                foreach (var prepared in preparedPairs.AsEnumerable().Reverse())
                {
                    await prepared.Lease.DisposeAsync();
                }
            }

            // Disabled/unmapped vaults alone are an intentional no-op. Invalid mappings or any
            // pair other than a fully completed sync make the run Partial.
            run.CompletedAt = DateTimeOffset.UtcNow;
            run.Status = discovery.Issues.Count > 0 || run.Pairs.Any(pair => pair.Status != "SyncCompleted")
                ? "Partial"
                : run.Pairs.Count == 0 ? "NoConfiguredPairs" : "Complete";
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            run.CompletedAt = DateTimeOffset.UtcNow;
            run.Status = "Cancelled";
            run.DiscoveryIssues.Add("Function host requested cancellation.");
            // Report before the diagnostic write so a storage failure cannot hide the cancellation summary.
            // The Function observes the exception instead of a RunnerExecutionResult with this status.
            ReportRunCompletion(run, runActivity, runTimer, runRecordLocation);
            await _stateStore.WriteRunRecordAsync(run, CancellationToken.None);
            throw;
        }
        catch (Exception exception)
        {
            run.CompletedAt = DateTimeOffset.UtcNow;
            run.Status = "Failed";
            run.DiscoveryIssues.Add(SafeError(exception));
            RunnerTelemetry.RecordException(runActivity, exception);
            runActivity?.SetStatus(ActivityStatusCode.Error, exception.GetType().Name);
            RunnerTelemetry.Failures.Add(1, new("sync.stage", "run"), new("error.type", exception.GetType().Name));
            AdminDiagnostics.LogSystemFailure(_logger, "RunOrchestration", exception);
            _logger.LogError(exception, "Run {RunId} failed during discovery or orchestration.", run.RunId);
        }

        ReportRunCompletion(run, runActivity, runTimer, runRecordLocation);
        // Do not return a finalized report until the final persistence attempt succeeds. Metrics
        // above may already have been recorded if this write fails, so they are not durability proof.
        await _stateStore.WriteRunRecordAsync(run, CancellationToken.None);
        return run;
    }

    /// <summary>Emits the final metrics, run diagnostic, lifecycle transition, and value-free run summary once per cycle.</summary>
    private void ReportRunCompletion(RunRecord run, Activity? runActivity, Stopwatch runTimer, RunRecordLocation runRecordLocation)
    {
        runTimer.Stop();
        var summary = RunExecutionSummary.Create(run);
        CompleteRunActivity(runActivity, run, summary);
        RunnerTelemetry.RunsCompleted.Add(1, new KeyValuePair<string, object?>("sync.status", run.Status));
        RunnerTelemetry.RunDuration.Record(runTimer.Elapsed.TotalMilliseconds, new KeyValuePair<string, object?>("sync.status", run.Status));
        var runDiagnostic = AdminDiagnostics.ClassifyRunStatus(run.Status);
        _logger.Log(
            run.Status is "Complete" or "NoConfiguredPairs" ? LogLevel.Information : LogLevel.Warning,
            AdminDiagnostics.RunDiagnosticSummaryEventId,
            "Run diagnostic {DiagnosticCode}. Stage {DiagnosticStage}; outcome {DiagnosticOutcome}; status {RunStatus}; discovered vaults {DiscoveredVaultCount}; enabled pairs {PairCount}; disabled pairs {DisabledPairCount}; mapping issues {MappingIssueCount}; priority {AdminPriority}; evidence type {EvidenceType}; action decision {ActionDecision}; confidence {Confidence}; summary {DiagnosticSummary}; administrator action {AdminAction}.",
            runDiagnostic.Code,
            "Run",
            run.Status,
            run.Status,
            run.DiscoveredVaultCount,
            run.TaggedPairCount,
            run.DisabledPairCount,
            run.DiscoveryIssues.Count,
            AdminDiagnostics.GetPriority(runDiagnostic.Code),
            "Evidence",
            AdminDiagnostics.GetActionDecision(runDiagnostic),
            AdminDiagnostics.GetConfidence(runDiagnostic.Code),
            runDiagnostic.Summary,
            runDiagnostic.AdminAction);
        AdminDiagnostics.LogLifecycle(
            _logger,
            "Run",
            run.Status,
            run.Status is "Complete" or "NoConfiguredPairs" ? "NoActionRequired" : "ReviewRequired");
        LogRunCompleted(_logger, run, summary, runTimer.Elapsed, runRecordLocation);
    }

    /// <summary>Starts the cycle span as an in-process child of the Function invocation span.</summary>
    /// <remarks>Internal kind keeps the cycle out of the host-owned request list; the host invocation is the request.</remarks>
    internal static Activity? StartRunActivity(RunRecord run, RunRecordLocation runRecordLocation)
    {
        var activity = RunnerTelemetry.ActivitySource.StartActivity("sync.run", ActivityKind.Internal);
        activity?.SetTag("sync.run_id", run.RunId);
        activity?.SetTag("sync.mode", run.Mode);
        activity?.SetTag("azure.subscription_count", run.SubscriptionIds.Count);
        activity?.SetTag("sync.run_record.container", runRecordLocation.ContainerName);
        activity?.SetTag("sync.run_record.blob", runRecordLocation.BlobName);
        return activity;
    }

    /// <summary>Adds final value-free counts and sets Ok only for successful aggregate statuses.</summary>
    /// <remarks>An Error status already set with an exception type is preserved for failed cycles.</remarks>
    internal static void CompleteRunActivity(Activity? runActivity, RunRecord run, RunExecutionSummary summary)
    {
        if (runActivity is null)
        {
            return;
        }

        runActivity.SetTag("sync.status", run.Status);
        runActivity.SetTag("sync.pair_count", run.TaggedPairCount);
        runActivity.SetTag("sync.disabled_pair_count", run.DisabledPairCount);
        runActivity.SetTag("sync.discovered_vault_count", run.DiscoveredVaultCount);
        runActivity.SetTag("sync.discovery_issue_count", summary.DiscoveryIssueCount);
        runActivity.SetTag("sync.pair.attempted_count", summary.AttemptedPairCount);
        runActivity.SetTag("sync.pair.completed_count", summary.CompletedPairCount);
        runActivity.SetTag("sync.pair.attention_count", summary.AttentionPairCount);
        runActivity.SetTag("sync.pair.failed_count", summary.FailedPairCount);
        runActivity.SetTag("sync.plan.item_count", summary.PlanItemCount);
        runActivity.SetTag("sync.plan.attention_item_count", summary.AttentionItemCount);
        runActivity.SetTag("sync.object.verified_change_count", summary.VerifiedObjectChangeCount);
        runActivity.SetTag("sync.rbac.verified_change_count", summary.VerifiedRbacChangeCount);
        if (run.Status is "Complete" or "NoConfiguredPairs")
        {
            runActivity.SetStatus(ActivityStatusCode.Ok);
        }
        else if (runActivity.Status != ActivityStatusCode.Error)
        {
            runActivity.SetStatus(ActivityStatusCode.Error, run.Status);
        }
    }

    /// <summary>Returns the W3C trace ID that Application Insights stores as the operation ID.</summary>
    internal static string? GetTraceId(Activity? activity) =>
        activity?.IdFormat == ActivityIdFormat.W3C ? activity.TraceId.ToHexString() : null;

    internal static void LogRunStarted(ILogger logger, RunRecord run, RunRecordLocation runRecordLocation)
    {
        logger.LogInformation(
            RunStartedEventId,
            "Run {RunId} started in mapping-driven synchronization mode {Mode} across {SubscriptionCount} subscriptions. Trace {TraceId}; run record {RunRecordUri}.",
            run.RunId,
            run.Mode,
            run.SubscriptionIds.Count,
            run.TraceId ?? "unavailable",
            runRecordLocation.BlobUri);
    }

    // Keep the "Run {RunId} completed with status" prefix: the log analyzer reads legacy exports by that wording.
    internal static void LogRunCompleted(
        ILogger logger,
        RunRecord run,
        RunExecutionSummary summary,
        TimeSpan elapsed,
        RunRecordLocation runRecordLocation)
    {
        logger.Log(
            run.Status switch
            {
                "Complete" or "NoConfiguredPairs" => LogLevel.Information,
                "Failed" => LogLevel.Critical,
                _ => LogLevel.Warning,
            },
            RunCompletedEventId,
            "Run {RunId} completed with status {RunStatus} in {DurationMs} ms. Discovered vaults {DiscoveredVaultCount}; enabled pairs {EnabledPairCount}; disabled pairs {DisabledPairCount}; unmapped vaults {UnmappedVaultCount}; discovery issues {DiscoveryIssueCount}; attempted pairs {AttemptedPairCount}; completed pairs {CompletedPairCount}; pairs needing attention {AttentionPairCount}; failed pairs {FailedPairCount}; pair statuses {PairStatusCounts}; plan items {PlanItemCount}; attention items {AttentionItemCount}; verified object changes {VerifiedObjectChangeCount}; verified RBAC changes {VerifiedRbacChangeCount}; run record {RunRecordUri}.",
            run.RunId,
            run.Status,
            (long)Math.Round(elapsed.TotalMilliseconds),
            summary.DiscoveredVaultCount,
            summary.EnabledPairCount,
            summary.DisabledPairCount,
            summary.UnmappedVaultCount,
            summary.DiscoveryIssueCount,
            summary.AttemptedPairCount,
            summary.CompletedPairCount,
            summary.AttentionPairCount,
            summary.FailedPairCount,
            summary.PairStatusCounts,
            summary.PlanItemCount,
            summary.AttentionItemCount,
            summary.VerifiedObjectChangeCount,
            summary.VerifiedRbacChangeCount,
            runRecordLocation.BlobUri);
    }

    /// <summary>Runs one scheduled cycle and exposes a small host-facing result instead of the internal inventory model.</summary>
    /// <param name="cancellationToken">The Function invocation's shutdown/cancellation token.</param>
    /// <returns>The run ID, aggregate status, run-record location, and value-free summary after final persistence succeeds.</returns>
    /// <exception cref="OperationCanceledException">Cancellation propagates after an attempt to persist its outcome.</exception>
    /// <remarks>No scheduling or retry policy is implemented here. The Function maps the result to invocation behavior.</remarks>
    public async Task<RunnerExecutionResult> ExecuteScheduledRunAsync(CancellationToken cancellationToken)
    {
        var run = await RunOnceAsync(cancellationToken);
        return new RunnerExecutionResult(run.RunId, run.Status)
        {
            RunRecordLocation = _stateStore.GetRunRecordLocation(run),
            Summary = RunExecutionSummary.Create(run),
        };
    }

    // Exception filter helper: annotating inside the filter preserves the original throw site and stack.
    private static bool AttachRunContext(Exception exception, RunRecord run, RunRecordLocation runRecordLocation)
    {
        RunExceptionContext.Attach(exception, run, runRecordLocation);
        return false;
    }

    private async Task ExecutePreparedPairAsync(
        PreparedPair prepared,
        string runId,
        ObjectSignatureService? signatures,
        int pairCount,
        CancellationToken cancellationToken)
    {
        var pair = prepared.Pair;
        var report = prepared.Report;
        using var pairScope = _logger.BeginScope(new Dictionary<string, object?>
        {
            ["PairId"] = pair.PairId,
            ["SourceVaultName"] = pair.Source.Name,
            ["TargetVaultName"] = pair.Target.Name,
            ["PairNumber"] = prepared.PairIndex + 1,
            ["PairCount"] = pairCount,
        });
        using var activity = RunnerTelemetry.ActivitySource.StartActivity("sync.execute-pair");
        activity?.SetTag("sync.pair_id", pair.PairId);
        activity?.SetTag("sync.pair_index", prepared.PairIndex + 1);
        activity?.SetTag("sync.pair_count", pairCount);

        try
        {
            report.Status = "Executing";
            report.CompletedAt = null;
            prepared.Lease.EnsureLeaseHeld();
            AdminDiagnostics.LogLifecycle(_logger, "Execution", "Started");

            await ApplyRbacPhaseAsync(VaultRbacCreatePhase, report.Plan, item =>
                item.Action == "CreateRoleAssignment" && !IsObjectScope(item.TargetScope),
                cancellationToken);

            if (signatures is not null)
            {
                await ApplyObjectPhaseAsync(
                    ObjectCreateReconcilePhase,
                    pair,
                    prepared.Lease,
                    runId,
                    report.Plan,
                    signatures,
                    item => item.Action is "CreateObject" or "ReconcileObject",
                    cancellationToken);
            }

            BlockDependentObjectRbac(report.Plan, signatures is not null);
            await ApplyRbacPhaseAsync(ObjectRbacCreatePhase, report.Plan, item =>
                item.Action == "CreateRoleAssignment" && IsObjectScope(item.TargetScope),
                cancellationToken);
            await ApplyRbacPhaseAsync(ObjectRbacDeletePhase, report.Plan, item =>
                item.Action == "DeleteRoleAssignment" && IsObjectScope(item.TargetScope),
                cancellationToken);

            if (signatures is not null)
            {
                await ApplyObjectPhaseAsync(
                    ObjectDeletePhase,
                    pair,
                    prepared.Lease,
                    runId,
                    report.Plan,
                    signatures,
                    item => item.Action == "DeleteObject",
                    cancellationToken);
            }

            await ApplyRbacPhaseAsync(VaultRbacDeletePhase, report.Plan, item =>
                item.Action == "DeleteRoleAssignment" && !IsObjectScope(item.TargetScope),
                cancellationToken);

            report.Status = HasUnappliedWork(report.Plan) ? "SyncCompletedWithUnappliedWork" : "SyncCompleted";
            report.CompletedAt = DateTimeOffset.UtcNow;
            AdminDiagnostics.LogPlanOutcomeGroups(_logger, report.Plan, "Execution");
            AdminDiagnostics.LogLifecycle(
                _logger,
                "Execution",
                report.Status,
                report.Status == "SyncCompleted" ? "NoActionRequired" : "ReviewRequired");
            activity?.SetStatus(report.Status == "SyncCompleted" ? ActivityStatusCode.Ok : ActivityStatusCode.Error, report.Status);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            report.Status = "Cancelled";
            report.CompletedAt = DateTimeOffset.UtcNow;
            report.Errors.Add("Function host requested cancellation.");
            throw;
        }
        catch (Exception exception)
        {
            report.Status = "Failed";
            report.CompletedAt = DateTimeOffset.UtcNow;
            report.Errors.Add(SafeError(exception));
            AdminDiagnostics.LogSystemFailure(_logger, "PairExecution", exception);
            RunnerTelemetry.RecordException(activity, exception);
            activity?.SetStatus(ActivityStatusCode.Error, exception.GetType().Name);
            _logger.LogError(exception, "Pair execution failed for {PairId}.", pair.PairId);
        }
        finally
        {
            prepared.Timer.Stop();
            RecordPairCompletion(report, prepared.Timer);
        }
    }

    private void RecordPairCompletion(PairScanReport report, Stopwatch timer)
    {
        var pairDiagnostic = AdminDiagnostics.ClassifyPairStatus(report.Status);
        var attentionItemCount = report.Plan.Count(item => AdminDiagnostics.RequiresAdminAttention(item.Status));
        var sourceWarningCount = report.Source?.Warnings.Count ?? 0;
        var targetWarningCount = report.Target?.Warnings.Count ?? 0;
        var failedRbacCount = report.Plan.Count(item =>
            item.ObjectType == "Authorization" && item.Status.Contains("FAILED", StringComparison.Ordinal));
        _logger.Log(
            report.Status == "SyncCompleted" ? LogLevel.Information : LogLevel.Warning,
            AdminDiagnostics.PairDiagnosticSummaryEventId,
            "Pair diagnostic {DiagnosticCode}. Stage {DiagnosticStage}; outcome {DiagnosticOutcome}; status {PairStatus}; source warnings {SourceWarningCount}; target warnings {TargetWarningCount}; attention items {AttentionItemCount}; failed RBAC items {FailedRbacCount}; priority {AdminPriority}; evidence type {EvidenceType}; action decision {ActionDecision}; confidence {Confidence}; summary {DiagnosticSummary}; administrator action {AdminAction}.",
            pairDiagnostic.Code,
            "Pair",
            report.Status,
            report.Status,
            sourceWarningCount,
            targetWarningCount,
            attentionItemCount,
            failedRbacCount,
            AdminDiagnostics.GetPriority(pairDiagnostic.Code),
            "Evidence",
            AdminDiagnostics.GetActionDecision(pairDiagnostic),
            AdminDiagnostics.GetConfidence(pairDiagnostic.Code),
            pairDiagnostic.Summary,
            pairDiagnostic.AdminAction);
        RunnerTelemetry.PairsProcessed.Add(1, new KeyValuePair<string, object?>("sync.status", report.Status));
        RunnerTelemetry.PairDuration.Record(timer.Elapsed.TotalMilliseconds, new KeyValuePair<string, object?>("sync.status", report.Status));
        const string message = "Pair {PairId} completed with status {Status} in {DurationMs} ms.";
        if (report.Status == "Failed")
        {
            _logger.LogError(message, report.PairId, report.Status, timer.Elapsed.TotalMilliseconds);
        }
        else if (report.Status is "PartialInventory" or "SyncCompletedWithUnappliedWork" or "ExecutionBlockedPlanningIncomplete")
        {
            _logger.LogWarning(message, report.PairId, report.Status, timer.Elapsed.TotalMilliseconds);
        }
        else
        {
            _logger.LogInformation(message, report.PairId, report.Status, timer.Elapsed.TotalMilliseconds);
        }
    }

    private Task ApplyObjectPhaseAsync(
        string phase,
        VaultPair pair,
        IPairStateLease pairLease,
        string runId,
        List<PlanItem> plan,
        ObjectSignatureService signatures,
        Func<PlanItem, bool> predicate,
        CancellationToken cancellationToken) =>
        RunExecutionPhaseAsync(
            phase,
            plan,
            predicate,
            selected => _objectExecutor.ApplyAsync(pair, pairLease, runId, selected, signatures, cancellationToken),
            cancellationToken);

    private Task ApplyRbacPhaseAsync(
        string phase,
        List<PlanItem> plan,
        Func<PlanItem, bool> predicate,
        CancellationToken cancellationToken) =>
        RunExecutionPhaseAsync(
            phase,
            plan,
            predicate,
            selected => _rbacExecutor.ApplyAsync(selected, cancellationToken),
            cancellationToken);

    // One span and one 3006 record per phase show where a pair's execution time and failures occur
    // without logging per-object identifiers beyond what the executors already report.
    private async Task RunExecutionPhaseAsync(
        string phase,
        List<PlanItem> plan,
        Func<PlanItem, bool> predicate,
        Func<PlanItem[], Task<IReadOnlyList<PlanItem>>> executePhase,
        CancellationToken cancellationToken)
    {
        var selected = plan.Where(predicate).ToArray();
        using var phaseScope = _logger.BeginScope(new Dictionary<string, object?> { ["ExecutionPhase"] = phase });
        using var phaseActivity = StartExecutionPhaseActivity(phase, selected.Length);
        var phaseTimer = Stopwatch.StartNew();
        IReadOnlyList<PlanItem> results;
        try
        {
            results = await executePhase(selected);
        }
        catch (Exception exception)
        {
            phaseTimer.Stop();
            ReportExecutionPhaseInterrupted(
                _logger,
                phaseActivity,
                phase,
                selected.Length,
                exception,
                exception is OperationCanceledException && cancellationToken.IsCancellationRequested,
                phaseTimer.Elapsed);
            throw;
        }

        phaseTimer.Stop();
        ReplaceResults(plan, results);
        ReportExecutionPhaseCompleted(_logger, phaseActivity, phase, selected.Length, results, phaseTimer.Elapsed);
    }

    /// <summary>Starts a phase span only when the phase has work, keeping empty phases out of trace timelines.</summary>
    internal static Activity? StartExecutionPhaseActivity(string phase, int itemCount)
    {
        if (itemCount == 0)
        {
            return null;
        }

        var activity = RunnerTelemetry.ActivitySource.StartActivity("sync.execute-phase");
        if (activity is not null)
        {
            // The phase set is fixed and small, so a phase-specific display name stays low-cardinality.
            activity.DisplayName = $"sync.execute-phase {phase}";
            activity.SetTag("sync.phase", phase);
            activity.SetTag("sync.phase.item_count", itemCount);
        }

        return activity;
    }

    /// <summary>Reports a finished phase with verified-change, no-change, and attention counts.</summary>
    internal static void ReportExecutionPhaseCompleted(
        ILogger logger,
        Activity? phaseActivity,
        string phase,
        int itemCount,
        IReadOnlyList<PlanItem> results,
        TimeSpan elapsed)
    {
        var verifiedChangeCount = RunExecutionSummary.CountVerifiedObjectChanges(results)
            + RunExecutionSummary.CountVerifiedRbacChanges(results);
        var attentionCount = results.Count(item => AdminDiagnostics.RequiresAdminAttention(item.Status));
        var noChangeCount = Math.Max(0, results.Count - verifiedChangeCount - attentionCount);
        var outcome = itemCount == 0 ? "NoItems" : attentionCount > 0 ? "CompletedWithAttention" : "Completed";
        if (phaseActivity is not null)
        {
            phaseActivity.SetTag("sync.phase.outcome", outcome);
            phaseActivity.SetTag("sync.phase.verified_change_count", verifiedChangeCount);
            phaseActivity.SetTag("sync.phase.attention_count", attentionCount);
            if (attentionCount > 0)
            {
                phaseActivity.SetStatus(ActivityStatusCode.Error, outcome);
            }
            else
            {
                phaseActivity.SetStatus(ActivityStatusCode.Ok);
            }
        }

        logger.Log(
            itemCount == 0 ? LogLevel.Debug : attentionCount > 0 ? LogLevel.Warning : LogLevel.Information,
            ExecutionPhaseCompletedEventId,
            "Execution phase {ExecutionPhase} finished with outcome {PhaseOutcome} in {DurationMs} ms: {PhaseItemCount} items; {PhaseVerifiedChangeCount} verified changes; {PhaseNoChangeCount} needed no change; {PhaseAttentionCount} need attention.",
            phase,
            outcome,
            (long)Math.Round(elapsed.TotalMilliseconds),
            itemCount,
            verifiedChangeCount,
            noChangeCount,
            attentionCount);
    }

    /// <summary>Reports a phase that ended with an exception; the pair-level handler logs the exception itself.</summary>
    internal static void ReportExecutionPhaseInterrupted(
        ILogger logger,
        Activity? phaseActivity,
        string phase,
        int itemCount,
        Exception exception,
        bool cancelled,
        TimeSpan elapsed)
    {
        var outcome = cancelled ? "Cancelled" : "Failed";
        var errorType = exception.GetType().Name;
        if (phaseActivity is not null)
        {
            if (!cancelled)
            {
                RunnerTelemetry.RecordException(phaseActivity, exception);
            }

            phaseActivity.SetTag("sync.phase.outcome", outcome);
            phaseActivity.SetTag("error.type", errorType);
            phaseActivity.SetStatus(ActivityStatusCode.Error, errorType);
        }

        logger.Log(
            cancelled ? LogLevel.Warning : LogLevel.Error,
            ExecutionPhaseCompletedEventId,
            "Execution phase {ExecutionPhase} finished with outcome {PhaseOutcome} in {DurationMs} ms after the executor raised {ErrorType}: {PhaseItemCount} items were selected.",
            phase,
            outcome,
            (long)Math.Round(elapsed.TotalMilliseconds),
            errorType,
            itemCount);
    }

    private static void ReplaceResults(List<PlanItem> plan, IReadOnlyList<PlanItem> results)
    {
        foreach (var result in results)
        {
            var index = plan.FindIndex(item => IsSamePlanIdentity(item, result));
            if (index >= 0)
            {
                plan[index] = result;
            }
        }
    }

    internal static bool IsSamePlanIdentity(PlanItem left, PlanItem right) =>
        left.ObjectType == right.ObjectType
        && left.Name.Equals(right.Name, StringComparison.OrdinalIgnoreCase)
        && left.Action == right.Action
        && string.Equals(left.TargetScope, right.TargetScope, StringComparison.OrdinalIgnoreCase)
        && string.Equals(left.AssignmentId, right.AssignmentId, StringComparison.OrdinalIgnoreCase);

    internal static void BlockDependentObjectRbac(List<PlanItem> plan, bool objectMutationEnabled)
    {
        for (var index = 0; index < plan.Count; index++)
        {
            var item = plan[index];
            if (item.ObjectType != "Authorization"
                || item.Action is not ("CreateRoleAssignment" or "DeleteRoleAssignment")
                || string.IsNullOrWhiteSpace(item.TargetScope))
            {
                continue;
            }

            var segments = item.TargetScope.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (segments.Length < 2
                || (!segments[^2].Equals("secrets", StringComparison.OrdinalIgnoreCase)
                    && !segments[^2].Equals("keys", StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            var objectType = segments[^2].Equals("secrets", StringComparison.OrdinalIgnoreCase) ? "Secret" : "Key";
            var objectName = Uri.UnescapeDataString(segments[^1]);
            var objectPlan = plan.FirstOrDefault(candidate =>
                candidate.ObjectType == objectType
                && candidate.Name.Equals(objectName, StringComparison.OrdinalIgnoreCase));
            var dependencySatisfied = objectPlan is not null
                && (objectPlan.Status is "OBJECT_REPLICATED_AND_VERIFIED" or "IN_SYNC_SIGNATURE_VERIFIED"
                    or "BLOCKED_KEY_MATERIAL_EQUIVALENCE_UNVERIFIABLE"
                    || (item.Action == "DeleteRoleAssignment"
                        && objectMutationEnabled
                        && objectPlan.Action == "DeleteObject"));
            if (!dependencySatisfied)
            {
                plan[index] = item with
                {
                    Action = "None",
                    Status = "BLOCKED_DEPENDENCY_FAILED",
                    Detail = "The object prerequisite did not complete successfully.",
                };
            }
        }
    }

    private static bool IsObjectScope(string? scope) =>
        scope?.Contains("/secrets/", StringComparison.OrdinalIgnoreCase) == true
        || scope?.Contains("/keys/", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>Reduces Azure request failures to HTTP/code metadata for persisted reports.</summary>
    /// <remarks>
    /// Other exception messages are retained verbatim. This is not general-purpose sanitization,
    /// and full exceptions are also logged elsewhere; callers must not place secret payloads in exceptions.
    /// </remarks>
    private ObjectSignatureService? LoadSignatureService()
    {
        try
        {
            return ObjectSignatureService.Load(_options);
        }
        catch (Exception exception)
        {
            AdminDiagnostics.LogSystemFailure(_logger, "HmacConfiguration", exception);
            throw;
        }
    }

    private static string SafeError(Exception exception)
    {
        return exception is global::Azure.RequestFailedException requestFailure
            ? $"{exception.GetType().Name}: HTTP {requestFailure.Status}, error {requestFailure.ErrorCode ?? "unknown"}."
            : $"{exception.GetType().Name}: {exception.Message}";
    }

    internal static bool HasUnappliedWork(IReadOnlyList<PlanItem> plan)
    {
        foreach (var item in plan)
        {
            if (item.Status.StartsWith("BLOCKED", StringComparison.Ordinal)
                || item.Status.StartsWith("CONFLICT", StringComparison.Ordinal)
                || item.Status.Contains("FAILED", StringComparison.Ordinal)
                || item.Status.Contains("UNRESOLVED", StringComparison.Ordinal)
                || (item.ObjectType == "Authorization"
                    && item.Status is not ("RBAC_ASSIGNMENT_IN_SYNC"
                        or "RBAC_ASSIGNMENT_CREATED_AND_VERIFIED"
                        or "RBAC_ASSIGNMENT_DELETED_AND_VERIFIED"
                        or "RBAC_ALREADY_ABSENT"
                        or "SKIPPED_SYNC_IDENTITY_SELF_ASSIGNMENT"
                        or "RBAC_DELETE_SKIPPED_SYNC_IDENTITY"
                        or "RBAC_ASSIGNMENT_INTENT_MATCH"
                        or "ACCESS_POLICY_INTENT_MATCH")))
            {
                return true;
            }
        }

        return false;
    }

    private sealed record PreparedPair(
        int PairIndex,
        VaultPair Pair,
        PairScanReport Report,
        PairLease Lease,
        Stopwatch Timer);
}

/// <summary>The host-facing identity and aggregate outcome of a cycle whose report was returned by the runner.</summary>
/// <param name="RunId">Correlation key used by logs, activities, and the dated run-history blob.</param>
/// <param name="Status">Aggregate result such as Complete, NoConfiguredPairs, Partial, or Failed; not a per-secret result.</param>
public sealed record RunnerExecutionResult(string RunId, string Status)
{
    /// <summary>Gets the private run-history blob that holds the detailed pair and plan-item report.</summary>
    public required RunRecordLocation RunRecordLocation { get; init; }

    /// <summary>Gets value-free aggregate counts for invocation logging and trace tags.</summary>
    public required RunExecutionSummary Summary { get; init; }
}
