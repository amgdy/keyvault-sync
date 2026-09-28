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
/// <para>Both hosts use this implementation. It owns no scheduling loop and creates neither source nor
/// target Key Vaults. Azure clients are reused across calls; pair state is protected by cooperative Blob leases.</para>
/// <para>An enabled source/target mapping opts that pair into supported synchronization. Standalone-secret writes
/// retain HMAC and intent checks; eligible native key/certificate-group seeds remain one-time operations.
/// Authorization changes and deletion remain plan-only.</para>
/// </remarks>
public sealed class RunnerApplication
{
    // These IDs describe orchestration stages. Child services supply their own event IDs while
    // inheriting the RunId/PairId scopes, so operators can correlate work across logger categories.
    private static readonly EventId DiscoveryStartedEventId = new(3000, "DiscoveryStarted");
    private static readonly EventId PairProgressEventId = new(3001, "PairProgress");
    private static readonly EventId PlanningProgressEventId = new(3002, "PlanningProgress");
    private static readonly EventId SecretSyncProgressEventId = new(3003, "SecretSyncProgress");

    private readonly RunnerOptions _options;
    private readonly TokenCredential _credential;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<RunnerApplication> _logger;
    private readonly ArmResourceClient _arm;
    private readonly VaultInventoryScanner _scanner;
    private readonly SecretSyncExecutor _secretExecutor;
    private readonly NativeSeedExecutor _nativeSeedExecutor;
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

    /// <summary>Creates the console/test runner from already resolved options and shared host dependencies.</summary>
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
        _secretExecutor = new SecretSyncExecutor(credential, loggerFactory.CreateLogger<SecretSyncExecutor>());
        _nativeSeedExecutor = new NativeSeedExecutor(
            new NativeSeedVaultClientFactory(credential),
            loggerFactory.CreateLogger<NativeSeedExecutor>());
        var blobService = new BlobServiceClient(options.StorageAccountUri, credential, new BlobClientOptions());
        _stateStore = new BlobStateStore(blobService, options, loggerFactory);
        _logger.LogInformation("Runner application configured for subscription {SubscriptionId}, storage host {StorageHost}, and state container {StateContainer}.",
            options.SubscriptionId, options.StorageAccountUri.Host, options.StateContainer);
    }

    /// <summary>Executes one cycle and persists its discovery, pair reports, plans, and final aggregate outcome.</summary>
    /// <param name="cancellationToken">Host cancellation propagated to Azure reads, writes, and lease work.</param>
    /// <returns>The completed run report, including partial or failed outcomes handled by orchestration.</returns>
    /// <exception cref="OperationCanceledException">The caller cancels; the recorded cancellation is not returned as success.</exception>
    /// <exception cref="InvalidOperationException">Protected HMAC configuration is malformed.</exception>
    /// <remarks>
    /// <para>State/HMAC initialization occurs before the run record is created and can throw directly.
    /// Pair failures normally allow later pairs to proceed; failure to persist history can escalate to a run failure.
    /// Final history persistence is outside the run catch block and can itself throw.</para>
    /// <para>Complete means each admitted pair finished with no unapplied work, not that every planned resource type
    /// was synchronized. Inspect pair statuses and plan items, not just the presence of a persisted run record.</para>
    /// </remarks>
    internal async Task<RunRecord> RunOnceAsync(CancellationToken cancellationToken)
    {
        // These prerequisites are outside the recorded cycle. If they fail, the host receives the
        // exception directly; no synthetic run ID, completion metric, or durable run record exists yet.
        _logger.LogDebug("RunOnce entered; loading optional HMAC configuration.");
        using var hmac = SecretHmacService.Load(_options);
        _logger.LogDebug("HMAC configuration loaded. Available: {HmacConfigured}; key version: {HmacKeyVersion}.",
            hmac is not null, hmac?.KeyVersion);
        _logger.LogDebug("Initializing state containers.");
        await _stateStore.InitializeAsync(cancellationToken);
        var cycleStarted = DateTimeOffset.UtcNow;
        var run = new RunRecord
        {
            RunId = $"{cycleStarted.ToUniversalTime().ToString("yyyyMMdd'T'HHmmssfffffff'Z'", CultureInfo.InvariantCulture)}-{Guid.NewGuid():N}",
            SubscriptionId = _options.SubscriptionId,
            StartedAt = cycleStarted,
            Mode = "AutomaticSync",
            Status = "Running",
        };
        using var runActivity = RunnerTelemetry.ActivitySource.StartActivity("sync.run", ActivityKind.Server);
        var runTimer = Stopwatch.StartNew();
        runActivity?.SetTag("sync.run_id", run.RunId);
        runActivity?.SetTag("sync.mode", run.Mode);
        runActivity?.SetTag("azure.subscription_id", run.SubscriptionId);
        RunnerTelemetry.RunsStarted.Add(1, new KeyValuePair<string, object?>("sync.mode", run.Mode));
        using var runScope = _logger.BeginScope(new Dictionary<string, object?>
        {
            ["RunId"] = run.RunId,
            ["SubscriptionId"] = run.SubscriptionId,
            ["Mode"] = run.Mode,
        });
        _logger.LogInformation("Run {RunId} started in mapping-driven synchronization mode {Mode} for subscription {SubscriptionId}.",
            run.RunId, run.Mode, run.SubscriptionId);

        try
        {
            // Record Running before discovery so an interrupted process leaves evidence of an
            // unfinished attempt. Later writes replace this same run blob with accumulated progress.
            await _stateStore.WriteRunRecordAsync(run, cancellationToken);
            _logger.LogInformation(DiscoveryStartedEventId,
                "Starting subscription Key Vault discovery. {PairTag}; resource group filter: {ResourceGroupFilter}.",
                _options.PairTag, _options.ResourceGroup);
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
            foreach (var issue in discovery.Issues)
            {
                _logger.LogWarning("Key Vault pair discovery issue. {Issue}.", issue);
            }

            if (discovery.Pairs.Count == 0)
            {
                _logger.LogInformation("No enabled Key Vault pairs were found. {DisabledPairCount} pairs were disabled; {UnmappedVaultCount} vaults were unmapped.",
                    discovery.DisabledPairCount, discovery.UnmappedVaultNames.Count);
            }

            // Pairs are deliberately processed sequentially. Each owns a separate state lease;
            // another process may handle other pairs, but should not share this pair concurrently.
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

                try
                {
                    _logger.LogInformation(PairProgressEventId, "Acquiring the pair state lease.");
                    await using var pairLease = await _stateStore.TryAcquirePairLeaseAsync(pair, cancellationToken);
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
                    _logger.LogInformation(PairProgressEventId, "Source inventory complete for {SourceVaultName}; scanning target vault {TargetVaultName}.",
                        pair.Source.Name, pair.Target.Name);
                    pairRun.Target = await _scanner.ScanAsync(pair.Target, cancellationToken);
                    RunnerTelemetry.RecordInventory(pairRun.Source, "source");
                    RunnerTelemetry.RecordInventory(pairRun.Target, "target");
                    _logger.LogInformation(PairProgressEventId,
                        "Pair inventories complete. Source: {SourceSecretCount} secrets, {SourceKeyCount} keys, {SourceCertificateCount} certificates. Target: {TargetSecretCount} secrets, {TargetKeyCount} keys, {TargetCertificateCount} certificates.",
                        pairRun.Source.Secrets.Count, pairRun.Source.Keys.Count, pairRun.Source.Certificates.Count,
                        pairRun.Target.Secrets.Count, pairRun.Target.Keys.Count, pairRun.Target.Certificates.Count);
                    _logger.LogInformation(PlanningProgressEventId, "Creating the synchronization plan from inventory and committed pair state.");
                    pairRun.Plan.AddRange(SyncPlanner.CreatePlan(pair, pairLease.State, pairRun.Source, pairRun.Target, hmac is not null));
                    // The planner does not read secret values or mutate Azure. With a configured HMAC
                    // key, supported secret actions enter the executor, which rechecks live preconditions.
                    if (hmac is not null)
                    {
                        var eligibleSecretCount = pairRun.Plan.Count(item => item.ObjectType == "Secret"
                            && (item.Action is "SetSecret" or "UpdateSecretProperties" or "VerifySecretBaseline")
                            && (item.Status is "READY_FOR_APPLY_IF_NAME_STAYS_EMPTY"
                                or "VERIFY_TARGET_HMAC_THEN_APPLY"
                                or "VERIFY_TARGET_HMAC_THEN_APPLY_METADATA"
                                or "VERIFY_TARGET_HMAC"));
                        _logger.LogInformation(SecretSyncProgressEventId,
                            "Secret synchronization started for pair {PairNumber} of {PairCount}; {EligibleSecretCount} plan items are eligible.",
                            pairIndex + 1, discovery.Pairs.Count, eligibleSecretCount);
                        var secretResults = await _secretExecutor.ApplyAsync(
                            pair,
                            pairLease,
                            run.RunId,
                            pairRun.Plan,
                            pairRun.Source,
                            pairRun.Target,
                            hmac,
                            cancellationToken);
                        foreach (var result in secretResults)
                        {
                            // Replace the proposal for this secret with its actual execution outcome;
                            // unrelated plan-only object types remain visible in the report.
                            var planIndex = pairRun.Plan.FindIndex(item => item.ObjectType == result.ObjectType
                                && item.Name.Equals(result.Name, StringComparison.OrdinalIgnoreCase));
                            if (planIndex >= 0)
                            {
                                pairRun.Plan[planIndex] = result;
                            }
                        }
                        _logger.LogInformation(SecretSyncProgressEventId,
                            "Secret synchronization finished for pair {PairNumber} of {PairCount}; {ResultCount} outcomes recorded.",
                            pairIndex + 1, discovery.Pairs.Count, secretResults.Count);
                    }
                    else
                    {
                        var blockedSecretCount = pairRun.Plan.Count(item =>
                            item.ObjectType == "Secret" && item.Status == "BLOCKED_HMAC_KEY_NOT_CONFIGURED");
                        if (blockedSecretCount > 0)
                        {
                            _logger.LogWarning(
                                "Automatic secret synchronization is blocked for pair {PairNumber} of {PairCount}; {BlockedSecretCount} plan items require KEYVAULTSYNC_HMAC_KEY. Eligible one-time key/certificate seeds are evaluated separately.",
                                pairIndex + 1, discovery.Pairs.Count, blockedSecretCount);
                        }
                    }

                    var eligibleSeedCount = pairRun.Plan.Count(item =>
                        (item.ObjectType == "Key" && item.Action == "NativeRestore" && item.Status == "ELIGIBLE_ONE_TIME_SEED_IF_TARGET_STAYS_EMPTY")
                        || (item.ObjectType == "CertificateGroup" && item.Action == "NativeRestore" && item.Status == "ELIGIBLE_ONE_TIME_SEED_IF_TARGET_GROUP_STAYS_EMPTY"));
                    _logger.LogInformation(PairProgressEventId,
                        "One-time native seed phase started for pair {PairNumber} of {PairCount}; {EligibleSeedCount} plan items are eligible.",
                        pairIndex + 1, discovery.Pairs.Count, eligibleSeedCount);
                    var seedResults = await _nativeSeedExecutor.ApplyAsync(
                        pair,
                        pairLease,
                        run.RunId,
                        pairRun.Plan,
                        pairRun.Source,
                        cancellationToken);
                    foreach (var result in seedResults)
                    {
                        var planIndex = pairRun.Plan.FindIndex(item => item.ObjectType == result.ObjectType
                            && item.Name.Equals(result.Name, StringComparison.OrdinalIgnoreCase));
                        if (planIndex >= 0)
                        {
                            pairRun.Plan[planIndex] = result;
                        }
                    }

                    _logger.LogInformation(PairProgressEventId,
                        "One-time native seed phase finished for pair {PairNumber} of {PairCount}; {ResultCount} outcomes recorded.",
                        pairIndex + 1, discovery.Pairs.Count, seedResults.Count);

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

                    // This checkpoint describes warning-free inventory, not successful mutation.
                    // A blocked plan can coexist with it. SaveState also enforces the lease and ETag;
                    // changing the in-memory timestamp alone does not make the checkpoint durable.
                    var complete = pairRun.Source.Warnings.Count == 0 && pairRun.Target.Warnings.Count == 0;
                    if (complete)
                    {
                        pairLease.State.LastCompleteScanAt = DateTimeOffset.UtcNow;
                        pairLease.State.LastCompleteRunId = run.RunId;
                        _logger.LogInformation(PairProgressEventId, "Saving the complete-scan checkpoint for this pair.");
                        await pairLease.SaveStateAsync(cancellationToken);
                        var hasUnappliedWork = HasUnappliedWork(pairRun.Plan);
                        pairRun.Status = hasUnappliedWork ? "SyncCompletedWithUnappliedWork" : "SyncCompleted";
                    }
                    else
                    {
                        pairRun.Status = "PartialInventory";
                        pairRun.Errors.Add("One or more inventory/read checks failed. This run cannot be used as deletion evidence.");
                    }

                    pairRun.CompletedAt = DateTimeOffset.UtcNow;
                    await _stateStore.WriteRunRecordAsync(run, cancellationToken);
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
                    RunnerTelemetry.RecordException(pairActivity, exception);
                    pairActivity?.SetStatus(ActivityStatusCode.Error, exception.GetType().Name);
                    RunnerTelemetry.Failures.Add(1, new("sync.stage", "pair"), new("error.type", exception.GetType().Name));
                    _logger.LogError(exception, "Pair scan failed for {PairId}.", pair.PairId);
                    await _stateStore.WriteRunRecordAsync(run, CancellationToken.None);
                }
                finally
                {
                    pairTimer.Stop();
                    pairActivity?.SetTag("sync.status", pairRun.Status);
                    // The explicit sync.status is the business outcome.
                    if (pairRun.Status == "SyncCompleted")
                    {
                        pairActivity?.SetStatus(ActivityStatusCode.Ok);
                    }
                    else if (pairRun.Status != "SkippedPairAlreadyLocked")
                    {
                        pairActivity?.SetStatus(ActivityStatusCode.Error, pairRun.Status);
                    }

                    RunnerTelemetry.PairsProcessed.Add(1, new KeyValuePair<string, object?>("sync.status", pairRun.Status));
                    RunnerTelemetry.PairDuration.Record(pairTimer.Elapsed.TotalMilliseconds, new KeyValuePair<string, object?>("sync.status", pairRun.Status));
                    var pairMessage = "Pair {PairId} completed with status {Status} in {DurationMs} ms.";
                    if (pairRun.Status == "Failed")
                    {
                        _logger.LogError(pairMessage, pair.PairId, pairRun.Status, pairTimer.Elapsed.TotalMilliseconds);
                    }
                    else if (pairRun.Status is "PartialInventory" or "SyncCompletedWithUnappliedWork")
                    {
                        _logger.LogWarning(pairMessage, pair.PairId, pairRun.Status, pairTimer.Elapsed.TotalMilliseconds);
                    }
                    else
                    {
                        _logger.LogInformation(pairMessage, pair.PairId, pairRun.Status, pairTimer.Elapsed.TotalMilliseconds);
                    }
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
            await _stateStore.WriteRunRecordAsync(run, CancellationToken.None);
            // Cancellation bypasses the final summary/metrics below; the Function observes the
            // exception instead of receiving a normal RunnerExecutionResult with this status.
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
            _logger.LogError(exception, "Run {RunId} failed during discovery or orchestration.", run.RunId);
        }

        runTimer.Stop();
        runActivity?.SetTag("sync.status", run.Status);
        runActivity?.SetTag("sync.pair_count", run.TaggedPairCount);
        runActivity?.SetTag("sync.disabled_pair_count", run.DisabledPairCount);
        runActivity?.SetTag("sync.discovered_vault_count", run.DiscoveredVaultCount);
        if (run.Status == "Complete")
        {
            runActivity?.SetStatus(ActivityStatusCode.Ok);
        }
        else if (run.Status != "Failed")
        {
            runActivity?.SetStatus(ActivityStatusCode.Error, run.Status);
        }

        RunnerTelemetry.RunsCompleted.Add(1, new KeyValuePair<string, object?>("sync.status", run.Status));
        RunnerTelemetry.RunDuration.Record(runTimer.Elapsed.TotalMilliseconds, new KeyValuePair<string, object?>("sync.status", run.Status));
        var runMessage = "Run {RunId} completed with status {Status} in {DurationMs} ms.";
        if (run.Status is "Partial" or "Cancelled")
        {
            _logger.LogWarning(runMessage, run.RunId, run.Status, runTimer.Elapsed.TotalMilliseconds);
        }
        else if (run.Status == "Failed")
        {
            _logger.LogCritical(runMessage, run.RunId, run.Status, runTimer.Elapsed.TotalMilliseconds);
        }
        else
        {
            _logger.LogInformation(runMessage, run.RunId, run.Status, runTimer.Elapsed.TotalMilliseconds);
        }
        // Do not return a finalized report until the final persistence attempt succeeds. Metrics
        // above may already have been recorded if this write fails, so they are not durability proof.
        await _stateStore.WriteRunRecordAsync(run, CancellationToken.None);
        return run;
    }

    /// <summary>Runs one scheduled cycle and exposes a small host-facing result instead of the internal inventory model.</summary>
    /// <param name="cancellationToken">The Function invocation's shutdown/cancellation token.</param>
    /// <returns>The run ID and aggregate status after the runner's final persistence attempt succeeds.</returns>
    /// <exception cref="OperationCanceledException">Cancellation propagates after an attempt to persist its outcome.</exception>
    /// <remarks>No scheduling or retry policy is implemented here. The Function maps the result to invocation behavior.</remarks>
    public async Task<RunnerExecutionResult> ExecuteScheduledRunAsync(CancellationToken cancellationToken)
    {
        var run = await RunOnceAsync(cancellationToken);
        return new RunnerExecutionResult(run.RunId, run.Status);
    }

    /// <summary>Reduces Azure request failures to HTTP/code metadata for persisted reports.</summary>
    /// <remarks>
    /// Other exception messages are retained verbatim. This is not general-purpose sanitization,
    /// and full exceptions are also logged elsewhere; callers must not place secret payloads in exceptions.
    /// </remarks>
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
                    && item.Status is not ("RBAC_INVENTORY_ONLY" or "ACCESS_POLICY_INTENT_MATCH")))
            {
                return true;
            }

            if (item.ObjectType is "Key" or "CertificateGroup")
            {
                if (item.Status is not ("MANAGED_WITH_CERTIFICATE_GROUP"
                        or "IN_SYNC_ONE_TIME_SEED"
                        or "SOURCE_ADVANCED_ONE_TIME_SEED_UNCHANGED"
                        or "NATIVE_KEY_SEEDED_AND_VERIFIED"
                        or "NATIVE_CERTIFICATE_GROUP_SEEDED_AND_VERIFIED"))
                {
                    return true;
                }
            }
        }

        return false;
    }
}

/// <summary>The host-facing identity and aggregate outcome of a cycle whose report was returned by the runner.</summary>
/// <param name="RunId">Correlation key used by logs, activities, and the dated run-history blob.</param>
/// <param name="Status">Aggregate result such as Complete, NoConfiguredPairs, Partial, or Failed; not a per-secret result.</param>
public sealed record RunnerExecutionResult(string RunId, string Status);
