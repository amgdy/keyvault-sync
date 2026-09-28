using System.Diagnostics;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using KeyVaultSync.Runner.Azure;
using KeyVaultSync.Runner.Security;
using KeyVaultSync.Runner.State;
using Microsoft.Extensions.Logging;

namespace KeyVaultSync.Runner.Sync;

/// <summary>Executes admitted standalone-secret proposals using durable intents and exact-version verification.</summary>
/// <remarks>
/// <para>Mutation-mode and single-writer acknowledgments are configuration gates enforced by the host/options path,
/// not permissions verified here. Key Vault Set Secret has no compare-and-set condition, so target requests use
/// zero SDK retries and a persisted intent; these measures do not provide distributed exactly-once execution.</para>
/// <para>The current executor excludes known source certificate backing names but does not discover every possible
/// ownership relationship or apply a blanket inventory-warning gate. It performs no deletion, rollback, automatic
/// rebaseline, or pending-intent recovery. Keep these limitations explicit when extending its callers.</para>
/// </remarks>
internal sealed class SecretSyncExecutor
{
    private static readonly EventId SecretSyncStepEventId = new(5000, "SecretSyncStep");
    private static readonly EventId SecretSyncOutcomeEventId = new(5001, "SecretSyncOutcome");
    private const string ReadyForFirstWrite = "READY_FOR_APPLY_IF_NAME_STAYS_EMPTY";
    private const string ReadyForUpdate = "VERIFY_TARGET_HMAC_THEN_APPLY";
    private const string ReadyForMetadataUpdate = "VERIFY_TARGET_HMAC_THEN_APPLY_METADATA";
    private const string ReadyForBaselineVerification = "VERIFY_TARGET_HMAC";
    private readonly ISecretSyncVaultClientFactory _clientFactory;
    private readonly ILogger<SecretSyncExecutor> _logger;

    public SecretSyncExecutor(TokenCredential credential, ILogger<SecretSyncExecutor> logger)
        : this(new SecretSyncVaultClientFactory(credential), logger)
    {
    }

    internal SecretSyncExecutor(
        ISecretSyncVaultClientFactory clientFactory,
        ILogger<SecretSyncExecutor> logger)
    {
        _clientFactory = clientFactory;
        _logger = logger;
    }

    /// <summary>Executes eligible secret proposals sequentially and returns replacement outcomes for those proposals only.</summary>
    /// <param name="pair">Directional identity used by endpoint construction and HMAC domain binding.</param>
    /// <param name="lease">Current pair-state owner; dependent work must stop if state persistence fails.</param>
    /// <param name="runId">Correlation ID recorded in any newly prepared write intent.</param>
    /// <param name="plan">Planner output; only eligible secret write or baseline-verification statuses are selected.</param>
    /// <param name="source">Inventory supplying known source certificate backing names, not source secret values.</param>
    /// <param name="target">Inventory supplying pre-scan secret head observations to cross-check against baselines.</param>
    /// <param name="hmac">Validated caller-owned service used for value and managed-metadata verification.</param>
    /// <param name="cancellationToken">Token passed to SDK/state calls; cancellation handling depends on the write phase.</param>
    /// <returns>Per-secret outcomes, including conflicts/failures, in the selected proposals' order.</returns>
    /// <remarks>
    /// Source reads use default SDK retry behavior; all calls through the target client have retries disabled.
    /// A completed apply activity means the loop completed, not that every item succeeded. State-persistence
    /// exceptions abort the loop, while many individual SDK errors become reported outcomes and leave later items eligible.
    /// </remarks>
    public async Task<IReadOnlyList<PlanItem>> ApplyAsync(
        VaultPair pair,
        IPairStateLease lease,
        string runId,
        IReadOnlyList<PlanItem> plan,
        VaultInventory source,
        VaultInventory target,
        SecretHmacService hmac,
        CancellationToken cancellationToken)
    {
        var sourceClient = _clientFactory.Create(pair.Source, isTarget: false);
        var targetClient = _clientFactory.Create(pair.Target, isTarget: true);
        var targetSummaries = target.Secrets.ToDictionary(item => item.Name, StringComparer.OrdinalIgnoreCase);
        // Certificate backups/restores own the conventional same-name backing secret as a group,
        // even when inventory could not resolve the certificate's secret reference.
        var certificateBackingNames = source.Certificates
            .Select(certificate => certificate.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var results = new List<PlanItem>();
        var eligibleItems = plan.Where(item => item.ObjectType == "Secret"
            && item.Action is "SetSecret" or "UpdateSecretProperties" or "VerifySecretBaseline"
            && item.Status is ReadyForFirstWrite or ReadyForUpdate or ReadyForMetadataUpdate or ReadyForBaselineVerification).ToArray();
        using var applyActivity = RunnerTelemetry.ActivitySource.StartActivity("keyvault.secret.apply-pair");
        applyActivity?.SetTag("sync.pair_id", pair.PairId);
        applyActivity?.SetTag("sync.run_id", runId);
        applyActivity?.SetTag("secret.eligible_count", eligibleItems.Length);
        _logger.LogInformation("Secret apply phase started. Pair {PairId}; run {RunId}; {EligibleSecretCount} eligible plan items.",
            pair.PairId, runId, eligibleItems.Length);

        foreach (var plannedItem in eligibleItems)
        {
            if (certificateBackingNames.Contains(plannedItem.Name))
            {
                _logger.LogWarning(SecretSyncOutcomeEventId,
                    "Secret sync item blocked because it belongs to a certificate group. Pair {PairId}; secret {SecretName}.",
                    pair.PairId, plannedItem.Name);
                results.Add(Outcome(plannedItem, "CERTIFICATE_BACKING_SECRET_NOT_WRITTEN", plannedItem.TargetVersion,
                    "This secret is managed as part of a certificate ownership group; it requires the separate certificate operation."));
                continue;
            }

            targetSummaries.TryGetValue(plannedItem.Name, out var targetSummary);
            results.Add(await ApplyOneAsync(pair, lease, runId, plannedItem, targetSummary, sourceClient, targetClient, hmac, cancellationToken));
        }

        applyActivity?.SetTag("secret.outcome_count", results.Count);
        applyActivity?.SetStatus(ActivityStatusCode.Ok);
        _logger.LogInformation("Secret apply phase completed. Pair {PairId}; run {RunId}; {OutcomeCount} outcomes recorded.",
            pair.PairId, runId, results.Count);
        return results;
    }

    /// <summary>Runs the read/validate, intent, recheck, mutation, verification, and commit sequence for one secret.</summary>
    /// <param name="pair">Pair identity and endpoints; HMACs use the exact PairId text.</param>
    /// <param name="lease">Mutable working state and its conditional persistence owner.</param>
    /// <param name="runId">ID attached to a pending intent before mutation.</param>
    /// <param name="plannedItem">Eligible action with a pinned source version; it is not sufficient proof of live target state.</param>
    /// <param name="targetSummary">Pre-scan target observation, null when the target was absent from active inventory.</param>
    /// <param name="sourceClient">Value-reading client for the source vault.</param>
    /// <param name="targetClient">Target client configured with zero SDK retries.</param>
    /// <param name="hmac">Live service for computing and comparing domain-bound value fingerprints.</param>
    /// <param name="cancellationToken">Passed through reads, state writes, and the single SDK mutation invocation.</param>
    /// <returns>A replacement plan entry when the operation can be classified without a state-persistence failure.</returns>
    /// <remarks>
    /// <para>Existing targets require a compatible committed baseline and repeated version/value/metadata checks.
    /// First writes require live active/soft-deleted absence checks. Neither path closes the external-writer race.</para>
    /// <para>After entering the write-attempt window, errors (including cancellation) conservatively retain intent
    /// and may return an unresolved outcome. Before that window, a saved intent can be cleared only through another
    /// successful conditional save. State-save failures propagate and must abort this pair.</para>
    /// </remarks>
    private async Task<PlanItem> ApplyOneAsync(
        VaultPair pair,
        IPairStateLease lease,
        string runId,
        PlanItem plannedItem,
        SecretSummary? targetSummary,
        ISecretSyncVaultClient sourceClient,
        ISecretSyncVaultClient targetClient,
        SecretHmacService hmac,
        CancellationToken cancellationToken)
    {
        using var activity = RunnerTelemetry.ActivitySource.StartActivity("keyvault.secret.apply");
        activity?.SetTag("sync.pair_id", pair.PairId);
        activity?.SetTag("secret.name", plannedItem.Name);
        activity?.SetTag("secret.source_version", plannedItem.SourceVersion);
        activity?.SetTag("secret.target_version_before", targetSummary?.LatestVersion);
        activity?.SetTag("hmac.key_version", hmac.KeyVersion);
        LogStep(activity, pair.PairId, plannedItem, "apply", "started", targetSummary?.LatestVersion);

        // These flags distinguish acknowledged state persistence from entry into the mutation
        // window. writeAttempted is conservative: true does not prove the service received a request.
        var intentPersisted = false;
        var writeAttempted = false;
        var metadataOnly = plannedItem.Action == "UpdateSecretProperties";
        KeyVaultSecret? targetSecretBefore = null;
        try
        {
            // Phase 1: never replay unresolved work or substitute an arbitrary source "latest".
            // The pinned source version keeps the value read tied to the inventory proposal.
            if (lease.State.PendingSecretWrites.TryGetValue(plannedItem.Name, out var pendingWrite))
            {
                return CompleteOutcome(activity, pair.PairId, plannedItem, "BLOCKED_PENDING_WRITE_RESOLUTION", targetSummary?.LatestVersion,
                    $"Run {pendingWrite.RunId} already has a durable write intent. Resolve it before retrying.");
            }

            LogStep(activity, pair.PairId, plannedItem, "pending-write-check", "completed", targetSummary?.LatestVersion);

            if (string.IsNullOrWhiteSpace(plannedItem.SourceVersion))
            {
                return CompleteOutcome(activity, pair.PairId, plannedItem, "SECRET_SOURCE_VERSION_UNKNOWN", targetSummary?.LatestVersion,
                    "The source head version is unknown; no value was read or written.");
            }

            LogStep(activity, pair.PairId, plannedItem, "source-secret-read", "started", targetSummary?.LatestVersion);
            var sourceSecret = await sourceClient.GetSecretAsync(
                plannedItem.Name,
                plannedItem.SourceVersion,
                cancellationToken);
            var sourceVersion = sourceSecret.Properties.Version ?? plannedItem.SourceVersion;
            if (!string.Equals(sourceVersion, plannedItem.SourceVersion, StringComparison.Ordinal))
            {
                return CompleteOutcome(activity, pair.PairId, plannedItem, "CONFLICT_SOURCE_CHANGED_DURING_VALIDATION", targetSummary?.LatestVersion,
                    "The source version returned by Key Vault did not match the version selected by inventory.");
            }

            LogStep(activity, pair.PairId, plannedItem, "source-secret-read", "completed", targetSummary?.LatestVersion, sourceVersion);
            LogStep(activity, pair.PairId, plannedItem, "source-fingerprint", "started", targetSummary?.LatestVersion, sourceVersion);
            var expectedValueHmac = hmac.ComputeValue(pair.PairId, plannedItem.Name, sourceSecret.Value);
            var expectedMetadataDigest = ComputeMetadataDigest(sourceSecret.Properties);
            LogStep(activity, pair.PairId, plannedItem, "source-fingerprint", "completed", targetSummary?.LatestVersion, sourceVersion);
            var baseline = lease.State.SecretBaselines.GetValueOrDefault(plannedItem.Name);
            LogStep(activity, pair.PairId, plannedItem, "baseline-lookup", baseline is null ? "not-found" : "found", targetSummary?.LatestVersion, sourceVersion);

            // Phase 2: a baseline establishes managed ownership only under the same fingerprint
            // domains and key-version label. Re-read live target content before trusting that baseline.
            if (baseline is not null)
            {
                if (!baseline.ValueDomainVersion.Equals(SecretHmacService.ValueDomainVersion, StringComparison.Ordinal)
                    || !baseline.MetadataDomainVersion.Equals(SecretHmacService.MetadataDomainVersion, StringComparison.Ordinal))
                {
                    return CompleteOutcome(activity, pair.PairId, plannedItem, "BLOCKED_HMAC_DOMAIN_VERSION_CHANGED", targetSummary?.LatestVersion,
                        "The committed baseline uses an unknown or legacy HMAC domain; no write or re-baseline is allowed.");
                }

                if (!string.Equals(baseline.HmacKeyVersion, hmac.KeyVersion, StringComparison.Ordinal))
                {
                    return CompleteOutcome(activity, pair.PairId, plannedItem, "BLOCKED_HMAC_KEY_VERSION_CHANGED", targetSummary?.LatestVersion,
                        "The configured HMAC key version differs from the committed baseline; no automatic re-baseline is allowed.");
                }

                if (targetSummary is null)
                {
                    return CompleteOutcome(activity, pair.PairId, plannedItem, "CONFLICT_PREVIOUS_TARGET_MISSING", null,
                        "A target with a committed baseline is missing from active inventory; no write was attempted.");
                }

                if (string.IsNullOrWhiteSpace(targetSummary.LatestVersion))
                {
                    return CompleteOutcome(activity, pair.PairId, plannedItem, "CONFLICT_TARGET_VERSION_UNKNOWN", targetSummary.LatestVersion,
                        "The target head version could not be established by inventory; no write was attempted.");
                }

                LogStep(activity, pair.PairId, plannedItem, "target-head-read", "started", targetSummary.LatestVersion, sourceVersion);
                var currentTarget = await ReadTargetHeadAsync(targetClient, plannedItem.Name, cancellationToken);
                targetSecretBefore = currentTarget;
                LogStep(activity, pair.PairId, plannedItem, "target-head-read", "completed", currentTarget.Properties.Version, sourceVersion);
                if (!string.Equals(currentTarget.Properties.Version, targetSummary.LatestVersion, StringComparison.Ordinal))
                {
                    return CompleteOutcome(activity, pair.PairId, plannedItem, "CONFLICT_TARGET_CHANGED_DURING_VALIDATION", currentTarget.Properties.Version,
                        "The target head changed after inventory observed it; no write was attempted.");
                }

                LogStep(activity, pair.PairId, plannedItem, "target-baseline-verification", "started", currentTarget.Properties.Version, sourceVersion);
                var currentTargetHmac = hmac.ComputeValue(pair.PairId, plannedItem.Name, currentTarget.Value);
                var currentTargetMetadata = ComputeMetadataDigest(currentTarget.Properties);
                var targetValueMatchesBaseline = SecretHmacService.ValueHmacEquals(currentTargetHmac, baseline.ValueHmac);
                var targetMetadataMatchesBaseline = string.Equals(currentTargetMetadata, baseline.MetadataDigest, StringComparison.Ordinal);
                if (!targetValueMatchesBaseline || !targetMetadataMatchesBaseline)
                {
                    return CompleteOutcome(activity, pair.PairId, plannedItem, "CONFLICT_TARGET_DRIFT", currentTarget.Properties.Version,
                        $"The current target differs from the committed baseline (value HMAC matches: {targetValueMatchesBaseline}; managed metadata matches: {targetMetadataMatchesBaseline}); no write was attempted.");
                }
                LogStep(activity, pair.PairId, plannedItem, "target-baseline-verification", "completed", currentTarget.Properties.Version, sourceVersion);

                if (SecretHmacService.ValueHmacEquals(expectedValueHmac, baseline.ValueHmac)
                    && string.Equals(expectedMetadataDigest, baseline.MetadataDigest, StringComparison.Ordinal))
                {
                    // New service versions are not drift when both logical content and metadata
                    // still match. Confirm neither head moved during verification before refresh.
                    var latestSource = await ReadSourceHeadAsync(sourceClient, plannedItem.Name, cancellationToken);
                    var latestTarget = await ReadTargetHeadAsync(targetClient, plannedItem.Name, cancellationToken);
                    if (!string.Equals(latestSource.Properties.Version, sourceVersion, StringComparison.Ordinal)
                        || !SecretHmacService.ValueHmacEquals(
                            hmac.ComputeValue(pair.PairId, plannedItem.Name, latestSource.Value),
                            expectedValueHmac)
                        || !string.Equals(ComputeMetadataDigest(latestSource.Properties), expectedMetadataDigest, StringComparison.Ordinal))
                    {
                        return CompleteOutcome(activity, pair.PairId, plannedItem, "CONFLICT_SOURCE_CHANGED_DURING_VALIDATION", latestTarget.Properties.Version,
                            "The source head changed while the HMAC baseline was being verified; no target write or baseline refresh occurred.");
                    }

                    if (!string.Equals(latestTarget.Properties.Version, currentTarget.Properties.Version, StringComparison.Ordinal)
                        || !SecretHmacService.ValueHmacEquals(
                            hmac.ComputeValue(pair.PairId, plannedItem.Name, latestTarget.Value),
                            baseline.ValueHmac)
                        || !string.Equals(ComputeMetadataDigest(latestTarget.Properties), baseline.MetadataDigest, StringComparison.Ordinal))
                    {
                        return CompleteOutcome(activity, pair.PairId, plannedItem, "CONFLICT_TARGET_CHANGED_DURING_VALIDATION", latestTarget.Properties.Version,
                            "The target head changed while the HMAC baseline was being verified; no target write or baseline refresh occurred.");
                    }

                    lease.State.SecretBaselines[plannedItem.Name] = baseline with
                    {
                        SourceVersion = latestSource.Properties.Version ?? sourceVersion,
                        TargetVersion = latestTarget.Properties.Version!,
                        VerifiedAt = DateTimeOffset.UtcNow,
                    };
                    LogStep(activity, pair.PairId, plannedItem, "baseline-refresh", "started", latestTarget.Properties.Version, latestSource.Properties.Version);
                    await SaveStateAsync(lease, plannedItem.Name, cancellationToken);
                    LogStep(activity, pair.PairId, plannedItem, "baseline-refresh", "completed", latestTarget.Properties.Version, latestSource.Properties.Version);
                    activity?.SetStatus(ActivityStatusCode.Ok);
                    return CompleteOutcome(activity, pair.PairId, plannedItem, "IN_SYNC_BY_HMAC_AND_METADATA", latestTarget.Properties.Version,
                        "Source and target values/metadata match the committed baseline. Verified source/target version observations were refreshed without a target write.");
                }
            }
            else if (targetSummary is not null)
            {
                return CompleteOutcome(activity, pair.PairId, plannedItem, "CONFLICT_UNBASELINED_TARGET", targetSummary.LatestVersion,
                    "The target exists without a committed HMAC baseline; equal values do not prove sync ownership.");
            }

            // Phase 3: save the intended post-write fingerprints before any mutation. If saving
            // throws, abort even if storage might have accepted it; never continue with an unknown
            // state checkpoint. No plaintext value or key bytes are put in this record.
            var targetVersionBefore = targetSecretBefore?.Properties.Version;
            var intent = new SecretWriteIntent
            {
                RunId = runId,
                SourceVersion = sourceVersion,
                ExpectedValueHmac = expectedValueHmac,
                ExpectedMetadataDigest = expectedMetadataDigest,
                HmacKeyVersion = hmac.KeyVersion,
                TargetVersionBefore = targetVersionBefore,
                CreatedAt = DateTimeOffset.UtcNow,
            };
            lease.State.PendingSecretWrites[plannedItem.Name] = intent;
            LogStep(activity, pair.PairId, plannedItem, "write-intent-persist", "started", targetVersionBefore, sourceVersion);
            await SaveStateAsync(lease, plannedItem.Name, cancellationToken);
            intentPersisted = true;
            LogStep(activity, pair.PairId, plannedItem, "write-intent-persist", "completed", targetVersionBefore, sourceVersion);

            // Phase 4: close the observation gap as far as possible after saving intent. These
            // reads are not compare-and-set and cannot fence an external writer after they complete.
            if (baseline is not null)
            {
                LogStep(activity, pair.PairId, plannedItem, "source-precondition-recheck", "started", targetVersionBefore, sourceVersion);
                var latestSource = await ReadSourceHeadAsync(sourceClient, plannedItem.Name, cancellationToken);
                if (!string.Equals(latestSource.Properties.Version, sourceVersion, StringComparison.Ordinal)
                    || !SecretHmacService.ValueHmacEquals(
                        hmac.ComputeValue(pair.PairId, plannedItem.Name, latestSource.Value),
                        expectedValueHmac)
                    || !string.Equals(ComputeMetadataDigest(latestSource.Properties), expectedMetadataDigest, StringComparison.Ordinal))
                {
                    throw new SecretWriteConflictException("The source changed after the write intent was saved.");
                }

                LogStep(activity, pair.PairId, plannedItem, "source-precondition-recheck", "completed", targetVersionBefore, sourceVersion);
                LogStep(activity, pair.PairId, plannedItem, "target-precondition-recheck", "started", targetVersionBefore, sourceVersion);
                var latestTarget = await ReadTargetHeadAsync(targetClient, plannedItem.Name, cancellationToken);
                targetSecretBefore = latestTarget;
                var latestTargetHmac = hmac.ComputeValue(pair.PairId, plannedItem.Name, latestTarget.Value);
                var latestTargetMetadata = ComputeMetadataDigest(latestTarget.Properties);
                if (!string.Equals(latestTarget.Properties.Version, targetVersionBefore, StringComparison.Ordinal)
                    || !SecretHmacService.ValueHmacEquals(latestTargetHmac, baseline.ValueHmac)
                    || !string.Equals(latestTargetMetadata, baseline.MetadataDigest, StringComparison.Ordinal))
                {
                    throw new SecretWriteConflictException("The target changed after the write intent was saved.");
                }
                LogStep(activity, pair.PairId, plannedItem, "target-precondition-recheck", "completed", latestTarget.Properties.Version, sourceVersion);
            }
            else
            {
                LogStep(activity, pair.PairId, plannedItem, "source-precondition-recheck", "started", null, sourceVersion);
                var latestSource = await ReadSourceHeadAsync(sourceClient, plannedItem.Name, cancellationToken);
                if (!string.Equals(latestSource.Properties.Version, sourceVersion, StringComparison.Ordinal)
                    || !SecretHmacService.ValueHmacEquals(
                        hmac.ComputeValue(pair.PairId, plannedItem.Name, latestSource.Value),
                        expectedValueHmac)
                    || !string.Equals(ComputeMetadataDigest(latestSource.Properties), expectedMetadataDigest, StringComparison.Ordinal))
                {
                    throw new SecretWriteConflictException("The source changed after the write intent was saved.");
                }

                LogStep(activity, pair.PairId, plannedItem, "source-precondition-recheck", "completed", null, sourceVersion);
                LogStep(activity, pair.PairId, plannedItem, "target-name-availability-check", "started", null, sourceVersion);
                await EnsureTargetNameUnusedAsync(targetClient, plannedItem.Name, cancellationToken);
                LogStep(activity, pair.PairId, plannedItem, "target-name-availability-check", "completed", null, sourceVersion);
            }

            // Phase 5: cross the conservative no-retry boundary before preparing/issuing the
            // mutation. A metadata PATCH targets the validated version; SetSecret creates a version.
            writeAttempted = true;
            string targetVersion;
            if (metadataOnly)
            {
                if (targetSecretBefore is null)
                {
                    throw new SecretWriteConflictException("A metadata-only plan has no validated target version.");
                }

                ApplyProperties(targetSecretBefore.Properties, sourceSecret.Properties);
                LogStep(activity, pair.PairId, plannedItem, "target-metadata-patch", "started", targetSecretBefore.Properties.Version, sourceVersion);
                var updatedProperties = await targetClient.UpdateSecretPropertiesAsync(targetSecretBefore.Properties, cancellationToken);
                targetVersion = updatedProperties.Version ?? throw new InvalidDataException("Key Vault returned metadata without a target version ID.");
                LogStep(activity, pair.PairId, plannedItem, "target-metadata-patch", "response-received", targetVersion, sourceVersion);
                if (!targetVersion.Equals(targetSecretBefore.Properties.Version, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Metadata update unexpectedly changed the target secret version ID.");
                }
            }
            else
            {
                var targetSecret = CreateTargetSecret(plannedItem.Name, sourceSecret);
                LogStep(activity, pair.PairId, plannedItem, "target-secret-set", "started", targetVersionBefore, sourceVersion);
                var setResponse = await targetClient.SetSecretAsync(targetSecret, cancellationToken);
                targetVersion = setResponse.Properties.Version
                    ?? throw new InvalidDataException("Key Vault returned a secret without a version ID.");
                LogStep(activity, pair.PairId, plannedItem, "target-secret-set", "response-received", targetVersion, sourceVersion);
            }

            // Phase 6: read exactly the returned version, not whichever version is latest now.
            // Matching value HMAC and managed metadata is required before committing ownership.
            // This proves the observed version, not that no external writer advanced the head later.
            LogStep(activity, pair.PairId, plannedItem, "target-version-verification", "started", targetVersion, sourceVersion);
            var verifiedTarget = await targetClient.GetSecretAsync(
                plannedItem.Name,
                targetVersion,
                cancellationToken);
            var verifiedValueHmac = hmac.ComputeValue(pair.PairId, plannedItem.Name, verifiedTarget.Value);
            var verifiedMetadata = ComputeMetadataDigest(verifiedTarget.Properties);

            if (!SecretHmacService.ValueHmacEquals(verifiedValueHmac, expectedValueHmac)
                || !string.Equals(verifiedMetadata, expectedMetadataDigest, StringComparison.Ordinal))
            {
                throw new InvalidDataException("The written target version did not match the expected HMAC and managed metadata.");
            }
            LogStep(activity, pair.PairId, plannedItem, "target-version-verification", "completed", targetVersion, sourceVersion);

            // Commit the verified baseline and intent removal in one conditional state upload.
            // Until that upload is acknowledged, the in-memory edits are not a durable success.
            lease.State.SecretBaselines[plannedItem.Name] = new SecretBaseline
            {
                ValueDomainVersion = SecretHmacService.ValueDomainVersion,
                MetadataDomainVersion = SecretHmacService.MetadataDomainVersion,
                SourceVersion = sourceVersion,
                TargetVersion = targetVersion,
                ValueHmac = expectedValueHmac,
                HmacKeyVersion = hmac.KeyVersion,
                MetadataDigest = expectedMetadataDigest,
                VerifiedAt = DateTimeOffset.UtcNow,
            };
            lease.State.PendingSecretWrites.Remove(plannedItem.Name);
            LogStep(activity, pair.PairId, plannedItem, "baseline-commit", "started", targetVersion, sourceVersion);
            await SaveStateAsync(lease, plannedItem.Name, cancellationToken);
            intentPersisted = false;
            LogStep(activity, pair.PairId, plannedItem, "baseline-commit", "completed", targetVersion, sourceVersion);
            activity?.SetTag("secret.target_version_after", targetVersion);
            activity?.SetStatus(ActivityStatusCode.Ok);
            _logger.LogInformation("Secret {SecretName} synced and verified at target version {TargetVersion}.", plannedItem.Name, targetVersion);
            return CompleteOutcome(activity, pair.PairId, plannedItem, "SECRET_SYNCED_AND_VERIFIED", targetVersion,
                "The target version was verified by HMAC and managed metadata, then committed to pair state.");
        }
        catch (SecretStatePersistenceException)
        {
            // Do not downgrade a failed state write to an ordinary per-secret outcome: later work
            // or a scan-checkpoint save could accidentally persist partially modified working state.
            activity?.SetStatus(ActivityStatusCode.Error, "Pair state persistence failed");
            LogStep(activity, pair.PairId, plannedItem, "pair-state-persist", "failed", targetSummary?.LatestVersion, plannedItem.SourceVersion);
            throw;
        }
        catch (SecretWriteConflictException exception)
        {
            // Only a definitely pre-attempt conflict permits intent removal. Even this cleanup
            // must be durably saved; a failed cleanup propagates instead of authorizing another try.
            if (intentPersisted && !writeAttempted)
            {
                lease.State.PendingSecretWrites.Remove(plannedItem.Name);
                await SaveStateAsync(lease, plannedItem.Name, cancellationToken);
                intentPersisted = false;
            }

            activity?.SetStatus(ActivityStatusCode.Error, "Precondition changed before write");
            _logger.LogWarning("Secret {SecretName} was not written because a source, target, or name-availability precondition changed during validation.", plannedItem.Name);
            return CompleteOutcome(activity, pair.PairId, plannedItem, "CONFLICT_PRECONDITION_CHANGED_BEFORE_WRITE",
                targetSecretBefore?.Properties.Version ?? targetSummary?.LatestVersion, exception.Message);
        }
        catch (Exception exception)
        {
            // This catch includes cancellation. A cancellation after entering the write window
            // is not evidence that the remote mutation failed and must not clear the durable intent.
            if (intentPersisted && !writeAttempted)
            {
                lease.State.PendingSecretWrites.Remove(plannedItem.Name);
                await SaveStateAsync(lease, plannedItem.Name, cancellationToken);
                intentPersisted = false;
            }

            RunnerTelemetry.RecordException(activity, exception);
            activity?.SetStatus(ActivityStatusCode.Error, exception.GetType().Name);
            if (writeAttempted)
            {
                // The service may have accepted the request even if the client saw a transport error.
                LogStep(activity, pair.PairId, plannedItem, "target-write-outcome", "unresolved", targetSummary?.LatestVersion, plannedItem.SourceVersion);
                _logger.LogError(exception, "Secret write outcome is unresolved for {SecretName}; its durable intent remains and will not be retried automatically.", plannedItem.Name);
                return CompleteOutcome(activity, pair.PairId, plannedItem, "WRITE_OUTCOME_UNRESOLVED", targetSummary?.LatestVersion,
                    "The write request may have been accepted. The durable intent blocks retries until the target is resolved explicitly.");
            }

            _logger.LogError(exception, "Secret apply failed before a write was attempted for {SecretName}.", plannedItem.Name);
            return CompleteOutcome(activity, pair.PairId, plannedItem, "SECRET_APPLY_FAILED_BEFORE_WRITE", targetSummary?.LatestVersion,
                $"No write was sent. {SafeError(exception)}");
        }
    }

    /// <summary>Adds a payload-free activity event and structured event 5000 for one named executor step.</summary>
    /// <remarks>
    /// Fingerprint mechanics are Trace; selected precondition reads are Debug; other milestones are Information.
    /// Failed/unresolved step status overrides that classification to Error. IDs and version labels are recorded,
    /// but neither secret values nor computed fingerprint strings are accepted by this helper.
    /// </remarks>
    private void LogStep(
        Activity? activity,
        string pairId,
        PlanItem plannedItem,
        string stepName,
        string stepStatus,
        string? targetVersion,
        string? sourceVersion = null)
    {
        activity?.AddEvent(new ActivityEvent("keyvault.secret.step", tags: new ActivityTagsCollection
        {
            { "sync.pair_id", pairId },
            { "secret.name", plannedItem.Name },
            { "secret.action", plannedItem.Action },
            { "secret.step", stepName },
            { "secret.step_status", stepStatus },
            { "secret.source_version", sourceVersion },
            { "secret.target_version", targetVersion },
        }));
        var logLevel = stepName switch
        {
            "source-fingerprint" or "baseline-lookup" or "target-baseline-verification" => LogLevel.Trace,
            "pending-write-check" or "target-head-read" or "target-precondition-recheck" or "target-name-availability-check" => LogLevel.Debug,
            _ => LogLevel.Information,
        };
        var message = "Secret sync step {StepName} {StepStatus}. Pair {PairId}; secret {SecretName}; action {Action}; source version {SourceVersion}; target version {TargetVersion}.";
        if (stepStatus is "failed" or "unresolved")
        {
            _logger.LogError(SecretSyncStepEventId, message,
                stepName, stepStatus, pairId, plannedItem.Name, plannedItem.Action, sourceVersion, targetVersion);
        }
        else if (logLevel == LogLevel.Trace)
        {
            _logger.LogTrace(SecretSyncStepEventId, message,
                stepName, stepStatus, pairId, plannedItem.Name, plannedItem.Action, sourceVersion, targetVersion);
        }
        else if (logLevel == LogLevel.Debug)
        {
            _logger.LogDebug(SecretSyncStepEventId, message,
                stepName, stepStatus, pairId, plannedItem.Name, plannedItem.Action, sourceVersion, targetVersion);
        }
        else
        {
            _logger.LogInformation(SecretSyncStepEventId, message,
                stepName, stepStatus, pairId, plannedItem.Name, plannedItem.Action, sourceVersion, targetVersion);
        }
    }

    /// <summary>Classifies/logs an outcome and returns its plan replacement without persisting state itself.</summary>
    /// <remarks>
    /// Failed/unresolved outcomes are Error; blocked/conflicting/unknown-source outcomes are Warning.
    /// Detail is returned for the report but is deliberately omitted from the structured outcome event.
    /// Activity error status can describe an intentional safety block, not just an unhandled exception.
    /// </remarks>
    private PlanItem CompleteOutcome(
        Activity? activity,
        string pairId,
        PlanItem plannedItem,
        string status,
        string? targetVersion,
        string detail)
    {
        var isError = status.Contains("FAILED", StringComparison.Ordinal)
            || status.Contains("UNRESOLVED", StringComparison.Ordinal);
        var isWarning = status.StartsWith("BLOCKED", StringComparison.Ordinal)
            || status.StartsWith("CONFLICT", StringComparison.Ordinal)
            || status == "SECRET_SOURCE_VERSION_UNKNOWN";
        activity?.SetTag("secret.outcome", status);
        activity?.SetStatus(isError || isWarning ? ActivityStatusCode.Error : ActivityStatusCode.Ok, status);
        const string message = "Secret sync outcome {Status}. Pair {PairId}; secret {SecretName}; action {Action}; target version {TargetVersion}.";
        if (isError)
        {
            _logger.LogError(SecretSyncOutcomeEventId, message,
                status, pairId, plannedItem.Name, plannedItem.Action, targetVersion);
        }
        else if (isWarning)
        {
            _logger.LogWarning(SecretSyncOutcomeEventId, message,
                status, pairId, plannedItem.Name, plannedItem.Action, targetVersion);
        }
        else
        {
            _logger.LogInformation(SecretSyncOutcomeEventId, message,
                status, pairId, plannedItem.Name, plannedItem.Action, targetVersion);
        }

        return Outcome(plannedItem, status, targetVersion, detail);
    }

    /// <summary>Rejects a first-write name if found in either live active or soft-deleted secret enumeration.</summary>
    /// <remarks>
    /// A failed list request propagates rather than being interpreted as absence. The two lists are not atomic,
    /// and successful absence observations do not prevent a later external write or establish certificate ownership.
    /// </remarks>
    private static async Task EnsureTargetNameUnusedAsync(ISecretSyncVaultClient targetClient, string secretName, CancellationToken cancellationToken)
    {
        await foreach (var activeSecret in targetClient.GetPropertiesOfSecretsAsync(cancellationToken))
        {
            if (activeSecret.Name.Equals(secretName, StringComparison.OrdinalIgnoreCase))
            {
                throw new SecretWriteConflictException("The target secret became active before the write.");
            }
        }

        await foreach (var deletedSecret in targetClient.GetDeletedSecretsAsync(cancellationToken))
        {
            if (deletedSecret.Name.Equals(secretName, StringComparison.OrdinalIgnoreCase))
            {
                throw new SecretWriteConflictException("The target secret name is soft-deleted.");
            }
        }
    }

    /// <summary>Reads the current target head value/properties for live baseline checks; no explicit version is requested.</summary>
    /// <remarks>Returned value material must stay out of logs and persisted reports; this is not a value-free inventory call.</remarks>
    private static Task<KeyVaultSecret> ReadTargetHeadAsync(ISecretSyncVaultClient targetClient, string secretName, CancellationToken cancellationToken)
    {
        return targetClient.GetSecretAsync(secretName, version: null, cancellationToken: cancellationToken);
    }

    /// <summary>Reads the current source head during apply to detect changes after inventory selected a pinned version.</summary>
    /// <remarks>The caller uses only its value HMAC/metadata and version; neither plaintext nor fingerprints are persisted.</remarks>
    private static Task<KeyVaultSecret> ReadSourceHeadAsync(ISecretSyncVaultClient sourceClient, string secretName, CancellationToken cancellationToken)
    {
        return sourceClient.GetSecretAsync(secretName, version: null, cancellationToken: cancellationToken);
    }

    /// <summary>Builds the SetSecret payload from the source value and the exact managed metadata subset.</summary>
    /// <remarks>Copies enabled/content type/validity/tags, not source IDs, version identifiers, or service timestamps.</remarks>
    private static KeyVaultSecret CreateTargetSecret(string secretName, KeyVaultSecret sourceSecret)
    {
        var targetSecret = new KeyVaultSecret(secretName, sourceSecret.Value)
        {
            Properties =
            {
                Enabled = sourceSecret.Properties.Enabled,
                ContentType = sourceSecret.Properties.ContentType,
                NotBefore = sourceSecret.Properties.NotBefore,
                ExpiresOn = sourceSecret.Properties.ExpiresOn,
            },
        };

        if (sourceSecret.Properties.Tags is not null)
        {
            foreach (var tag in sourceSecret.Properties.Tags)
            {
                targetSecret.Properties.Tags[tag.Key] = tag.Value;
            }
        }

        return targetSecret;
    }

    /// <summary>Overwrites managed properties on a validated target version in preparation for a metadata-only PATCH.</summary>
    /// <remarks>Tags are replaced, not merged, so target-only tags are removed. No secret value is changed by this helper.</remarks>
    private static void ApplyProperties(SecretProperties targetProperties, SecretProperties sourceProperties)
    {
        targetProperties.Enabled = sourceProperties.Enabled;
        targetProperties.ContentType = sourceProperties.ContentType;
        targetProperties.NotBefore = sourceProperties.NotBefore;
        targetProperties.ExpiresOn = sourceProperties.ExpiresOn;
        targetProperties.Tags.Clear();
        if (sourceProperties.Tags is not null)
        {
            foreach (var tag in sourceProperties.Tags)
            {
                targetProperties.Tags[tag.Key] = tag.Value;
            }
        }
    }

    /// <summary>Adapts SDK properties to the shared metadata canonicalization used by planning and verification.</summary>
    /// <remarks>Keep this subset aligned with CreateTargetSecret/ApplyProperties and the versioned HMAC service format.</remarks>
    private static string ComputeMetadataDigest(SecretProperties properties)
    {
        var tags = properties.Tags is null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(properties.Tags, StringComparer.OrdinalIgnoreCase);
        return SecretHmacService.ComputeMetadata(
            properties.Enabled,
            properties.ContentType,
            properties.NotBefore,
            properties.ExpiresOn,
            tags);
    }

    /// <summary>Wraps every state-save failure in the fatal-to-this-pair exception recognized by the executor.</summary>
    /// <remarks>Includes cancellation and uncertain upload results; callers must not continue or replay the Key Vault mutation.</remarks>
    private static async Task SaveStateAsync(IPairStateLease lease, string secretName, CancellationToken cancellationToken)
    {
        try
        {
            await lease.SaveStateAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            throw new SecretStatePersistenceException(secretName, exception);
        }
    }

    /// <summary>Copies the original action/source identity and replaces only outcome status, target version, and explanation.</summary>
    private static PlanItem Outcome(PlanItem plannedItem, string status, string? targetVersion, string detail)
    {
        return plannedItem with
        {
            Status = status,
            TargetVersion = targetVersion,
            Detail = detail,
        };
    }

    /// <summary>Reduces Azure failures to HTTP/code metadata for report text while retaining other exception messages.</summary>
    /// <remarks>This is not universal redaction; full exceptions are also logged on error paths.</remarks>
    private static string SafeError(Exception exception)
    {
        return exception is RequestFailedException requestFailure
            ? $"{exception.GetType().Name}: HTTP {requestFailure.Status}, error {requestFailure.ErrorCode ?? "unknown"}."
            : $"{exception.GetType().Name}: {exception.Message}";
    }

    /// <summary>Signals a failed source, target, or name-availability precondition before the write-attempt boundary.</summary>
    /// <param name="message">A payload-free explanation of the conflict.</param>
    private sealed class SecretWriteConflictException(string message) : Exception(message);

    /// <summary>Forces pair abortion when the durable state outcome cannot be trusted after a save attempt.</summary>
    /// <param name="secretName">Object name for correlation, never its value or fingerprints.</param>
    /// <param name="innerException">Original storage/cancellation failure retained for diagnostics.</param>
    private sealed class SecretStatePersistenceException(string secretName, Exception innerException)
        : InvalidOperationException($"Pair state could not be persisted for secret {secretName}.", innerException);
}