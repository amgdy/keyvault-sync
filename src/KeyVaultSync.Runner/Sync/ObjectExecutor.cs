using Azure;
using KeyVaultSync.Runner.Azure;
using KeyVaultSync.Runner.Security;
using KeyVaultSync.Runner.State;
using Microsoft.Extensions.Logging;

namespace KeyVaultSync.Runner.Sync;

/// <summary>Executes supported object writes and soft deletes behind versioned signatures and durable intents.</summary>
/// <remarks>
/// This is the only component that owns Key Vault object mutation. It persists intent before one
/// zero-retry target request, verifies the exact result, then commits the baseline and clears intent.
/// </remarks>
internal sealed class ObjectExecutor
{
    private readonly IObjectReplicationVaultClientFactory _clientFactory;
    private readonly ILogger<ObjectExecutor> _logger;

    /// <summary>Initializes the guarded object executor.</summary>
    /// <param name="clientFactory">Creates source-read and zero-retry target clients.</param>
    /// <param name="logger">Structured logger used for value-free mutation diagnostics.</param>
    public ObjectExecutor(
        IObjectReplicationVaultClientFactory clientFactory,
        ILogger<ObjectExecutor> logger)
    {
        _clientFactory = clientFactory;
        _logger = logger;
    }

    /// <summary>Applies actionable object plan items while the caller holds the pair lease.</summary>
    /// <returns>One terminal result for every object create, reconcile, or delete item.</returns>
    public async Task<IReadOnlyList<PlanItem>> ApplyAsync(
        VaultPair pair,
        IPairStateLease stateLease,
        string runId,
        IReadOnlyList<PlanItem> plan,
        ObjectSignatureService signatures,
        CancellationToken cancellationToken)
    {
        var sourceVaultClient = _clientFactory.Create(pair.Source, false);
        var targetVaultClient = _clientFactory.Create(pair.Target, true);
        var objectResults = new List<PlanItem>();
        foreach (var objectPlanItem in plan.Where(
                     planItem => planItem.Action is "CreateObject" or "ReconcileObject" or "DeleteObject"))
        {
            stateLease.EnsureLeaseHeld();
            var objectResult = objectPlanItem.Action == "DeleteObject"
                ? await DeleteAsync(objectPlanItem, stateLease, runId, targetVaultClient, signatures, cancellationToken)
                : await ReconcileAsync(
                    objectPlanItem,
                    stateLease,
                    runId,
                    sourceVaultClient,
                    targetVaultClient,
                    signatures,
                    cancellationToken);
            objectResults.Add(objectResult);
        }

        return objectResults;
    }

    private async Task<PlanItem> ReconcileAsync(
        PlanItem item,
        IPairStateLease lease,
        string runId,
        IObjectReplicationVaultClient sourceClient,
        IObjectReplicationVaultClient targetClient,
        ObjectSignatureService signatures,
        CancellationToken cancellationToken)
    {
        var objectStateKey = ReplicationPlanner.GetObjectKey(item.ObjectType, item.Name);
        if (lease.State.PendingObjectMutations.ContainsKey(objectStateKey))
        {
            return Outcome(item, "BLOCKED_UNRESOLVED_INTENT", "A durable object mutation intent remains unresolved.");
        }

        using var sourceObject = await sourceClient.ReadAsync(
            item.ObjectType,
            item.Name,
            item.SourceVersion,
            cancellationToken);
        if (sourceObject is null || !string.Equals(sourceObject.Version, item.SourceVersion, StringComparison.Ordinal))
        {
            return Outcome(item, "STALE_PLAN_SOURCE_VERSION_UNAVAILABLE", "The exact planned source version is no longer available.");
        }

        var sourceSignature = signatures.Compute(sourceObject.ToSignatureInput());
        using var liveTarget = await targetClient.ReadAsync(item.ObjectType, item.Name, null, cancellationToken);
        lease.State.ObjectBaselines.TryGetValue(objectStateKey, out var baseline);
        if (item.Action == "CreateObject")
        {
            if (liveTarget is not null)
            {
                return Outcome(item, "CONFLICT_TARGET_APPEARED", "The target appeared after planning; no write was attempted.");
            }
        }
        else
        {
            if (baseline is null
                || !string.Equals(baseline.DomainVersion, ObjectSignatureService.DomainVersion, StringComparison.Ordinal)
                || !string.Equals(baseline.HmacKeyVersion, signatures.KeyVersion, StringComparison.Ordinal))
            {
                return Outcome(item, "BLOCKED_INCOMPATIBLE_BASELINE", "The target baseline is unavailable or uses another signature/key version and requires explicit administrative recovery.");
            }

            if (liveTarget is null)
            {
                return Outcome(item, "CONFLICT_MANAGED_TARGET_MISSING", "The previously managed target is missing.");
            }

            var liveTargetSignature = signatures.Compute(liveTarget.ToSignatureInput());
            if (!ObjectSignatureService.Equals(baseline.TargetSignature, liveTargetSignature))
            {
                return Outcome(item, "CONFLICT_EXTERNALLY_MODIFIED", "The live target signature no longer matches its committed baseline.");
            }

            if (ObjectSignatureService.Equals(baseline.SourceSignature, sourceSignature))
            {
                if (!string.Equals(baseline.TargetVersion, liveTarget.Version, StringComparison.Ordinal))
                {
                    lease.State.ObjectBaselines[objectStateKey] = baseline with
                    {
                        TargetVersion = liveTarget.Version,
                        VerifiedAt = DateTimeOffset.UtcNow,
                    };
                    await lease.SaveStateAsync(cancellationToken);
                }

                return Outcome(item, "IN_SYNC_SIGNATURE_VERIFIED", "Source and target signatures match their committed managed state.")
                    with { TargetVersion = liveTarget.Version };
            }
        }

        var expectedTargetSignature = signatures.Compute((sourceObject with
        {
            VersionlessObjectId = targetClient.GetVersionlessObjectId(item.ObjectType, item.Name),
            Enabled = sourceObject.Enabled ?? true,
        }).ToSignatureInput());
        // Persist intent before crossing the no-retry mutation boundary.
        lease.State.PendingObjectMutations[objectStateKey] = new ObjectMutationIntent
        {
            RunId = runId,
            ObjectType = item.ObjectType,
            ObjectId = targetClient.GetVersionlessObjectId(item.ObjectType, item.Name),
            Action = item.Action,
            SourceVersion = sourceObject.Version,
            ExpectedSourceSignature = sourceSignature,
            ExpectedTargetSignature = expectedTargetSignature,
            TargetVersionBefore = liveTarget?.Version,
            CreatedAt = DateTimeOffset.UtcNow,
        };
        await lease.SaveStateAsync(cancellationToken);

        ReplicatedObject? written = null;
        try
        {
            written = await targetClient.WriteAsync(sourceObject, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (IsDefinitiveFailure(exception))
        {
            lease.State.PendingObjectMutations.Remove(objectStateKey);
            await lease.SaveStateAsync(cancellationToken);
            return Outcome(item, "WRITE_FAILED_DEFINITIVELY", SafeError(exception));
        }
        catch (Exception exception)
        {
            _logger.LogError(exception,
                "Object mutation outcome is ambiguous. Run {RunId}; type {ObjectType}; action {Action}.",
                runId, item.ObjectType, item.Action);
            return Outcome(item, "AMBIGUOUS_OUTCOME_UNRESOLVED_INTENT", SafeError(exception));
        }

        using var writtenLifetime = written;
        ReplicatedObject? verified;
        try
        {
            verified = await targetClient.ReadAsync(item.ObjectType, item.Name, written.Version, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _logger.LogError(exception,
                "Object verification outcome is ambiguous. Run {RunId}; type {ObjectType}; action {Action}.",
                runId, item.ObjectType, item.Action);
            return Outcome(item, "AMBIGUOUS_OUTCOME_UNRESOLVED_INTENT", SafeError(exception));
        }

        using var verifiedLifetime = verified;
        if (verified is null || !string.Equals(verified.Version, written.Version, StringComparison.Ordinal))
        {
            return Outcome(item, "AMBIGUOUS_OUTCOME_UNRESOLVED_INTENT", "The exact written version could not be read back.");
        }

        var verifiedTargetSignature = signatures.Compute(verified.ToSignatureInput());
        if (!ObjectSignatureService.Equals(expectedTargetSignature, verifiedTargetSignature))
        {
            return Outcome(item, "AMBIGUOUS_OUTCOME_UNRESOLVED_INTENT", "The exact written version did not match the expected signature.");
        }

        lease.State.ObjectBaselines[objectStateKey] = new ObjectBaseline
        {
            DomainVersion = ObjectSignatureService.DomainVersion,
            ObjectType = item.ObjectType,
            ObjectId = verified.VersionlessObjectId,
            SourceVersion = sourceObject.Version,
            TargetVersion = verified.Version,
            SourceSignature = sourceSignature,
            TargetSignature = verifiedTargetSignature,
            HmacKeyVersion = signatures.KeyVersion,
            VerifiedAt = DateTimeOffset.UtcNow,
        };
        lease.State.PendingObjectMutations.Remove(objectStateKey);
        await lease.SaveStateAsync(cancellationToken);
        return Outcome(item, "OBJECT_REPLICATED_AND_VERIFIED", "The exact target version was verified and committed.")
            with { TargetVersion = verified.Version };
    }

    private async Task<PlanItem> DeleteAsync(
        PlanItem item,
        IPairStateLease lease,
        string runId,
        IObjectReplicationVaultClient targetClient,
        ObjectSignatureService signatures,
        CancellationToken cancellationToken)
    {
        var objectStateKey = ReplicationPlanner.GetObjectKey(item.ObjectType, item.Name);
        if (lease.State.PendingObjectMutations.ContainsKey(objectStateKey))
        {
            return Outcome(item, "BLOCKED_UNRESOLVED_INTENT", "A durable object mutation intent remains unresolved.");
        }

        if (!lease.State.ObjectBaselines.TryGetValue(objectStateKey, out var baseline)
            || !string.Equals(baseline.DomainVersion, ObjectSignatureService.DomainVersion, StringComparison.Ordinal)
            || !string.Equals(baseline.HmacKeyVersion, signatures.KeyVersion, StringComparison.Ordinal))
        {
            return Outcome(item, "BLOCKED_INCOMPATIBLE_BASELINE", "A compatible ownership baseline is required for deletion.");
        }

        using var liveTarget = await targetClient.ReadAsync(item.ObjectType, item.Name, null, cancellationToken);
        if (liveTarget is null)
        {
            return Outcome(item, "CONFLICT_MANAGED_TARGET_MISSING", "The target disappeared before the planned delete.");
        }

        var liveSignature = signatures.Compute(liveTarget.ToSignatureInput());
        if (!ObjectSignatureService.Equals(baseline.TargetSignature, liveSignature))
        {
            return Outcome(item, "CONFLICT_EXTERNALLY_MODIFIED", "The target changed after the last committed verification.");
        }

        // Deletion uses the same intent-before-mutation boundary as create and reconcile operations.
        lease.State.PendingObjectMutations[objectStateKey] = new ObjectMutationIntent
        {
            RunId = runId,
            ObjectType = item.ObjectType,
            ObjectId = liveTarget.VersionlessObjectId,
            Action = "DeleteObject",
            SourceVersion = baseline.SourceVersion,
            ExpectedSourceSignature = baseline.SourceSignature,
            ExpectedTargetSignature = baseline.TargetSignature,
            TargetVersionBefore = liveTarget.Version,
            CreatedAt = DateTimeOffset.UtcNow,
        };
        await lease.SaveStateAsync(cancellationToken);

        try
        {
            await targetClient.DeleteAsync(item.ObjectType, item.Name, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (IsDefinitiveFailure(exception))
        {
            lease.State.PendingObjectMutations.Remove(objectStateKey);
            await lease.SaveStateAsync(cancellationToken);
            return Outcome(item, "DELETE_FAILED_DEFINITIVELY", SafeError(exception));
        }
        catch (Exception exception)
        {
            _logger.LogError(exception,
                "Object delete outcome is ambiguous. Run {RunId}; type {ObjectType}.",
                runId, item.ObjectType);
            return Outcome(item, "AMBIGUOUS_OUTCOME_UNRESOLVED_INTENT", SafeError(exception));
        }

        ReplicatedObject? remaining;
        try
        {
            remaining = await targetClient.ReadAsync(item.ObjectType, item.Name, null, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _logger.LogError(exception,
                "Object delete verification outcome is ambiguous. Run {RunId}; type {ObjectType}.",
                runId, item.ObjectType);
            return Outcome(item, "AMBIGUOUS_OUTCOME_UNRESOLVED_INTENT", SafeError(exception));
        }

        using var remainingLifetime = remaining;
        if (remaining is not null)
        {
            return Outcome(item, "AMBIGUOUS_OUTCOME_UNRESOLVED_INTENT", "The target still appeared active after the delete request.");
        }

        lease.State.ObjectBaselines.Remove(objectStateKey);
        lease.State.PendingObjectMutations.Remove(objectStateKey);
        if (lease.State.DeletionApproval is not null)
        {
            lease.State.DeletionApproval = null;
        }

        await lease.SaveStateAsync(cancellationToken);
        return Outcome(item, "OBJECT_SOFT_DELETED_AND_VERIFIED", "The target is no longer active; no purge was attempted.");
    }

    private static bool IsDefinitiveFailure(Exception exception) =>
        exception is RequestFailedException requestFailure
        && requestFailure.Status is >= 400 and < 500
        && requestFailure.Status is not 408 and not 429;

    private static string SafeError(Exception exception) =>
        exception is RequestFailedException requestFailure
            ? $"HTTP {requestFailure.Status}, error {requestFailure.ErrorCode ?? "unknown"}."
            : exception.GetType().Name;

    private static PlanItem Outcome(PlanItem item, string status, string detail) =>
        item with { Status = status, Detail = detail };
}
