using System.Diagnostics;
using System.Security.Cryptography;
using Azure;
using KeyVaultSync.Runner.State;
using Microsoft.Extensions.Logging;

namespace KeyVaultSync.Runner.Sync;

internal interface INativeSeedVaultClientFactory
{
    INativeSeedVaultClient Create(VaultResource vault, bool isTarget);
}

internal interface INativeSeedVaultClient
{
    Task<NativeKeyObservation> ReadKeyAsync(string name, string? version, CancellationToken cancellationToken);
    Task<byte[]> BackupKeyAsync(string name, CancellationToken cancellationToken);
    Task<NativeKeyObservation> RestoreKeyBackupAsync(string name, byte[] backup, CancellationToken cancellationToken);
    Task<NativeCertificateGroupObservation> ReadCertificateGroupAsync(string name, string? version, CancellationToken cancellationToken);
    Task<byte[]> BackupCertificateAsync(string name, CancellationToken cancellationToken);
    Task<NativeCertificateGroupObservation> RestoreCertificateBackupAsync(string name, byte[] backup, CancellationToken cancellationToken);
    Task<bool> HasAnyObjectNamedAsync(string name, CancellationToken cancellationToken);
}

internal sealed record NativeKeyObservation(
    string Name,
    string Version,
    string? KeyType,
    string? PublicFingerprintSha256,
    IReadOnlyList<string> Versions);

internal sealed record NativeCertificateGroupObservation(
    string Name,
    string Version,
    string? PublicFingerprintSha256,
    string? BackingKeyName,
    string? BackingKeyVersion,
    string? BackingKeyType,
    string? BackingKeyPublicFingerprintSha256,
    string? BackingSecretName,
    string? BackingSecretVersion,
    IReadOnlyList<string> CertificateVersions,
    IReadOnlyList<string> BackingKeyVersions,
    IReadOnlyList<string> BackingSecretVersions);

/// <summary>Executes only planned one-time native seeds using durable pending intents and exact-version verification.</summary>
/// <remarks>
/// <para>Backup payloads stay in process memory and are cleared after use. Restore calls cross a no-retry boundary;
/// any outcome after a request starts remains pending unless the returned object and its group are verified.</para>
/// <para>Native restore is not version-by-version synchronization. The source is rechecked around whole-object backup,
/// and subsequent source versions are deliberately not copied after the first verified seed.</para>
/// </remarks>
internal sealed class NativeSeedExecutor(
    INativeSeedVaultClientFactory clientFactory,
    ILogger<NativeSeedExecutor> logger)
{
    private const string ReadyForKeySeed = "ELIGIBLE_ONE_TIME_SEED_IF_TARGET_STAYS_EMPTY";
    private const string ReadyForCertificateGroupSeed = "ELIGIBLE_ONE_TIME_SEED_IF_TARGET_GROUP_STAYS_EMPTY";
    private static readonly EventId NativeSeedOutcomeEventId = new(5100, "NativeSeedOutcome");

    public async Task<IReadOnlyList<PlanItem>> ApplyAsync(
        VaultPair pair,
        IPairStateLease lease,
        string runId,
        IReadOnlyList<PlanItem> plan,
        VaultInventory source,
        CancellationToken cancellationToken)
    {
        var eligibleItems = plan.Where(item =>
                (item.ObjectType == "Key" && item.Action == "NativeRestore" && item.Status == ReadyForKeySeed)
                || (item.ObjectType == "CertificateGroup" && item.Action == "NativeRestore" && item.Status == ReadyForCertificateGroupSeed))
            .ToArray();
        if (eligibleItems.Length == 0)
        {
            return [];
        }

        var sourceClient = clientFactory.Create(pair.Source, isTarget: false);
        var targetClient = clientFactory.Create(pair.Target, isTarget: true);
        var results = new List<PlanItem>(eligibleItems.Length);
        using var activity = RunnerTelemetry.ActivitySource.StartActivity("keyvault.native-seed-pair");
        activity?.SetTag("sync.pair_id", pair.PairId);
        activity?.SetTag("sync.run_id", runId);
        activity?.SetTag("native_seed.eligible_count", eligibleItems.Length);
        logger.LogInformation("Native seed phase started for pair {PairId}; run {RunId}; {EligibleCount} eligible items.",
            pair.PairId, runId, eligibleItems.Length);

        foreach (var item in eligibleItems)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lease.EnsureLeaseHeld();
            results.Add(item.ObjectType == "Key"
                ? await SeedKeyAsync(pair, lease, runId, item, source, sourceClient, targetClient, cancellationToken)
                : await SeedCertificateGroupAsync(pair, lease, runId, item, source, sourceClient, targetClient, cancellationToken));
        }

        activity?.SetTag("native_seed.outcome_count", results.Count);
        activity?.SetStatus(ActivityStatusCode.Ok);
        logger.LogInformation("Native seed phase completed for pair {PairId}; run {RunId}; {OutcomeCount} outcomes recorded.",
            pair.PairId, runId, results.Count);
        return results;
    }

    private async Task<PlanItem> SeedKeyAsync(
        VaultPair pair,
        IPairStateLease lease,
        string runId,
        PlanItem plannedItem,
        VaultInventory source,
        INativeSeedVaultClient sourceClient,
        INativeSeedVaultClient targetClient,
        CancellationToken cancellationToken)
    {
        var name = plannedItem.Name;
        var sourceSummary = source.Keys.FirstOrDefault(key => key.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (sourceSummary is null
            || string.IsNullOrWhiteSpace(plannedItem.SourceVersion)
            || !string.Equals(sourceSummary.LatestVersion, plannedItem.SourceVersion, StringComparison.Ordinal))
        {
            return Outcome(pair, plannedItem, "BLOCKED_SOURCE_KEY_VERSION_UNKNOWN", null,
                "The source key head is no longer the version admitted by the plan.");
        }

        if (lease.State.PendingKeySeeds.TryGetValue(name, out var pending))
        {
            return Outcome(pair, plannedItem, "BLOCKED_PENDING_NATIVE_SEED_RESOLUTION", null,
                $"Run {pending.RunId} already has a durable restore intent. Resolve the target before another attempt.");
        }

        if (lease.State.KeySeedBaselines.ContainsKey(name))
        {
            return Outcome(pair, plannedItem, "CONFLICT_NATIVE_SEED_ALREADY_BASELINED", null,
                "A verified one-time seed baseline already exists. Native restore will not overwrite or rotate it.");
        }

        var intentPersisted = false;
        var restoreAttempted = false;
        byte[]? backup = null;
        try
        {
            var sourceKey = await sourceClient.ReadKeyAsync(name, plannedItem.SourceVersion, cancellationToken);
            if (!KeyObservationMatches(sourceSummary, sourceKey, plannedItem.SourceVersion))
            {
                return Outcome(pair, plannedItem, "BLOCKED_SOURCE_KEY_CHANGED", null,
                    "The exact source key version no longer matches the complete inventory observation.");
            }

            var sourceHead = await sourceClient.ReadKeyAsync(name, version: null, cancellationToken);
            if (!string.Equals(sourceHead.Version, plannedItem.SourceVersion, StringComparison.Ordinal))
            {
                return Outcome(pair, plannedItem, "BLOCKED_SOURCE_KEY_HEAD_CHANGED", null,
                    "The source key head changed since planning; no target restore was attempted.");
            }

            backup = await sourceClient.BackupKeyAsync(name, cancellationToken);
            sourceHead = await sourceClient.ReadKeyAsync(name, version: null, cancellationToken);
            if (!string.Equals(sourceHead.Version, plannedItem.SourceVersion, StringComparison.Ordinal))
            {
                return Outcome(pair, plannedItem, "BLOCKED_SOURCE_KEY_CHANGED_DURING_BACKUP", null,
                    "The source key head changed while its whole-object backup was being prepared.");
            }

            if (await targetClient.HasAnyObjectNamedAsync(name, cancellationToken))
            {
                return Outcome(pair, plannedItem, "BLOCKED_TARGET_NAME_BECAME_OCCUPIED", null,
                    "A live target key, certificate, secret, or soft-deleted name now collides with this key.");
            }

            lease.State.PendingKeySeeds[name] = new NativeSeedIntent
            {
                RunId = runId,
                SourceVersion = plannedItem.SourceVersion,
                CreatedAt = DateTimeOffset.UtcNow,
            };
            await PersistStateAsync(lease, name);
            intentPersisted = true;

            lease.EnsureLeaseHeld();
            sourceHead = await sourceClient.ReadKeyAsync(name, version: null, cancellationToken);
            if (!string.Equals(sourceHead.Version, plannedItem.SourceVersion, StringComparison.Ordinal))
            {
                await ClearKeyIntentAsync(lease, name);
                intentPersisted = false;
                return Outcome(pair, plannedItem, "BLOCKED_SOURCE_KEY_HEAD_CHANGED", null,
                    "The source key head changed after the durable intent was saved; no target restore was attempted.");
            }

            if (await targetClient.HasAnyObjectNamedAsync(name, cancellationToken))
            {
                await ClearKeyIntentAsync(lease, name);
                intentPersisted = false;
                return Outcome(pair, plannedItem, "BLOCKED_TARGET_NAME_BECAME_OCCUPIED", null,
                    "A live target key, certificate, secret, or soft-deleted name appeared before restore.");
            }

            lease.EnsureLeaseHeld();
            restoreAttempted = true;
            var restoredKey = await targetClient.RestoreKeyBackupAsync(name, backup, cancellationToken);
            if (!KeyObservationMatches(sourceKey, restoredKey)
                || !VersionSetsMatch(sourceSummary.Versions.Select(version => version.Version), restoredKey.Versions))
            {
                throw new InvalidDataException("The restored key identity or version inventory did not match the source backup.");
            }

            lease.State.KeySeedBaselines[name] = new NativeSeedBaseline
            {
                SourceVersion = plannedItem.SourceVersion,
                TargetVersion = restoredKey.Version,
                KeyType = restoredKey.KeyType,
                PublicFingerprintSha256 = restoredKey.PublicFingerprintSha256,
                VerifiedAt = DateTimeOffset.UtcNow,
            };
            lease.State.PendingKeySeeds.Remove(name);
            await PersistStateAsync(lease, name);
            intentPersisted = false;
            return Outcome(pair, plannedItem, "NATIVE_KEY_SEEDED_AND_VERIFIED", restoredKey.Version,
                "The source key was backed up, restored once into an unused target name, verified, and committed to pair state.");
        }
        catch (NativeSeedStatePersistenceException)
        {
            throw;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (restoreAttempted)
            {
                logger.LogError("Native key restore outcome is unresolved for {KeyName}; its durable intent remains and will not be retried automatically.", name);
            }
            else if (intentPersisted)
            {
                await ClearKeyIntentAsync(lease, name);
            }

            throw;
        }
        catch (Exception exception)
        {
            if (restoreAttempted)
            {
                logger.LogError(exception, "Native key restore outcome is unresolved for {KeyName}; its durable intent remains and will not be retried automatically.", name);
                return Outcome(pair, plannedItem, "NATIVE_SEED_OUTCOME_UNRESOLVED", null,
                    "The restore request started but its outcome or verification is uncertain. The durable intent blocks automatic retries.");
            }

            if (intentPersisted)
            {
                await ClearKeyIntentAsync(lease, name);
            }

            logger.LogError(exception, "Native key seed failed before restore for {KeyName}.", name);
            return Outcome(pair, plannedItem, "NATIVE_SEED_FAILED_BEFORE_RESTORE", null,
                $"No target restore was sent. {SafeError(exception)}");
        }
        finally
        {
            if (backup is not null)
            {
                CryptographicOperations.ZeroMemory(backup);
            }
        }
    }

    private async Task<PlanItem> SeedCertificateGroupAsync(
        VaultPair pair,
        IPairStateLease lease,
        string runId,
        PlanItem plannedItem,
        VaultInventory source,
        INativeSeedVaultClient sourceClient,
        INativeSeedVaultClient targetClient,
        CancellationToken cancellationToken)
    {
        var name = plannedItem.Name;
        var sourceSummary = source.Certificates.FirstOrDefault(certificate => certificate.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (sourceSummary is null
            || string.IsNullOrWhiteSpace(plannedItem.SourceVersion)
            || !string.Equals(sourceSummary.LatestVersion, plannedItem.SourceVersion, StringComparison.Ordinal))
        {
            return Outcome(pair, plannedItem, "BLOCKED_SOURCE_CERTIFICATE_VERSION_UNKNOWN", null,
                "The source certificate head is no longer the version admitted by the plan.");
        }

        if (lease.State.PendingCertificateGroupSeeds.TryGetValue(name, out var pending))
        {
            return Outcome(pair, plannedItem, "BLOCKED_PENDING_NATIVE_SEED_RESOLUTION", null,
                $"Run {pending.RunId} already has a durable restore intent. Resolve every target group member before another attempt.");
        }

        if (lease.State.CertificateGroupSeedBaselines.ContainsKey(name))
        {
            return Outcome(pair, plannedItem, "CONFLICT_NATIVE_SEED_ALREADY_BASELINED", null,
                "A verified one-time certificate-group seed baseline already exists. Restore will not overwrite or rotate it.");
        }

        var intentPersisted = false;
        var restoreAttempted = false;
        byte[]? backup = null;
        try
        {
            var sourceGroup = await sourceClient.ReadCertificateGroupAsync(name, plannedItem.SourceVersion, cancellationToken);
            if (!CertificateGroupMatchesInventory(sourceSummary, source, sourceGroup, plannedItem.SourceVersion))
            {
                return Outcome(pair, plannedItem, "BLOCKED_SOURCE_CERTIFICATE_GROUP_CHANGED", null,
                    "The pinned source certificate or one of its same-name backing references no longer matches complete inventory.");
            }

            var sourceHead = await sourceClient.ReadCertificateGroupAsync(name, version: null, cancellationToken);
            if (!string.Equals(sourceHead.Version, plannedItem.SourceVersion, StringComparison.Ordinal))
            {
                return Outcome(pair, plannedItem, "BLOCKED_SOURCE_CERTIFICATE_HEAD_CHANGED", null,
                    "The source certificate head changed since planning; no target restore was attempted.");
            }

            backup = await sourceClient.BackupCertificateAsync(name, cancellationToken);
            sourceHead = await sourceClient.ReadCertificateGroupAsync(name, version: null, cancellationToken);
            if (!string.Equals(sourceHead.Version, plannedItem.SourceVersion, StringComparison.Ordinal))
            {
                return Outcome(pair, plannedItem, "BLOCKED_SOURCE_CERTIFICATE_CHANGED_DURING_BACKUP", null,
                    "The source certificate head changed while its whole-object backup was being prepared.");
            }

            if (await targetClient.HasAnyObjectNamedAsync(name, cancellationToken))
            {
                return Outcome(pair, plannedItem, "BLOCKED_TARGET_GROUP_BECAME_OCCUPIED", null,
                    "A live target certificate, key, secret, or soft-deleted name now collides with this certificate group.");
            }

            lease.State.PendingCertificateGroupSeeds[name] = new NativeSeedIntent
            {
                RunId = runId,
                SourceVersion = plannedItem.SourceVersion,
                CreatedAt = DateTimeOffset.UtcNow,
            };
            await PersistStateAsync(lease, name);
            intentPersisted = true;

            lease.EnsureLeaseHeld();
            sourceHead = await sourceClient.ReadCertificateGroupAsync(name, version: null, cancellationToken);
            if (!string.Equals(sourceHead.Version, plannedItem.SourceVersion, StringComparison.Ordinal))
            {
                await ClearCertificateGroupIntentAsync(lease, name);
                intentPersisted = false;
                return Outcome(pair, plannedItem, "BLOCKED_SOURCE_CERTIFICATE_HEAD_CHANGED", null,
                    "The source certificate head changed after the durable intent was saved; no target restore was attempted.");
            }

            if (await targetClient.HasAnyObjectNamedAsync(name, cancellationToken))
            {
                await ClearCertificateGroupIntentAsync(lease, name);
                intentPersisted = false;
                return Outcome(pair, plannedItem, "BLOCKED_TARGET_GROUP_BECAME_OCCUPIED", null,
                    "A live target certificate, key, secret, or soft-deleted name appeared before restore.");
            }

            lease.EnsureLeaseHeld();
            restoreAttempted = true;
            var restoredGroup = await targetClient.RestoreCertificateBackupAsync(name, backup, cancellationToken);
            if (!CertificateGroupsMatch(sourceGroup, restoredGroup))
            {
                throw new InvalidDataException("The restored certificate or one of its backing objects did not match the source group.");
            }

            lease.State.CertificateGroupSeedBaselines[name] = new NativeSeedBaseline
            {
                SourceVersion = plannedItem.SourceVersion,
                TargetVersion = restoredGroup.Version,
                PublicFingerprintSha256 = restoredGroup.PublicFingerprintSha256,
                BackingKeyVersion = restoredGroup.BackingKeyVersion,
                BackingKeyPublicFingerprintSha256 = restoredGroup.BackingKeyPublicFingerprintSha256,
                BackingSecretVersion = restoredGroup.BackingSecretVersion,
                VerifiedAt = DateTimeOffset.UtcNow,
            };
            lease.State.PendingCertificateGroupSeeds.Remove(name);
            await PersistStateAsync(lease, name);
            intentPersisted = false;
            return Outcome(pair, plannedItem, "NATIVE_CERTIFICATE_GROUP_SEEDED_AND_VERIFIED", restoredGroup.Version,
                "The certificate group was backed up, restored once into unused target namespaces, verified without reading private payloads, and committed to pair state.");
        }
        catch (NativeSeedStatePersistenceException)
        {
            throw;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (restoreAttempted)
            {
                logger.LogError("Native certificate restore outcome is unresolved for {CertificateName}; its durable intent remains and will not be retried automatically.", name);
            }
            else if (intentPersisted)
            {
                await ClearCertificateGroupIntentAsync(lease, name);
            }

            throw;
        }
        catch (Exception exception)
        {
            if (restoreAttempted)
            {
                logger.LogError(exception, "Native certificate restore outcome is unresolved for {CertificateName}; its durable intent remains and will not be retried automatically.", name);
                return Outcome(pair, plannedItem, "NATIVE_SEED_OUTCOME_UNRESOLVED", null,
                    "The restore request started but its outcome or group verification is uncertain. The durable intent blocks automatic retries.");
            }

            if (intentPersisted)
            {
                await ClearCertificateGroupIntentAsync(lease, name);
            }

            logger.LogError(exception, "Native certificate seed failed before restore for {CertificateName}.", name);
            return Outcome(pair, plannedItem, "NATIVE_SEED_FAILED_BEFORE_RESTORE", null,
                $"No target restore was sent. {SafeError(exception)}");
        }
        finally
        {
            if (backup is not null)
            {
                CryptographicOperations.ZeroMemory(backup);
            }
        }
    }

    private static bool KeyObservationMatches(KeySummary expected, NativeKeyObservation actual, string? expectedVersion)
    {
        return actual.Name.Equals(expected.Name, StringComparison.OrdinalIgnoreCase)
            && (expectedVersion is null || actual.Version.Equals(expectedVersion, StringComparison.Ordinal))
            && !string.IsNullOrWhiteSpace(actual.Version)
            && string.Equals(actual.KeyType, expected.KeyType, StringComparison.OrdinalIgnoreCase)
            && (expected.PublicFingerprintSha256 is not null
                ? string.Equals(actual.PublicFingerprintSha256, expected.PublicFingerprintSha256, StringComparison.OrdinalIgnoreCase)
                : IsSymmetricKeyType(expected.KeyType) && actual.PublicFingerprintSha256 is null);
    }

    private static bool KeyObservationMatches(NativeKeyObservation source, NativeKeyObservation target)
    {
        return target.Name.Equals(source.Name, StringComparison.OrdinalIgnoreCase)
            && target.Version.Equals(source.Version, StringComparison.Ordinal)
            && string.Equals(target.KeyType, source.KeyType, StringComparison.OrdinalIgnoreCase)
            && (source.PublicFingerprintSha256 is not null
                ? string.Equals(target.PublicFingerprintSha256, source.PublicFingerprintSha256, StringComparison.OrdinalIgnoreCase)
                : IsSymmetricKeyType(source.KeyType) && target.PublicFingerprintSha256 is null);
    }

    private static bool IsSymmetricKeyType(string? keyType)
    {
        return keyType?.Contains("oct", StringComparison.OrdinalIgnoreCase) == true;
    }

    private static bool CertificateGroupMatchesInventory(
        CertificateSummary expected,
        VaultInventory source,
        NativeCertificateGroupObservation actual,
        string expectedVersion)
    {
        var sourceKeyReference = ParseObjectReference(expected.KeyId, source.VaultName, "keys");
        var sourceSecretReference = ParseObjectReference(expected.SecretId, source.VaultName, "secrets");
        var sourceBackingKey = source.Keys.FirstOrDefault(key =>
            key.Name.Equals(expected.Name, StringComparison.OrdinalIgnoreCase));
        var sourceBackingSecret = source.Secrets.FirstOrDefault(secret =>
            secret.Name.Equals(expected.Name, StringComparison.OrdinalIgnoreCase));
        return actual.Name.Equals(expected.Name, StringComparison.OrdinalIgnoreCase)
            && actual.Version.Equals(expectedVersion, StringComparison.Ordinal)
            && string.Equals(actual.PublicFingerprintSha256, expected.ThumbprintSha256, StringComparison.OrdinalIgnoreCase)
            && sourceKeyReference is not null
            && sourceSecretReference is not null
            && sourceKeyReference.Name.Equals(expected.Name, StringComparison.OrdinalIgnoreCase)
            && sourceSecretReference.Name.Equals(expected.Name, StringComparison.OrdinalIgnoreCase)
            && actual.BackingKeyName?.Equals(expected.Name, StringComparison.OrdinalIgnoreCase) == true
            && actual.BackingKeyVersion == sourceKeyReference.Version
            && actual.BackingSecretName?.Equals(expected.Name, StringComparison.OrdinalIgnoreCase) == true
            && actual.BackingSecretVersion == sourceSecretReference.Version
            && sourceBackingKey is not null
            && sourceBackingKey.Versions.Any(version => version.Version == actual.BackingKeyVersion)
            && string.Equals(sourceBackingKey.KeyType, actual.BackingKeyType, StringComparison.OrdinalIgnoreCase)
            && actual.BackingKeyPublicFingerprintSha256 is not null
            && (sourceBackingKey.LatestVersion != actual.BackingKeyVersion
                || string.Equals(sourceBackingKey.PublicFingerprintSha256, actual.BackingKeyPublicFingerprintSha256, StringComparison.OrdinalIgnoreCase))
            && sourceBackingSecret is not null
            && sourceBackingSecret.Versions.Any(version => version.Version == actual.BackingSecretVersion)
            && VersionSetsMatch(expected.Versions.Select(version => version.Version), actual.CertificateVersions)
            && VersionSetsMatch(sourceBackingKey.Versions.Select(version => version.Version), actual.BackingKeyVersions)
            && VersionSetsMatch(sourceBackingSecret.Versions.Select(version => version.Version), actual.BackingSecretVersions);
    }

    private static bool CertificateGroupsMatch(
        NativeCertificateGroupObservation source,
        NativeCertificateGroupObservation target)
    {
        return target.Name.Equals(source.Name, StringComparison.OrdinalIgnoreCase)
            && target.Version.Equals(source.Version, StringComparison.Ordinal)
            && string.Equals(target.PublicFingerprintSha256, source.PublicFingerprintSha256, StringComparison.OrdinalIgnoreCase)
            && source.BackingKeyName?.Equals(source.Name, StringComparison.OrdinalIgnoreCase) == true
            && target.BackingKeyName?.Equals(target.Name, StringComparison.OrdinalIgnoreCase) == true
            && !string.IsNullOrWhiteSpace(target.BackingKeyVersion)
            && string.Equals(target.BackingKeyType, source.BackingKeyType, StringComparison.OrdinalIgnoreCase)
            && target.BackingKeyVersion == source.BackingKeyVersion
            && source.BackingKeyPublicFingerprintSha256 is not null
            && string.Equals(target.BackingKeyPublicFingerprintSha256, source.BackingKeyPublicFingerprintSha256, StringComparison.OrdinalIgnoreCase)
            && source.BackingSecretName?.Equals(source.Name, StringComparison.OrdinalIgnoreCase) == true
            && target.BackingSecretName?.Equals(target.Name, StringComparison.OrdinalIgnoreCase) == true
            && target.BackingSecretVersion == source.BackingSecretVersion
            && VersionSetsMatch(source.CertificateVersions, target.CertificateVersions)
            && VersionSetsMatch(source.BackingKeyVersions, target.BackingKeyVersions)
            && VersionSetsMatch(source.BackingSecretVersions, target.BackingSecretVersions);
    }

    private static bool VersionSetsMatch(IEnumerable<string> expected, IEnumerable<string> actual)
    {
        var expectedVersions = expected.Where(version => !string.IsNullOrWhiteSpace(version)).ToHashSet(StringComparer.Ordinal);
        var actualVersions = actual.Where(version => !string.IsNullOrWhiteSpace(version)).ToHashSet(StringComparer.Ordinal);
        return expectedVersions.Count > 0 && expectedVersions.SetEquals(actualVersions);
    }

    private static NativeObjectReference? ParseObjectReference(string? identifier, string vaultName, string collection)
    {
        if (!Uri.TryCreate(identifier, UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps
            || !uri.Host.Equals($"{vaultName}.vault.azure.net", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        for (var index = 0; index + 2 < segments.Length; index++)
        {
            if (segments[index].Equals(collection, StringComparison.OrdinalIgnoreCase))
            {
                return new NativeObjectReference(
                    Uri.UnescapeDataString(segments[index + 1]),
                    Uri.UnescapeDataString(segments[index + 2]));
            }
        }

        return null;
    }

    private static async Task PersistStateAsync(IPairStateLease lease, string name)
    {
        try
        {
            await lease.SaveStateAsync(CancellationToken.None);
        }
        catch (Exception exception)
        {
            throw new NativeSeedStatePersistenceException(name, exception);
        }
    }

    private static async Task ClearKeyIntentAsync(IPairStateLease lease, string name)
    {
        lease.State.PendingKeySeeds.Remove(name);
        await PersistStateAsync(lease, name);
    }

    private static async Task ClearCertificateGroupIntentAsync(IPairStateLease lease, string name)
    {
        lease.State.PendingCertificateGroupSeeds.Remove(name);
        await PersistStateAsync(lease, name);
    }

    private PlanItem Outcome(VaultPair pair, PlanItem plannedItem, string status, string? targetVersion, string detail)
    {
        var isError = status.Contains("FAILED", StringComparison.Ordinal)
            || status.Contains("UNRESOLVED", StringComparison.Ordinal);
        var isWarning = status.StartsWith("BLOCKED", StringComparison.Ordinal)
            || status.StartsWith("CONFLICT", StringComparison.Ordinal);
        if (isError)
        {
            logger.LogError(NativeSeedOutcomeEventId,
                "Native seed outcome {Status}. Pair {PairId}; object {ObjectName}; target version {TargetVersion}.",
                status, pair.PairId, plannedItem.Name, targetVersion);
        }
        else if (isWarning)
        {
            logger.LogWarning(NativeSeedOutcomeEventId,
                "Native seed outcome {Status}. Pair {PairId}; object {ObjectName}; target version {TargetVersion}.",
                status, pair.PairId, plannedItem.Name, targetVersion);
        }
        else
        {
            logger.LogInformation(NativeSeedOutcomeEventId,
                "Native seed outcome {Status}. Pair {PairId}; object {ObjectName}; target version {TargetVersion}.",
                status, pair.PairId, plannedItem.Name, targetVersion);
        }

        return plannedItem with
        {
            Status = status,
            TargetVersion = targetVersion,
            Detail = detail,
        };
    }

    private static string SafeError(Exception exception)
    {
        return exception is RequestFailedException requestFailure
            ? $"{exception.GetType().Name}: HTTP {requestFailure.Status}, error {requestFailure.ErrorCode ?? "unknown"}."
            : exception.GetType().Name;
    }

    private sealed record NativeObjectReference(string Name, string Version);

    private sealed class NativeSeedStatePersistenceException(string name, Exception innerException)
        : InvalidOperationException($"Pair state could not be persisted for native seed {name}.", innerException);
}
