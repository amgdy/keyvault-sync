using System.Text.Json;
using KeyVaultSync.Runner.Security;

namespace KeyVaultSync.Runner.Sync;

/// <summary>Creates a deterministic plan from inventory and committed state without making Azure calls.</summary>
/// <remarks>
/// This is a pure decision layer: it neither reads secret values nor changes state or resources. Status/action
/// strings are consumed by the executor and run aggregation, so changing them is a behavioral contract change.
/// Native key and certificate-group entries are conditional proposals for the guarded seed executor.
/// Authorization, recovery, and retirement entries remain guidance rather than executable adapters.
/// </remarks>
internal static class SyncPlanner
{
    /// <summary>Compares observed names, versions, metadata, and committed ownership to propose supported or blocked work.</summary>
    /// <param name="pair">Directional vault mapping used for scope eligibility and diagnostic subjects.</param>
    /// <param name="state">Loaded committed baselines and unresolved intents; this method does not mutate it.</param>
    /// <param name="source">Source observation, including any warnings that invalidate complete-inventory evidence.</param>
    /// <param name="target">Target observation, including active and soft-deleted names.</param>
    /// <param name="hmacAvailable">Whether a configured HMAC service was loaded, not proof that a baseline/key matches.</param>
    /// <returns>Secret proposals followed by key, certificate, authorization, and inventory-warning entries.</returns>
    /// <remarks>
    /// <para>Readiness is conditional on executor-side live checks. The planner cannot verify target value HMACs,
    /// enforce single-writer permissions, or prove that an unused name remains empty before a write.</para>
    /// <para>Warnings are appended as plan entries. Native seed eligibility is withheld when either inventory
    /// has warnings; consumers must still enforce live namespace and source-version checks.
    /// Source absence never generates an automatic target deletion.</para>
    /// </remarks>
    public static List<PlanItem> CreatePlan(VaultPair pair, PairState state, VaultInventory source, VaultInventory target, bool hmacAvailable)
    {
        var plan = new List<PlanItem>();
        var targetSecrets = target.Secrets.ToDictionary(item => item.Name, StringComparer.OrdinalIgnoreCase);
        var targetDeletedSecrets = target.DeletedSecretNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var sourceSecrets = source.Secrets.ToDictionary(item => item.Name, StringComparer.OrdinalIgnoreCase);
        var sourceDeletedSecrets = source.DeletedSecretNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
        // Certificate and backing secret names remain grouped even when reference metadata is incomplete.
        var certificateBackingSecretNames = source.Certificates
            .SelectMany(certificate => new[]
            {
                certificate.Name,
                GetVaultObjectName(certificate.SecretId, "secrets"),
            })
            .Where(name => name is not null)
            .Select(name => name!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var sourceSecret in source.Secrets)
        {
            if (certificateBackingSecretNames.Contains(sourceSecret.Name))
            {
                plan.Add(Item("Secret", sourceSecret.Name, "None", "MANAGED_WITH_CERTIFICATE_GROUP", sourceSecret.LatestVersion, null,
                    "This is a certificate-managed backing secret. Only the certificate-group operation may change it."));
                continue;
            }

            // An unresolved intent outranks freshness comparisons: a previous request might have
            // succeeded without a durable baseline, so treating it as a fresh attempt is unsafe.
            if (state.PendingSecretWrites.TryGetValue(sourceSecret.Name, out var pendingWrite))
            {
                targetSecrets.TryGetValue(sourceSecret.Name, out var pendingTarget);
                plan.Add(Item("Secret", sourceSecret.Name, "ResolvePendingWrite", "BLOCKED_PENDING_WRITE_RESOLUTION",
                    sourceSecret.LatestVersion, pendingTarget?.LatestVersion,
                    $"Run {pendingWrite.RunId} has a durable write intent from {pendingWrite.CreatedAt:O}. Verify the target outcome and resolve this intent before any retry."));
                continue;
            }

            if (targetDeletedSecrets.Contains(sourceSecret.Name))
            {
                plan.Add(Item("Secret", sourceSecret.Name, "SetSecret", "BLOCKED_SOFT_DELETED_TARGET", sourceSecret.LatestVersion, null,
                    "The target name is soft-deleted. The runner never purges or restores it automatically."));
                continue;
            }

            if (!targetSecrets.TryGetValue(sourceSecret.Name, out var targetSecret))
            {
                // A formerly owned target that disappeared is a conflict, not a missing-name seed.
                // Without a baseline, the empty-name proposal still requires live absence checks.
                if (state.SecretBaselines.ContainsKey(sourceSecret.Name))
                {
                    plan.Add(Item("Secret", sourceSecret.Name, "None", "CONFLICT_PREVIOUS_TARGET_MISSING", sourceSecret.LatestVersion, null,
                        "A previously synced target is missing from active inventory. Do not recreate it automatically."));
                }
                else
                {
                    plan.Add(Item("Secret", sourceSecret.Name, "SetSecret", hmacAvailable ? "READY_FOR_APPLY_IF_NAME_STAYS_EMPTY" : "BLOCKED_HMAC_KEY_NOT_CONFIGURED",
                        sourceSecret.LatestVersion, null, "Target secret is absent. Recheck active and soft-deleted target state immediately before any write."));
                }

                continue;
            }

            // Equal names, versions, or values cannot establish ownership of an existing target.
            // Baselines must come from a verified managed write, not implicit adoption during a scan.
            if (!state.SecretBaselines.TryGetValue(sourceSecret.Name, out var baseline))
            {
                plan.Add(Item("Secret", sourceSecret.Name, "CompareHmac", "CONFLICT_UNBASELINED_TARGET", sourceSecret.LatestVersion, targetSecret.LatestVersion,
                    "Target already exists but no committed source/target HMAC baseline exists. Equal values alone do not prove sync ownership."));
                continue;
            }

            // Domain changes alter the fingerprint contract. Do not silently recompute a baseline
            // under a new format; the executor separately checks the configured HMAC key version.
            if (!baseline.ValueDomainVersion.Equals(SecretHmacService.ValueDomainVersion, StringComparison.Ordinal)
                || !baseline.MetadataDomainVersion.Equals(SecretHmacService.MetadataDomainVersion, StringComparison.Ordinal))
            {
                plan.Add(Item("Secret", sourceSecret.Name, "RebaselineAfterReview", "CONFLICT_HMAC_DOMAIN_VERSION", sourceSecret.LatestVersion, targetSecret.LatestVersion,
                    "The stored baseline uses an unknown or legacy HMAC domain. Review exact source/target versions and approve a new baseline explicitly."));
                continue;
            }

            var sourceMetadataDigest = SecretHmacService.ComputeMetadata(
                sourceSecret.Enabled,
                sourceSecret.ContentType,
                sourceSecret.NotBefore,
                sourceSecret.ExpiresOn,
                sourceSecret.Tags);
            var sourceValueUnchanged = string.Equals(sourceSecret.LatestVersion, baseline.SourceVersion, StringComparison.Ordinal);
            var sourceMetadataUnchanged = string.Equals(sourceMetadataDigest, baseline.MetadataDigest, StringComparison.Ordinal);
            var targetVersionUnchanged = string.Equals(targetSecret.LatestVersion, baseline.TargetVersion, StringComparison.Ordinal);
            if (sourceValueUnchanged && sourceMetadataUnchanged)
            {
                if (!targetVersionUnchanged)
                {
                    plan.Add(Item("Secret", sourceSecret.Name, "VerifySecretBaseline",
                        hmacAvailable ? "VERIFY_TARGET_HMAC" : "BLOCKED_HMAC_KEY_NOT_CONFIGURED",
                        sourceSecret.LatestVersion, targetSecret.LatestVersion,
                        "The target head has a new version. Verify its value HMAC and managed metadata against the committed baseline before refreshing version observations."));
                }
                else
                {
                    // This is an inventory/baseline shortcut, not fresh HMAC verification of
                    // the current target value or target metadata. No executor operation is proposed here.
                    plan.Add(Item("Secret", sourceSecret.Name, "None", "IN_SYNC_BY_VERSION_AND_METADATA", sourceSecret.LatestVersion, targetSecret.LatestVersion,
                        "Source version and managed metadata match the last committed baseline."));
                }

                continue;
            }

            if (sourceValueUnchanged)
            {
                plan.Add(Item("Secret", sourceSecret.Name, "UpdateSecretProperties",
                    hmacAvailable ? "VERIFY_TARGET_HMAC_THEN_APPLY_METADATA" : "BLOCKED_HMAC_KEY_NOT_CONFIGURED",
                    sourceSecret.LatestVersion, targetSecret.LatestVersion,
                    "Only source metadata changed. Verify the target value and metadata against the committed baseline before updating the current target version."));
            }
            else
            {
                plan.Add(Item("Secret", sourceSecret.Name, "SetSecret", hmacAvailable ? "VERIFY_TARGET_HMAC_THEN_APPLY" : "BLOCKED_HMAC_KEY_NOT_CONFIGURED",
                    sourceSecret.LatestVersion, targetSecret.LatestVersion,
                    "Source version or metadata changed. Verify the target value and metadata against the committed baseline before writing."));
            }
        }

        // Retain every target-only name, whether the source is soft-deleted, inexplicably absent,
        // or never mapped. This planner has no implemented retirement/deletion policy.
        foreach (var targetSecret in target.Secrets.Where(item => !sourceSecrets.ContainsKey(item.Name)))
        {
            if (sourceDeletedSecrets.Contains(targetSecret.Name))
            {
                plan.Add(Item("Secret", targetSecret.Name, "None", "SOURCE_DELETED_RETAIN_TARGET", null, targetSecret.LatestVersion,
                    "Source is in its soft-deleted inventory. Retain the target unless the configured retirement policy identifies exact versions."));
            }
            else if (state.SecretBaselines.ContainsKey(targetSecret.Name))
            {
                plan.Add(Item("Secret", targetSecret.Name, "None", "SOURCE_ABSENCE_UNEXPLAINED", null, targetSecret.LatestVersion,
                    "A previously mapped source secret is missing from the active inventory. Do not delete the target copy."));
            }
            else
            {
                plan.Add(Item("Secret", targetSecret.Name, "None", "UNMAPPED_TARGET_RETAIN", null, targetSecret.LatestVersion,
                    "Target-only secret has no mapping. Keep it and report it; do not adopt or overwrite automatically."));
            }
        }

        AddKeyPlans(plan, pair, state, source, target);
        AddCertificatePlans(plan, pair, state, source, target);
        AddAuthorizationPlan(plan, source, target);

        foreach (var warning in source.Warnings.Select(value => $"Source: {value}")
                     .Concat(target.Warnings.Select(value => $"Target: {value}")))
        {
            plan.Add(Item("Inventory", pair.Source.Name, "None", "INVENTORY_WARNING", null, null, warning));
        }

        return plan;
    }

    /// <summary>Adds guarded, one-time native key-seed proposals without treating key material as a secret value.</summary>
    /// <remarks>The same-subscription/same-region rule is conservative eligibility, not a guarantee that restore will succeed.</remarks>
    private static void AddKeyPlans(
        ICollection<PlanItem> plan,
        VaultPair pair,
        PairState state,
        VaultInventory source,
        VaultInventory target)
    {
        var targetKeys = target.Keys.ToDictionary(item => item.Name, StringComparer.OrdinalIgnoreCase);
        var targetCertificates = target.Certificates.Select(item => item.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var targetSecrets = target.Secrets.Select(item => item.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var targetDeleted = target.DeletedKeyNames
            .Concat(target.DeletedCertificateNames)
            .Concat(target.DeletedSecretNames)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var certificateBackingKeyNames = source.Certificates
            .SelectMany(certificate => new[]
            {
                certificate.Name,
                GetVaultObjectName(certificate.KeyId, "keys"),
            })
            .Where(name => name is not null)
            .Select(name => name!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var key in source.Keys)
        {
            if (certificateBackingKeyNames.Contains(key.Name))
            {
                plan.Add(Item("Key", key.Name, "None", "MANAGED_WITH_CERTIFICATE_GROUP", key.LatestVersion, null,
                    "This key is a certificate-group backing object. Only the certificate-group operation may restore it."));
                continue;
            }

            if (state.PendingKeySeeds.TryGetValue(key.Name, out var pendingSeed))
            {
                targetKeys.TryGetValue(key.Name, out var pendingTargetKey);
                plan.Add(Item("Key", key.Name, "ResolvePendingNativeSeed", "BLOCKED_PENDING_NATIVE_SEED_RESOLUTION",
                    key.LatestVersion, pendingTargetKey?.LatestVersion,
                    $"Run {pendingSeed.RunId} has a durable restore intent from {pendingSeed.CreatedAt:O}. Verify the target outcome before any retry."));
                continue;
            }

            if (targetDeleted.Contains(key.Name))
            {
                plan.Add(Item("Key", key.Name, "NativeRestore", "BLOCKED_SOFT_DELETED_TARGET", key.LatestVersion,
                    targetKeys.GetValueOrDefault(key.Name)?.LatestVersion,
                    "The target key/certificate/secret name is soft-deleted. Restore or purge requires a separate recovery operation."));
                continue;
            }

            if (source.Warnings.Count > 0 || target.Warnings.Count > 0)
            {
                plan.Add(Item("Key", key.Name, "NativeRestore", "BLOCKED_INCOMPLETE_INVENTORY", key.LatestVersion,
                    targetKeys.GetValueOrDefault(key.Name)?.LatestVersion,
                    "Complete source and target inventories are required before evaluating a native seed."));
                continue;
            }

            if (state.KeySeedBaselines.TryGetValue(key.Name, out var baseline))
            {
                if (!targetKeys.TryGetValue(key.Name, out var seededTarget))
                {
                    plan.Add(Item("Key", key.Name, "None", "CONFLICT_PREVIOUS_NATIVE_SEED_TARGET_MISSING", key.LatestVersion, null,
                        "A previously seeded target key is missing. Do not restore it again automatically."));
                }
                else if (targetCertificates.Contains(key.Name) || targetSecrets.Contains(key.Name))
                {
                    plan.Add(Item("Key", key.Name, "ReviewSeedDrift", "CONFLICT_NATIVE_SEED_NAME_COLLISION",
                        key.LatestVersion, seededTarget.LatestVersion,
                        "A certificate or secret now shares this seeded key name. Do not recreate or overwrite any namespace."));
                }
                else if (string.Equals(seededTarget.LatestVersion, baseline.TargetVersion, StringComparison.Ordinal)
                    && string.Equals(seededTarget.KeyType, baseline.KeyType, StringComparison.OrdinalIgnoreCase)
                    && (baseline.PublicFingerprintSha256 is not null
                        ? string.Equals(seededTarget.PublicFingerprintSha256, baseline.PublicFingerprintSha256, StringComparison.OrdinalIgnoreCase)
                        : IsSymmetricKeyType(baseline.KeyType) && seededTarget.PublicFingerprintSha256 is null))
                {
                    var sourceAdvanced = !string.Equals(key.LatestVersion, baseline.SourceVersion, StringComparison.Ordinal);
                    plan.Add(Item("Key", key.Name, "None",
                        sourceAdvanced ? "SOURCE_ADVANCED_ONE_TIME_SEED_UNCHANGED" : "IN_SYNC_ONE_TIME_SEED",
                        key.LatestVersion, seededTarget.LatestVersion,
                        sourceAdvanced
                            ? "The source has advanced, but this one-time seed does not copy or rotate later key versions."
                            : "The target still matches the verified one-time seed."));
                }
                else
                {
                    plan.Add(Item("Key", key.Name, "ReviewSeedDrift", "CONFLICT_NATIVE_SEED_TARGET_DRIFT", key.LatestVersion, seededTarget.LatestVersion,
                        "The target differs from its verified one-time seed baseline. Do not overwrite, re-seed, or rotate automatically."));
                }

                continue;
            }

            if (targetKeys.ContainsKey(key.Name) || targetCertificates.Contains(key.Name) || targetSecrets.Contains(key.Name))
            {
                plan.Add(Item("Key", key.Name, "None", "BLOCKED_UNOWNED_TARGET_NAME", key.LatestVersion,
                    targetKeys.GetValueOrDefault(key.Name)?.LatestVersion,
                    "The target name is already occupied in a key, certificate, or secret namespace and has no seed baseline."));
            }
            else if (string.IsNullOrWhiteSpace(key.LatestVersion)
                || string.IsNullOrWhiteSpace(key.KeyType)
                || !key.Versions.Any(version => string.Equals(version.Version, key.LatestVersion, StringComparison.Ordinal)))
            {
                plan.Add(Item("Key", key.Name, "NativeRestore", "BLOCKED_SOURCE_KEY_METADATA_INCOMPLETE", key.LatestVersion, null,
                    "The source key head or type could not be established from inventory."));
            }
            else if (SameSubscription(pair.Source.Id, pair.Target.Id)
                && pair.Source.Location.Equals(pair.Target.Location, StringComparison.OrdinalIgnoreCase))
            {
                plan.Add(Item("Key", key.Name, "NativeRestore", "ELIGIBLE_ONE_TIME_SEED_IF_TARGET_STAYS_EMPTY",
                    key.LatestVersion, null, "Native backup/restore is a one-time seed, not recurring key rotation sync."));
            }
            else
            {
                plan.Add(Item("Key", key.Name, "NativeRestore", "BLOCKED_NATIVE_RESTORE_SCOPE", key.LatestVersion, null,
                    "Native key restore is restricted to the same subscription and Azure region."));
            }
        }
    }

    /// <summary>Adds guarded, one-time native restore proposals for certificates and their coupled backing objects.</summary>
    /// <remarks>A certificate is seedable only when its source references resolve to active same-name backing objects.</remarks>
    private static void AddCertificatePlans(
        ICollection<PlanItem> plan,
        VaultPair pair,
        PairState state,
        VaultInventory source,
        VaultInventory target)
    {
        var targetCertificates = target.Certificates.ToDictionary(item => item.Name, StringComparer.OrdinalIgnoreCase);
        var targetKeys = target.Keys.ToDictionary(item => item.Name, StringComparer.OrdinalIgnoreCase);
        var targetSecrets = target.Secrets.ToDictionary(item => item.Name, StringComparer.OrdinalIgnoreCase);
        var targetDeleted = target.DeletedCertificateNames
            .Concat(target.DeletedKeyNames)
            .Concat(target.DeletedSecretNames)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var certificate in source.Certificates)
        {
            if (state.PendingCertificateGroupSeeds.TryGetValue(certificate.Name, out var pendingSeed))
            {
                targetCertificates.TryGetValue(certificate.Name, out var pendingTargetCertificate);
                plan.Add(Item("CertificateGroup", certificate.Name, "ResolvePendingNativeSeed", "BLOCKED_PENDING_NATIVE_SEED_RESOLUTION",
                    certificate.LatestVersion, pendingTargetCertificate?.LatestVersion,
                    $"Run {pendingSeed.RunId} has a durable restore intent from {pendingSeed.CreatedAt:O}. Verify all target group members before any retry."));
                continue;
            }

            if (targetDeleted.Contains(certificate.Name))
            {
                plan.Add(Item("CertificateGroup", certificate.Name, "NativeRestore", "BLOCKED_SOFT_DELETED_TARGET", certificate.LatestVersion, null,
                    "A certificate or same-name backing-object name is soft-deleted. Do not purge or recreate automatically."));
                continue;
            }

            if (source.Warnings.Count > 0 || target.Warnings.Count > 0)
            {
                plan.Add(Item("CertificateGroup", certificate.Name, "NativeRestore", "BLOCKED_INCOMPLETE_INVENTORY", certificate.LatestVersion,
                    targetCertificates.GetValueOrDefault(certificate.Name)?.LatestVersion,
                    "Complete source and target inventories are required before evaluating a certificate-group seed."));
                continue;
            }

            if (state.CertificateGroupSeedBaselines.TryGetValue(certificate.Name, out var baseline))
            {
                if (!targetCertificates.TryGetValue(certificate.Name, out var seededTargetCertificate))
                {
                    var hasRemainingBacking = targetKeys.ContainsKey(certificate.Name) || targetSecrets.ContainsKey(certificate.Name);
                    plan.Add(Item("CertificateGroup", certificate.Name, "ReviewSeedDrift",
                        hasRemainingBacking ? "CONFLICT_PARTIAL_NATIVE_SEED_GROUP" : "CONFLICT_PREVIOUS_NATIVE_SEED_GROUP_MISSING",
                        certificate.LatestVersion, null,
                        hasRemainingBacking
                            ? "The certificate is missing while a backing object remains. Do not restore the group automatically."
                            : "A previously seeded certificate group is missing. Do not restore it again automatically."));
                }
                else if (string.Equals(seededTargetCertificate.LatestVersion, baseline.TargetVersion, StringComparison.Ordinal)
                    && string.Equals(seededTargetCertificate.ThumbprintSha256, baseline.PublicFingerprintSha256, StringComparison.OrdinalIgnoreCase)
                    && IsCertificateGroupReferenceIntact(seededTargetCertificate, target, baseline))
                {
                    var sourceAdvanced = !string.Equals(certificate.LatestVersion, baseline.SourceVersion, StringComparison.Ordinal);
                    plan.Add(Item("CertificateGroup", certificate.Name, "None",
                        sourceAdvanced ? "SOURCE_ADVANCED_ONE_TIME_SEED_UNCHANGED" : "IN_SYNC_ONE_TIME_SEED",
                        certificate.LatestVersion, seededTargetCertificate.LatestVersion,
                        sourceAdvanced
                            ? "The source has advanced, but this one-time seed does not rotate the certificate group."
                            : "The target certificate and its referenced backing key/secret still match the verified one-time seed."));
                }
                else
                {
                    plan.Add(Item("CertificateGroup", certificate.Name, "ReviewSeedDrift", "CONFLICT_NATIVE_SEED_TARGET_DRIFT",
                        certificate.LatestVersion, seededTargetCertificate.LatestVersion,
                        "The certificate or its backing references differ from the verified one-time seed. Do not overwrite or re-seed automatically."));
                }

                continue;
            }

            if (targetCertificates.ContainsKey(certificate.Name)
                || targetKeys.ContainsKey(certificate.Name)
                || targetSecrets.ContainsKey(certificate.Name))
            {
                plan.Add(Item("CertificateGroup", certificate.Name, "None", "BLOCKED_UNOWNED_TARGET_GROUP", certificate.LatestVersion,
                    targetCertificates.GetValueOrDefault(certificate.Name)?.LatestVersion,
                    "At least one target certificate/backing namespace is occupied and no committed seed baseline proves ownership."));
            }
            else if (!IsCertificateGroupReferenceIntact(certificate, source))
            {
                plan.Add(Item("CertificateGroup", certificate.Name, "NativeRestore", "BLOCKED_SOURCE_CERTIFICATE_GROUP_INCOMPLETE", certificate.LatestVersion, null,
                    "The source certificate's current public material and same-name backing key/secret references could not all be verified."));
            }
            else if (SameSubscription(pair.Source.Id, pair.Target.Id)
                && pair.Source.Location.Equals(pair.Target.Location, StringComparison.OrdinalIgnoreCase))
            {
                plan.Add(Item("CertificateGroup", certificate.Name, "NativeRestore", "ELIGIBLE_ONE_TIME_SEED_IF_TARGET_GROUP_STAYS_EMPTY",
                    certificate.LatestVersion, null, "Native certificate backup/restore seeds the certificate and its coupled backing objects once; it does not rotate them."));
            }
            else
            {
                plan.Add(Item("CertificateGroup", certificate.Name, "NativeRestore", "BLOCKED_NATIVE_RESTORE_SCOPE", certificate.LatestVersion, null,
                    "Native certificate restore is restricted to a target vault in the same region as the source."));
            }
        }
    }

    private static bool IsCertificateGroupReferenceIntact(
        CertificateSummary certificate,
        VaultInventory inventory,
        NativeSeedBaseline? expectedBaseline = null)
    {
        if (string.IsNullOrWhiteSpace(certificate.LatestVersion)
            || string.IsNullOrWhiteSpace(certificate.ThumbprintSha256)
            || !certificate.Versions.Any(version => version.Version.Equals(certificate.LatestVersion, StringComparison.Ordinal)))
        {
            return false;
        }

        if (expectedBaseline is not null
            && (string.IsNullOrWhiteSpace(expectedBaseline.BackingKeyVersion)
                || string.IsNullOrWhiteSpace(expectedBaseline.BackingKeyPublicFingerprintSha256)
                || string.IsNullOrWhiteSpace(expectedBaseline.BackingSecretVersion)))
        {
            return false;
        }

        var keyReference = ParseVaultReference(certificate.KeyId, inventory.VaultName, "keys");
        var secretReference = ParseVaultReference(certificate.SecretId, inventory.VaultName, "secrets");
        if (keyReference is null
            || secretReference is null
            || !keyReference.Name.Equals(certificate.Name, StringComparison.OrdinalIgnoreCase)
            || !secretReference.Name.Equals(certificate.Name, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var key = inventory.Keys.FirstOrDefault(item => item.Name.Equals(keyReference.Name, StringComparison.OrdinalIgnoreCase));
        var secret = inventory.Secrets.FirstOrDefault(item => item.Name.Equals(secretReference.Name, StringComparison.OrdinalIgnoreCase));
        var backingKeyPresent = key is not null
            && !string.IsNullOrWhiteSpace(key.KeyType)
            && key.Versions.Any(version => version.Version.Equals(keyReference.Version, StringComparison.Ordinal))
            && (expectedBaseline is null
                || (string.Equals(keyReference.Version, expectedBaseline.BackingKeyVersion, StringComparison.Ordinal)
                    && (!string.Equals(keyReference.Version, key.LatestVersion, StringComparison.Ordinal)
                        || string.Equals(key.PublicFingerprintSha256, expectedBaseline.BackingKeyPublicFingerprintSha256, StringComparison.OrdinalIgnoreCase))));
        var backingSecretPresent = secret is not null
            && secret.Versions.Any(version => version.Version.Equals(secretReference.Version, StringComparison.Ordinal))
            && (expectedBaseline is null
                || string.Equals(secretReference.Version, expectedBaseline.BackingSecretVersion, StringComparison.Ordinal));
        return backingKeyPresent && backingSecretPresent;
    }

    private static bool IsSymmetricKeyType(string? keyType)
    {
        return keyType?.Contains("oct", StringComparison.OrdinalIgnoreCase) == true;
    }

    private static KeyVaultObjectReference? ParseVaultReference(string? identifier, string vaultName, string collection)
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
                return new KeyVaultObjectReference(
                    Uri.UnescapeDataString(segments[index + 1]),
                    Uri.UnescapeDataString(segments[index + 2]));
            }
        }

        return null;
    }

    private static string? GetVaultObjectName(string? identifier, string collection)
    {
        if (!Uri.TryCreate(identifier, UriKind.Absolute, out var uri))
        {
            return null;
        }

        var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        for (var index = 0; index + 1 < segments.Length; index++)
        {
            if (segments[index].Equals(collection, StringComparison.OrdinalIgnoreCase))
            {
                return Uri.UnescapeDataString(segments[index + 1]);
            }
        }

        return null;
    }

    private sealed record KeyVaultObjectReference(string Name, string Version);

    /// <summary>Reports incomplete authorization, model differences, RBAC inventory, or canonical legacy-policy differences.</summary>
    /// <remarks>No branch grants/revokes access. Even equal declarations are not a proof of effective authorization.</remarks>
    private static void AddAuthorizationPlan(ICollection<PlanItem> plan, VaultInventory source, VaultInventory target)
    {
        if (source.Authorization.Warnings.Count > 0 || target.Authorization.Warnings.Count > 0)
        {
            plan.Add(Item("Authorization", source.VaultName, "CompareDeclaredIntent", "AUTHORIZATION_INVENTORY_INCOMPLETE", null, null,
                $"Authorization inventory has {source.Authorization.Warnings.Count} source and {target.Authorization.Warnings.Count} target warnings."));
            return;
        }

        if (source.Authorization.UsesRbac != target.Authorization.UsesRbac)
        {
            plan.Add(Item("Authorization", source.VaultName, "ReconcileDeclaredIntent", "PERMISSION_MODEL_MISMATCH", null, null,
                "Source and target use different authorization models. Compile declared regional intent; do not clone the source document."));
            return;
        }

        if (source.Authorization.UsesRbac)
        {
            plan.Add(Item("Authorization", source.VaultName, "InventoryDirectRoleAssignments", "RBAC_INVENTORY_ONLY", null, null,
                $"Inventory sees {source.Authorization.RoleAssignments.Count} scoped role assignments on source and {target.Authorization.RoleAssignments.Count} on target. Group membership, PIM, deny assignments, and management-group inheritance are not resolved."));
            return;
        }

        var policiesMatch = NormalizeAccessPolicies(source.Authorization.AccessPolicies)
            .SequenceEqual(NormalizeAccessPolicies(target.Authorization.AccessPolicies), StringComparer.Ordinal);
        var status = policiesMatch ? "ACCESS_POLICY_INTENT_MATCH" : "ACCESS_POLICY_INTENT_DIFFERS";
        plan.Add(Item("Authorization", source.VaultName, "CompareDeclaredIntent", status, null, null,
            policiesMatch
                ? $"Source and target declare the same {source.Authorization.AccessPolicies.Count} legacy access policies, including principals and permission sets."
                : $"Source and target declare different legacy access policies ({source.Authorization.AccessPolicies.Count} source, {target.Authorization.AccessPolicies.Count} target). No authorization changes are applied."));
    }

    /// <summary>Canonicalizes principal IDs and sorted permission categories/values for order-insensitive declaration comparison.</summary>
    /// <remarks>
    /// JSON encoding avoids delimiter ambiguity. Casing and order are normalized, but duplicate entries are retained;
    /// this is declaration comparison, not group expansion or semantic permission evaluation.
    /// </remarks>
    private static string[] NormalizeAccessPolicies(IReadOnlyList<AccessPolicySummary> policies)
    {
        return policies
            .Select(policy => JsonSerializer.Serialize(new
            {
                TenantId = policy.TenantId.ToLowerInvariant(),
                ObjectId = policy.ObjectId.ToLowerInvariant(),
                ApplicationId = policy.ApplicationId?.ToLowerInvariant(),
                Permissions = policy.Permissions
                    .OrderBy(permission => permission.Key, StringComparer.OrdinalIgnoreCase)
                    .Select(permission => new
                    {
                        Kind = permission.Key.ToLowerInvariant(),
                        Values = permission.Value
                            .Select(value => value.ToLowerInvariant())
                            .Order(StringComparer.Ordinal)
                            .ToArray(),
                    })
                    .ToArray(),
            }))
            .Order(StringComparer.Ordinal)
            .ToArray();
    }

    /// <summary>Compares the subscription segments of already admitted vault IDs without an ARM lookup.</summary>
    /// <remarks>Assumes discovery supplied conventional full IDs; it is not an identifier validator.</remarks>
    private static bool SameSubscription(string sourceId, string targetId)
    {
        static string? Subscription(string id)
        {
            var segments = id.Split('/', StringSplitOptions.RemoveEmptyEntries);
            return segments.Length >= 2 && segments[0].Equals("subscriptions", StringComparison.OrdinalIgnoreCase)
                ? segments[1]
                : null;
        }

        return string.Equals(Subscription(sourceId), Subscription(targetId), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Constructs a uniform plan entry, keeping human-readable reasoning separate from machine-consumed status tokens.</summary>
    private static PlanItem Item(string type, string name, string action, string status, string? sourceVersion, string? targetVersion, string detail)
    {
        return new PlanItem
        {
            ObjectType = type,
            Name = name,
            Action = action,
            Status = status,
            SourceVersion = sourceVersion,
            TargetVersion = targetVersion,
            Detail = detail,
        };
    }
}
