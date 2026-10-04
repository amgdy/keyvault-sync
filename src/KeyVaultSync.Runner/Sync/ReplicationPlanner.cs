using System.Security.Cryptography;
using System.Text;

namespace KeyVaultSync.Runner.Sync;

/// <summary>Creates a value-free, deterministic plan for supported objects, deletes, and Key Vault RBAC.</summary>
internal static class ReplicationPlanner
{
    /// <summary>Gets the absolute managed-object delete count that triggers the approval circuit breaker.</summary>
    internal const int BulkDeleteCountThreshold = 10;
    /// <summary>Gets the managed-object delete ratio that triggers the approval circuit breaker.</summary>
    internal const decimal BulkDeletePercentageThreshold = 0.25m;

    /// <summary>Creates the complete deterministic, value-free plan for one source/target pair.</summary>
    /// <remarks>
    /// Planning performs no Azure or state writes. Incomplete inventory, missing HMAC configuration,
    /// unsupported material, and ownership conflicts are represented as explicit non-actionable items.
    /// </remarks>
    public static IReadOnlyList<PlanItem> CreatePlan(
        VaultPair pair,
        PairState state,
        VaultInventory sourceInventory,
        VaultInventory targetInventory,
        bool hmacAvailable,
        string? syncPrincipalId,
        DateTimeOffset now)
    {
        var plan = new List<PlanItem>();
        var inventoriesAreComplete = sourceInventory.Warnings.Count == 0
            && targetInventory.Warnings.Count == 0
            && sourceInventory.Authorization.Warnings.Count == 0
            && targetInventory.Authorization.Warnings.Count == 0;
        var certificateNames = sourceInventory.Certificates.Select(certificate => certificate.Name)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        AddObjectPlans(
            plan,
            "Secret",
            sourceInventory.Secrets.Where(secret => !certificateNames.Contains(secret.Name))
                .Select(secret => (secret.Name, secret.CurrentVersion, true)),
            targetInventory.Secrets.Where(secret => !certificateNames.Contains(secret.Name))
                .Select(secret => (secret.Name, secret.CurrentVersion)),
            targetInventory.DeletedSecretNames,
            pair,
            state,
            inventoriesAreComplete,
            hmacAvailable);

        AddObjectPlans(
            plan,
            "Certificate",
            sourceInventory.Certificates.Select(certificate =>
                (certificate.Name, certificate.CurrentVersion, certificate.Exportable == true)),
            targetInventory.Certificates.Select(certificate => (certificate.Name, certificate.CurrentVersion)),
            targetInventory.DeletedCertificateNames,
            pair,
            state,
            inventoriesAreComplete,
            hmacAvailable);

        foreach (var sourceKey in sourceInventory.Keys.Where(key => !certificateNames.Contains(key.Name)))
        {
            var targetKey = targetInventory.Keys.FirstOrDefault(
                candidate => candidate.Name.Equals(sourceKey.Name, StringComparison.OrdinalIgnoreCase));
            plan.Add(Item(
                "Key",
                sourceKey.Name,
                "None",
                targetKey is null
                    ? "BLOCKED_TARGET_KEY_PROVISIONING_REQUIRED"
                    : "BLOCKED_KEY_MATERIAL_EQUIVALENCE_UNVERIFIABLE",
                sourceKey.CurrentVersion,
                targetKey?.CurrentVersion,
                targetKey is null
                    ? "Azure Key Vault does not expose existing private or symmetric key material. Provision an independently generated or externally imported target key before key-scope RBAC can converge."
                    : "A target key with the same name exists, but Azure Key Vault does not expose private or symmetric material so cryptographic equivalence cannot be verified. Key-scope RBAC may still converge."));
        }

        ApplyDeleteCircuitBreaker(plan, state, now);
        AddRbacPlans(plan, pair, sourceInventory, targetInventory, syncPrincipalId);

        foreach (var warning in sourceInventory.Warnings.Select(value => $"Source: {value}")
                     .Concat(targetInventory.Warnings.Select(value => $"Target: {value}")))
        {
            plan.Add(Item("Inventory", pair.PairId, "None", "INVENTORY_WARNING", null, null, warning));
        }

        return Order(plan);
    }

    private static void AddObjectPlans(
        ICollection<PlanItem> plan,
        string objectType,
        IEnumerable<(string Name, string Version, bool Replicable)> sourceObjects,
        IEnumerable<(string Name, string Version)> targetObjects,
        IEnumerable<string> deletedTargetNames,
        VaultPair pair,
        PairState state,
        bool inventoriesAreComplete,
        bool hmacAvailable)
    {
        var sourceObjectsByName = sourceObjects.ToDictionary(
            sourceObject => sourceObject.Name,
            StringComparer.OrdinalIgnoreCase);
        var targetObjectsByName = targetObjects.ToDictionary(
            targetObject => targetObject.Name,
            StringComparer.OrdinalIgnoreCase);
        var softDeletedTargetNames = deletedTargetNames.ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var sourceObject in sourceObjectsByName.Values.OrderBy(
                     sourceObject => sourceObject.Name,
                     StringComparer.OrdinalIgnoreCase))
        {
            var objectStateKey = GetObjectKey(objectType, sourceObject.Name);
            targetObjectsByName.TryGetValue(sourceObject.Name, out var targetObject);
            if (!sourceObject.Replicable)
            {
                plan.Add(Item(objectType, sourceObject.Name, "None", "BLOCKED_CERTIFICATE_REISSUANCE_REQUIRED",
                    sourceObject.Version, targetObject.Version,
                    "The source certificate does not expose exportable PFX material. Reissue or externally import the certificate and private key into the target vault."));
                continue;
            }

            if (!inventoriesAreComplete)
            {
                plan.Add(Item(objectType, sourceObject.Name, "None", "BLOCKED_INCOMPLETE_INVENTORY",
                    sourceObject.Version, targetObject.Version, "Complete source and target inventories are required before mutation."));
                continue;
            }

            if (!hmacAvailable)
            {
                plan.Add(Item(objectType, sourceObject.Name, "None", "BLOCKED_HMAC_KEY_NOT_CONFIGURED",
                    sourceObject.Version, targetObject.Version, "The versioned object integrity key is required for supported object writes."));
                continue;
            }

            if (state.PendingObjectMutations.TryGetValue(objectStateKey, out var pending))
            {
                plan.Add(Item(objectType, sourceObject.Name, "ResolvePendingIntent", "BLOCKED_UNRESOLVED_INTENT",
                    sourceObject.Version, targetObject.Version,
                    $"A durable {pending.Action} intent from run {pending.RunId} remains unresolved."));
                continue;
            }

            if (softDeletedTargetNames.Contains(sourceObject.Name))
            {
                plan.Add(Item(objectType, sourceObject.Name, "None", "BLOCKED_SOFT_DELETED_TARGET",
                    sourceObject.Version, targetObject.Version, "The target name is soft-deleted and will not be purged automatically."));
                continue;
            }

            var hasBaseline = state.ObjectBaselines.TryGetValue(objectStateKey, out var baseline);
            if (string.IsNullOrWhiteSpace(targetObject.Name))
            {
                plan.Add(hasBaseline
                    ? Item(objectType, sourceObject.Name, "None", "CONFLICT_MANAGED_TARGET_MISSING",
                        sourceObject.Version, null, "A committed managed target is missing; automatic recreation is blocked.")
                    : Item(objectType, sourceObject.Name, "CreateObject", "READY_CREATE_IF_TARGET_STAYS_EMPTY",
                        sourceObject.Version, null, "The target is absent and will be rechecked immediately before creation."));
                continue;
            }

            if (!hasBaseline)
            {
                plan.Add(Item(objectType, sourceObject.Name, "None", "CONFLICT_UNMANAGED_TARGET_EXISTS",
                    sourceObject.Version, targetObject.Version, "An existing target without a compatible committed baseline is never adopted implicitly."));
                continue;
            }

            if (!string.Equals(baseline!.DomainVersion, Security.ObjectSignatureService.DomainVersion, StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(baseline.SourceSignature)
                || string.IsNullOrWhiteSpace(baseline.TargetSignature))
            {
                plan.Add(Item(objectType, sourceObject.Name, "None", "BLOCKED_INCOMPATIBLE_BASELINE",
                    sourceObject.Version, targetObject.Version, "The committed baseline is not compatible with the current signature contract and requires explicit administrative recovery."));
                continue;
            }

            plan.Add(Item(objectType, sourceObject.Name, "ReconcileObject", "VERIFY_SIGNATURES_THEN_RECONCILE",
                sourceObject.Version, targetObject.Version,
                "The executor will verify the live target against the committed baseline and compare the exact pinned source state."));
        }

        foreach (var targetObject in targetObjectsByName.Values
                     .Where(targetObject => !sourceObjectsByName.ContainsKey(targetObject.Name))
                     .OrderBy(targetObject => targetObject.Name, StringComparer.OrdinalIgnoreCase))
        {
            var objectStateKey = GetObjectKey(objectType, targetObject.Name);
            if (!state.ObjectBaselines.ContainsKey(objectStateKey))
            {
                plan.Add(Item(objectType, targetObject.Name, "None", "CONFLICT_UNMANAGED_TARGET_ONLY",
                    null, targetObject.Version, "Target-only content without a baseline is retained."));
                continue;
            }

            if (!inventoriesAreComplete || !hmacAvailable)
            {
                plan.Add(Item(objectType, targetObject.Name, "None",
                    inventoriesAreComplete ? "BLOCKED_HMAC_KEY_NOT_CONFIGURED" : "BLOCKED_INCOMPLETE_INVENTORY",
                    null, targetObject.Version, "Delete evidence requires complete inventory and the integrity key."));
                continue;
            }

            if (state.PendingObjectMutations.ContainsKey(objectStateKey))
            {
                plan.Add(Item(objectType, targetObject.Name, "ResolvePendingIntent", "BLOCKED_UNRESOLVED_INTENT",
                    null, targetObject.Version, "A durable object mutation intent remains unresolved."));
                continue;
            }

            plan.Add(Item(objectType, targetObject.Name, "DeleteObject", "VERIFY_SIGNATURE_THEN_SOFT_DELETE",
                null, targetObject.Version, "The source is absent; the executor will verify managed ownership before soft delete."));
        }
    }

    private static void ApplyDeleteCircuitBreaker(
        IList<PlanItem> plan,
        PairState state,
        DateTimeOffset now)
    {
        var deleteItems = plan.Where(item => item.Action == "DeleteObject")
            .OrderBy(item => item.ObjectType, StringComparer.Ordinal)
            .ThenBy(item => item.Name, StringComparer.Ordinal)
            .ToArray();
        if (deleteItems.Length == 0)
        {
            return;
        }

        var managedCount = Math.Max(1, state.ObjectBaselines.Count);
        var percentage = (decimal)deleteItems.Length / managedCount;
        var thresholdExceeded = deleteItems.Length >= BulkDeleteCountThreshold
            || percentage >= BulkDeletePercentageThreshold;
        if (!thresholdExceeded)
        {
            return;
        }

        var hash = ComputeDeletionPlanHash(deleteItems);
        var approved = state.DeletionApproval is { } approval
            && approval.ExpiresAt > now
            && string.Equals(approval.PlanHash, hash, StringComparison.OrdinalIgnoreCase);
        if (approved)
        {
            return;
        }

        for (var index = 0; index < plan.Count; index++)
        {
            if (plan[index].Action == "DeleteObject")
            {
                plan[index] = plan[index] with
                {
                    Action = "None",
                    Status = "BLOCKED_DELETE_CIRCUIT_BREAKER",
                    Detail = $"Bulk deletion requires a one-use approval for plan hash {hash}.",
                };
            }
        }
    }

    /// <summary>Computes the stable approval hash for the actionable object-deletion set.</summary>
    internal static string ComputeDeletionPlanHash(IEnumerable<PlanItem> items)
    {
        var canonical = string.Join(
            "\n",
            items.Where(item => item.Action == "DeleteObject")
                .OrderBy(item => item.ObjectType, StringComparer.Ordinal)
                .ThenBy(item => item.Name, StringComparer.Ordinal)
                .Select(item => $"{item.ObjectType}\0{item.Name}"));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static void AddRbacPlans(
        ICollection<PlanItem> plan,
        VaultPair pair,
        VaultInventory sourceInventory,
        VaultInventory targetInventory,
        string? syncPrincipalId)
    {
        if (sourceInventory.Authorization.Warnings.Count > 0
            || targetInventory.Authorization.Warnings.Count > 0)
        {
            plan.Add(Item("Authorization", pair.PairId, "None", "BLOCKED_AUTHORIZATION_INVENTORY_INCOMPLETE",
                null, null, "Complete source and target authorization inventories are required before RBAC reconciliation."));
            return;
        }

        var sourceAssignments = sourceInventory.Authorization.RoleAssignments
            .Where(assignment => assignment.ScopeKind is "Vault" or "Object")
            .DistinctBy(assignment => NormalizeAssignmentId(assignment.Id), StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var targetAssignments = targetInventory.Authorization.RoleAssignments
            .Where(assignment => assignment.ScopeKind is "Vault" or "Object")
            .DistinctBy(assignment => NormalizeAssignmentId(assignment.Id), StringComparer.OrdinalIgnoreCase)
            .ToArray();

        foreach (var sourceAssignment in sourceAssignments)
        {
            if (!KeyVaultRbacPolicy.IsKeyVaultRole(sourceAssignment.RoleDefinitionId))
            {
                plan.Add(AuthorizationItem(
                    sourceAssignment,
                    "None",
                    "ROLE_DEFINITION_NOT_AVAILABLE",
                    MapScope(pair, sourceAssignment.Scope),
                    null,
                    "Only the explicit Key Vault built-in role allowlist is replicated automatically."));
                continue;
            }

            var targetScope = MapScope(pair, sourceAssignment.Scope);
            if (targetScope is null)
            {
                continue;
            }

            var existing = targetAssignments.FirstOrDefault(targetAssignment =>
                AssignmentEquivalent(sourceAssignment, targetAssignment)
                && targetAssignment.Scope.Equals(targetScope, StringComparison.OrdinalIgnoreCase));
            if (existing is not null)
            {
                plan.Add(AuthorizationItem(sourceAssignment, "None", "RBAC_ASSIGNMENT_IN_SYNC",
                    targetScope, GetAssignmentName(existing.Id), "The target role assignment matches the source declaration."));
                continue;
            }

            var assignmentId = KeyVaultRbacPolicy.GetDeterministicAssignmentId(
                targetScope,
                sourceAssignment.PrincipalId,
                sourceAssignment.RoleDefinitionId);
            plan.Add(AuthorizationItem(sourceAssignment, "CreateRoleAssignment", "READY_CREATE_ROLE_ASSIGNMENT",
                targetScope, assignmentId, "Create the exact allowed Key Vault assignment at the mapped target scope."));
        }

        foreach (var targetAssignment in targetAssignments)
        {
            if (!KeyVaultRbacPolicy.IsKeyVaultRole(targetAssignment.RoleDefinitionId))
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(syncPrincipalId))
            {
                plan.Add(AuthorizationItem(targetAssignment, "None", "BLOCKED_SYNC_IDENTITY_UNKNOWN",
                    targetAssignment.Scope, GetAssignmentName(targetAssignment.Id),
                    "Target-only RBAC cleanup requires KEYVAULTSYNC_PRINCIPAL_ID so self-revocation can be excluded."));
                continue;
            }

            if (targetAssignment.PrincipalId.Equals(syncPrincipalId, StringComparison.OrdinalIgnoreCase))
            {
                plan.Add(AuthorizationItem(targetAssignment, "None", "SKIPPED_SYNC_IDENTITY_SELF_ASSIGNMENT",
                    targetAssignment.Scope, GetAssignmentName(targetAssignment.Id),
                    "The runtime identity is permanently excluded from target-only RBAC cleanup."));
                continue;
            }

            var sourceScope = ReverseMapScope(pair, targetAssignment.Scope);
            var matchingSource = sourceScope is not null && sourceAssignments.Any(sourceAssignment =>
                sourceAssignment.Scope.Equals(sourceScope, StringComparison.OrdinalIgnoreCase)
                && AssignmentEquivalent(sourceAssignment, targetAssignment));
            if (!matchingSource)
            {
                plan.Add(AuthorizationItem(targetAssignment, "DeleteRoleAssignment", "READY_DELETE_ROLE_ASSIGNMENT",
                    targetAssignment.Scope, GetAssignmentName(targetAssignment.Id),
                    "Delete the exact target-only allowed Key Vault role assignment."));
            }
        }
    }

    private static string? MapScope(VaultPair pair, string sourceScope)
    {
        if (sourceScope.Equals(pair.Source.Id, StringComparison.OrdinalIgnoreCase))
        {
            return pair.Target.Id;
        }

        var prefix = pair.Source.Id.TrimEnd('/') + "/";
        return sourceScope.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? pair.Target.Id.TrimEnd('/') + sourceScope[pair.Source.Id.Length..]
            : null;
    }

    private static string? ReverseMapScope(VaultPair pair, string targetScope)
    {
        if (targetScope.Equals(pair.Target.Id, StringComparison.OrdinalIgnoreCase))
        {
            return pair.Source.Id;
        }

        var prefix = pair.Target.Id.TrimEnd('/') + "/";
        return targetScope.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? pair.Source.Id.TrimEnd('/') + targetScope[pair.Target.Id.Length..]
            : null;
    }

    private static bool AssignmentEquivalent(RoleAssignmentSummary left, RoleAssignmentSummary right) =>
        left.PrincipalId.Equals(right.PrincipalId, StringComparison.OrdinalIgnoreCase)
        && GetRoleId(left.RoleDefinitionId).Equals(GetRoleId(right.RoleDefinitionId), StringComparison.OrdinalIgnoreCase)
        && string.Equals(left.PrincipalType, right.PrincipalType, StringComparison.OrdinalIgnoreCase)
        && string.Equals(left.Condition, right.Condition, StringComparison.Ordinal)
        && string.Equals(left.ConditionVersion, right.ConditionVersion, StringComparison.Ordinal);

    private static string NormalizeAssignmentId(string assignmentId) =>
        assignmentId.Trim().TrimEnd('/');

    private static string GetRoleId(string roleDefinitionId) =>
        roleDefinitionId.TrimEnd('/').Split('/').Last();

    private static string GetAssignmentName(string assignmentId) =>
        assignmentId.TrimEnd('/').Split('/').Last();

    private static PlanItem AuthorizationItem(
        RoleAssignmentSummary assignment,
        string action,
        string status,
        string? targetScope,
        string? assignmentId,
        string detail) =>
        new()
        {
            ObjectType = "Authorization",
            Name = assignmentId ?? assignment.Id,
            Action = action,
            Status = status,
            Detail = detail,
            TargetScope = targetScope,
            AssignmentId = assignmentId,
            PrincipalId = assignment.PrincipalId,
            RoleDefinitionId = assignment.RoleDefinitionId,
            PrincipalType = assignment.PrincipalType,
            Condition = assignment.Condition,
            ConditionVersion = assignment.ConditionVersion,
        };

    private static IReadOnlyList<PlanItem> Order(IEnumerable<PlanItem> plan) =>
        plan.OrderBy(item => Priority(item))
            .ThenBy(item => item.ObjectType, StringComparer.Ordinal)
            .ThenBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static int Priority(PlanItem item) => (item.ObjectType, item.Action, item.TargetScope?.Contains("/secrets/", StringComparison.OrdinalIgnoreCase) == true
        || item.TargetScope?.Contains("/keys/", StringComparison.OrdinalIgnoreCase) == true) switch
        {
            ("Authorization", "CreateRoleAssignment", false) => 10,
            (_, "CreateObject" or "ReconcileObject", _) => 20,
            ("Authorization", "CreateRoleAssignment", true) => 30,
            ("Authorization", "DeleteRoleAssignment", true) => 40,
            (_, "DeleteObject", _) => 50,
            ("Authorization", "DeleteRoleAssignment", false) => 60,
            _ => 70,
        };

    /// <summary>Builds the stable pair-state key shared by baselines and pending mutation intents.</summary>
    internal static string GetObjectKey(string objectType, string name) => $"{objectType}/{name}";

    private static PlanItem Item(
        string objectType,
        string name,
        string action,
        string status,
        string? sourceVersion,
        string? targetVersion,
        string detail) =>
        new()
        {
            ObjectType = objectType,
            Name = name,
            Action = action,
            Status = status,
            SourceVersion = sourceVersion,
            TargetVersion = targetVersion,
            Detail = detail,
        };
}
