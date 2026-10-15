using Azure;
using Microsoft.Extensions.Logging;

namespace KeyVaultSync.Runner;

/// <summary>Defines stable, value-free diagnostic codes and administrator remediation for exported telemetry.</summary>
/// <remarks>
/// Durable run records remain authoritative and can contain private operational identifiers. These helpers emit
/// bounded categories, counts, and recommended actions so exported logs can be triaged without object values,
/// credentials, HMAC material, principal IDs, or full ARM scopes.
/// </remarks>
internal static class AdminDiagnostics
{
    /// <summary>Identifies one classified inventory warning.</summary>
    public static readonly EventId InventoryWarningEventId = new(5000, "InventoryWarning");
    /// <summary>Identifies an aggregate group of plan items sharing one terminal or proposed status.</summary>
    public static readonly EventId PlanOutcomeSummaryEventId = new(5001, "PlanOutcomeSummary");
    /// <summary>Identifies one RBAC mutation or verification outcome.</summary>
    public static readonly EventId RbacOutcomeEventId = new(5002, "RbacOutcome");
    /// <summary>Identifies the final bounded diagnostic summary for one pair attempt.</summary>
    public static readonly EventId PairDiagnosticSummaryEventId = new(5003, "PairDiagnosticSummary");
    /// <summary>Identifies a bounded source/target mapping decision.</summary>
    public static readonly EventId DiscoveryDecisionEventId = new(5004, "DiscoveryDecision");
    /// <summary>Identifies one object mutation, verification, or safety outcome.</summary>
    public static readonly EventId ObjectOutcomeEventId = new(5005, "ObjectOutcome");
    /// <summary>Identifies the final bounded diagnostic summary for one run.</summary>
    public static readonly EventId RunDiagnosticSummaryEventId = new(5006, "RunDiagnosticSummary");
    /// <summary>Identifies a storage, configuration, discovery, or orchestration failure category.</summary>
    public static readonly EventId SystemFailureEventId = new(5007, "SystemFailure");
    /// <summary>Identifies one bounded run or pair lifecycle transition.</summary>
    public static readonly EventId LifecycleEventId = new(5008, "LifecycleTransition");

    /// <summary>Classifies one persisted inventory warning without copying its identifier-bearing text to telemetry.</summary>
    public static AdminDiagnostic ClassifyInventoryWarning(string warning)
    {
        if (warning.StartsWith("Key head version could not be determined", StringComparison.Ordinal))
        {
            return new("KVS-INV-KEY-HEAD", "Key head version could not be determined.",
                "Inspect the affected key versions and current key metadata before the next run.");
        }

        if (warning.StartsWith("Certificate metadata/backing references could not be read", StringComparison.Ordinal))
        {
            return new("KVS-INV-CERTIFICATE-METADATA", "Certificate metadata or backing references could not be read.",
                "Verify certificate read permissions and inspect the affected certificate's backing secret and key references.");
        }

        if (warning.StartsWith("Certificate head version could not be determined", StringComparison.Ordinal))
        {
            return new("KVS-INV-CERTIFICATE-HEAD", "Certificate head version could not be determined.",
                "Verify certificate read permissions and inspect the affected certificate's current version.");
        }

        if (warning.StartsWith("Deleted-secret inventory is incomplete", StringComparison.Ordinal))
        {
            return new("KVS-INV-DELETED-SECRETS", "Soft-deleted secret inventory is incomplete.",
                "Verify deleted-secret list permission and network reachability; do not use this run as deletion evidence.");
        }

        if (warning.StartsWith("Deleted-key inventory is incomplete", StringComparison.Ordinal))
        {
            return new("KVS-INV-DELETED-KEYS", "Soft-deleted key inventory is incomplete.",
                "Verify deleted-key list permission and network reachability; do not use this run as deletion evidence.");
        }

        if (warning.StartsWith("Deleted-certificate inventory is incomplete", StringComparison.Ordinal))
        {
            return new("KVS-INV-DELETED-CERTIFICATES", "Soft-deleted certificate inventory is incomplete.",
                "Verify deleted-certificate list permission and network reachability; do not use this run as deletion evidence.");
        }

        if (warning.StartsWith("Object role-assignment inventory is incomplete", StringComparison.Ordinal))
        {
            return new("KVS-INV-OBJECT-RBAC", "Object-scope role-assignment inventory is incomplete.",
                "Verify ARM Reader access and deny assignments at the affected vault or child scope.");
        }

        if (warning.StartsWith("Role-assignment inventory is incomplete", StringComparison.Ordinal))
        {
            return new("KVS-INV-VAULT-RBAC", "Vault role-assignment inventory is incomplete.",
                "Verify ARM Reader access and deny assignments at the affected vault and ancestor scopes.");
        }

        return new("KVS-INV-UNKNOWN", "Inventory completed with an unclassified warning.",
            "Inspect the private durable run record for the exact warning and resolve it before relying on deletion evidence.");
    }

    /// <summary>Maps one plan status to a stable diagnostic and administrator action.</summary>
    public static AdminDiagnostic ClassifyPlanStatus(string status) =>
        status switch
        {
            "INVENTORY_WARNING" => new("KVS-INV-PARTIAL",
                "Inventory contains a warning that prevents complete-scan evidence.",
                "Inspect the private run record, resolve the warning, and allow a new complete inventory."),
            "BLOCKED_INCOMPLETE_INVENTORY" => new("KVS-PLAN-INCOMPLETE-INVENTORY",
                "Object mutation was blocked because this object's inventory, or a vault-level object listing, was incomplete.",
                "Resolve the warning for this object name, or the vault-level listing warning, then allow a later run to re-plan the pair."),
            "BLOCKED_HMAC_KEY_NOT_CONFIGURED" => new("KVS-PLAN-HMAC-MISSING",
                "Object mutation was blocked because protected HMAC material is unavailable.",
                "Restore the environment's original protected HMAC key; never generate a replacement for committed baselines."),
            "BLOCKED_UNRESOLVED_INTENT" => new("KVS-PLAN-UNRESOLVED-INTENT",
                "A prior mutation has an unresolved durable intent.",
                "Use the approved recovery process to inspect the exact target state; do not automatically retry or clear the intent."),
            "BLOCKED_SOFT_DELETED_TARGET" => new("KVS-PLAN-SOFT-DELETED-NAME",
                "The target name is occupied by a soft-deleted object.",
                "Review the soft-deleted object and follow an explicitly approved recovery process; KeyVaultSync never purges it."),
            "BLOCKED_SOURCE_VERSION_DISABLED" => new("KVS-PLAN-SOURCE-DISABLED",
                "The source object's current version is disabled, so it was not replicated.",
                "Enable the current version, or make an enabled version current, if this object should be synchronized; older versions are never used."),
            "BLOCKED_CERTIFICATE_REISSUANCE_REQUIRED" => new("KVS-PLAN-CERTIFICATE-NONEXPORTABLE",
                "Certificate private material is not exportable.",
                "Reissue or externally import the certificate and private key into the target vault."),
            "BLOCKED_TARGET_KEY_PROVISIONING_REQUIRED" => new("KVS-PLAN-KEY-PROVISIONING",
                "A standalone key cannot be copied and the target key is absent.",
                "Independently generate or externally import the target key before key-scope RBAC can converge."),
            "BLOCKED_KEY_MATERIAL_EQUIVALENCE_UNVERIFIABLE" => new("KVS-PLAN-KEY-EQUIVALENCE",
                "Private or symmetric key equivalence cannot be verified.",
                "Treat key material synchronization as an external process; only eligible key-scope RBAC can converge."),
            "BLOCKED_DELETE_CIRCUIT_BREAKER" => new("KVS-PLAN-DELETE-CIRCUIT",
                "Bulk deletion was stopped by the deletion circuit breaker.",
                "Review the exact deletion plan hash and issue an approved one-use authorization only if every deletion is expected."),
            "BLOCKED_INCOMPATIBLE_BASELINE" => new("KVS-PLAN-INCOMPATIBLE-BASELINE",
                "The committed baseline is absent or incompatible with the active signature domain or HMAC key version.",
                "Use explicit administrative recovery; never silently adopt the target or replace the HMAC key."),
            "BLOCKED_AUTHORIZATION_INVENTORY_INCOMPLETE" => new("KVS-PLAN-AUTH-INVENTORY",
                "RBAC reconciliation was blocked because authorization inventory was incomplete.",
                "Restore complete ARM role-assignment reads for source and target scopes, then run discovery and inventory again."),
            "BLOCKED_SYNC_IDENTITY_UNKNOWN" or "RBAC_DELETE_BLOCKED_SYNC_IDENTITY_UNKNOWN" => new("KVS-RBAC-SYNC-IDENTITY-MISSING",
                "RBAC cleanup was blocked because the runtime identity object ID is not configured.",
                "Set KEYVAULTSYNC_PRINCIPAL_ID to the runtime managed identity object ID before allowing target-only assignment deletion."),
            "BLOCKED_DEPENDENCY_FAILED" => new("KVS-PLAN-DEPENDENCY-FAILED",
                "Object-scope RBAC was blocked because its object dependency did not complete safely.",
                "Resolve the related object outcome first; child-scope RBAC will be replanned on a later run."),
            "CONFLICT_UNMANAGED_TARGET_EXISTS" => new("KVS-PLAN-UNMANAGED-TARGET",
                "An existing target has no compatible managed baseline.",
                "Do not adopt or overwrite it automatically; investigate ownership and use an approved recovery decision."),
            "CONFLICT_UNMANAGED_TARGET_ONLY" => new("KVS-PLAN-UNMANAGED-TARGET-ONLY",
                "A target-only object is not owned by KeyVaultSync.",
                "Confirm ownership; KeyVaultSync will not delete an unmanaged target-only object."),
            "CONFLICT_MANAGED_TARGET_MISSING" => new("KVS-PLAN-MANAGED-TARGET-MISSING",
                "A previously managed target object is missing.",
                "Investigate deletion or vault recovery and use explicit state recovery; do not recreate from a stale assumption."),
            "CONFLICT_TARGET_APPEARED" => new("KVS-OBJECT-TARGET-APPEARED",
                "A target object appeared after planning and before mutation.",
                "Identify the concurrent writer and re-establish the operational single-writer boundary before a later run."),
            "CONFLICT_EXTERNALLY_MODIFIED" => new("KVS-PLAN-EXTERNAL-MODIFICATION",
                "The live target no longer matches its committed baseline.",
                "Identify the external writer and resolve ownership; do not force overwrite or silently rebaseline."),
            "STALE_PLAN_SOURCE_VERSION_UNAVAILABLE" => new("KVS-OBJECT-STALE-SOURCE",
                "The source object was deleted or became unreadable between planning and execution.",
                "Inspect source lifecycle activity and allow a later run to create a fresh plan."),
            "READ_FAILED_BEFORE_MUTATION" => new("KVS-OBJECT-READ-FAILED",
                "The source or target object could not be read before mutation, so only this object was skipped and nothing was written.",
                "Check the reason in the detail: a disabled current version, missing data-plane read permission, or an invalid certificate payload is the usual cause. A later run retries automatically."),
            "WRITE_FAILED_DEFINITIVELY" => new("KVS-OBJECT-WRITE-DEFINITIVE",
                "Azure definitively rejected the object write before a successful outcome was possible.",
                "Inspect the HTTP status and error code, correct permissions, policy, input, or network configuration, then allow a fresh plan."),
            "DELETE_FAILED_DEFINITIVELY" => new("KVS-OBJECT-DELETE-DEFINITIVE",
                "Azure definitively rejected the soft-delete request.",
                "Inspect the HTTP status and error code, correct target delete authorization or policy, then allow a fresh plan."),
            "AMBIGUOUS_OUTCOME_UNRESOLVED_INTENT" => new("KVS-OBJECT-AMBIGUOUS",
                "A mutation or exact verification outcome is ambiguous and durable intent remains.",
                "Do not retry automatically. Inspect the exact target state through the approved recovery process and resolve the intent explicitly."),
            "ROLE_DEFINITION_NOT_AVAILABLE" => new("KVS-RBAC-ROLE-DEFINITION",
                "A source assignment references a role definition that is unavailable or outside the supported Key Vault allowlist.",
                "Confirm the assignment uses a supported Key Vault data-plane role and that its role definition is visible."),
            "RBAC_ACTION_FAILED" => new("KVS-RBAC-FAILED",
                "An ARM role-assignment mutation failed.",
                "Inspect the HTTP status and error code, then verify target-scope role-assignment authority and deny assignments."),
            "RBAC_ACTION_FAILED_VERIFICATION" => new("KVS-RBAC-VERIFY",
                "ARM did not converge to the expected assignment state during bounded verification.",
                "Read the exact assignment after propagation and compare its scope, principal, role, and condition."),
            "RBAC_ACTION_FAILED_INVALID_PLAN" => new("KVS-RBAC-INVALID-PLAN",
                "An RBAC action was missing a required scope, assignment, principal, or role field.",
                "Inspect the private run record and planner inputs; do not construct or execute the assignment manually from incomplete data."),
            "RBAC_ACTION_BLOCKED_ROLE_NOT_ALLOWED" => new("KVS-RBAC-ROLE-NOT-ALLOWED",
                "The planned role is outside the Key Vault-specific role allowlist.",
                "Use a supported Key Vault data-plane role; broader Azure roles are intentionally not replicated."),
            "RBAC_DELETE_SKIPPED_SYNC_IDENTITY" or "SKIPPED_SYNC_IDENTITY_SELF_ASSIGNMENT" => new("KVS-RBAC-SELF-PROTECTION",
                "The runtime identity's own assignment was retained to prevent self-revocation.",
                "No action is normally required; manage the runtime identity assignment only through an approved deployment procedure."),
            "READY_CREATE_IF_TARGET_STAYS_EMPTY" => new("KVS-PLAN-READY-CREATE",
                "The object is eligible for guarded creation if the target remains absent.",
                "No action is required unless execution reports a later conflict or failure."),
            "VERIFY_SIGNATURES_THEN_RECONCILE" => new("KVS-PLAN-READY-RECONCILE",
                "The managed object is eligible for signature verification and reconciliation.",
                "No action is required unless execution reports a conflict, failure, or unresolved intent."),
            "VERIFY_SIGNATURE_THEN_SOFT_DELETE" => new("KVS-PLAN-READY-DELETE",
                "The managed target-only object is eligible for signature verification and soft deletion.",
                "Review deletion approvals when required; KeyVaultSync never purges objects."),
            "READY_CREATE_ROLE_ASSIGNMENT" => new("KVS-RBAC-READY-CREATE",
                "A supported direct role assignment is ready for target creation.",
                "No action is required unless ARM mutation or verification fails."),
            "READY_DELETE_ROLE_ASSIGNMENT" => new("KVS-RBAC-READY-DELETE",
                "A managed target-only role assignment is ready for deletion.",
                "No action is required unless ARM mutation or verification fails."),
            "IN_SYNC_SIGNATURE_VERIFIED" => new("KVS-OBJECT-IN-SYNC",
                "The managed source and target object signatures remain in sync.",
                "No administrator action is required."),
            "OBJECT_REPLICATED_AND_VERIFIED" => new("KVS-OBJECT-REPLICATED",
                "The exact target object version was written, read back, verified, and committed.",
                "No administrator action is required."),
            "OBJECT_SOFT_DELETED_AND_VERIFIED" => new("KVS-OBJECT-DELETED",
                "The managed target object was soft-deleted and verified absent from active inventory.",
                "No administrator action is required; KeyVaultSync does not purge."),
            "RBAC_ASSIGNMENT_IN_SYNC" => new("KVS-RBAC-IN-SYNC",
                "The supported direct role assignment is already in sync.",
                "No administrator action is required."),
            "RBAC_ASSIGNMENT_CREATED_AND_VERIFIED" => new("KVS-RBAC-CREATED",
                "The target role assignment was created and verified.",
                "No administrator action is required."),
            "RBAC_ASSIGNMENT_DELETED_AND_VERIFIED" => new("KVS-RBAC-DELETED",
                "The target role assignment was deleted and verified absent.",
                "No administrator action is required."),
            "RBAC_CREATED_AND_VERIFIED" => new("KVS-RBAC-CREATED",
                "The target role assignment was created and verified by a legacy runner.",
                "No administrator action is required."),
            "RBAC_DELETED_AND_VERIFIED" => new("KVS-RBAC-DELETED",
                "The target role assignment was deleted and verified absent by a legacy runner.",
                "No administrator action is required."),
            "RBAC_ALREADY_ABSENT" => new("KVS-RBAC-ALREADY-ABSENT",
                "The target role assignment was already absent.",
                "No administrator action is required."),
            "RBAC_ASSIGNMENT_INTENT_MATCH" => new("KVS-RBAC-INTENT-MATCH",
                "A legacy RBAC intent record matches the observed assignment.",
                "Review legacy state only if migration or cleanup remains pending."),
            "ACCESS_POLICY_INTENT_MATCH" => new("KVS-ACCESS-POLICY-INTENT-MATCH",
                "A legacy access-policy intent record matches observed state.",
                "Access-policy synchronization is not implemented; preserve this evidence for explicit migration or recovery."),
            _ when status.StartsWith("BLOCKED", StringComparison.Ordinal) => new("KVS-PLAN-BLOCKED",
                "A planned action was blocked by a safety precondition.",
                "Inspect the private run record's status and detail, resolve the precondition, and allow a new plan."),
            _ when status.StartsWith("CONFLICT", StringComparison.Ordinal) => new("KVS-PLAN-CONFLICT",
                "A planned action conflicts with observed target state.",
                "Investigate ownership and target state; do not force adoption, overwrite, or deletion."),
            _ when status.Contains("FAILED", StringComparison.Ordinal) => new("KVS-ACTION-FAILED",
                "An execution or verification action failed.",
                "Inspect the structured HTTP/error fields and private run record before retrying."),
            _ => new("KVS-PLAN-UNKNOWN-STATUS", "The runner emitted a plan status not recognized by this diagnostic catalog.",
                "Preserve the private run record and update the analyzer/catalog before interpreting or retrying this item."),
        };

    /// <summary>Maps a discovery decision to a stable diagnostic and remediation.</summary>
    public static AdminDiagnostic ClassifyDiscoveryDecision(string decision) =>
        decision switch
        {
            "Enabled" => new("KVS-DISCOVERY-ENABLED", "A source/target mapping passed all eligibility checks.",
                "No administrator action is required."),
            "SourceDisabled" => new("KVS-DISCOVERY-SOURCE-DISABLED", "The source vault deliberately disables synchronization.",
                "Remove or change KeyVaultSyncDisabled=true on the source only when synchronization should resume."),
            "TargetDisabled" => new("KVS-DISCOVERY-TARGET-DISABLED", "The target vault deliberately disables synchronization.",
                "Remove or change KeyVaultSyncDisabled=true on the target only when synchronization should resume."),
            "InvalidSourceId" => new("KVS-DISCOVERY-INVALID-SOURCE-ID", "The target mapping tag is not a valid Key Vault ARM resource ID.",
                "Set sync-source-keyvault-id to the exact versionless ARM ID of the intended source vault."),
            "TargetUnreadable" => new("KVS-DISCOVERY-TARGET-UNREADABLE", "The target vault could not be read for eligibility validation.",
                "Verify ARM Reader access, network reachability, resource existence, and subscription configuration."),
            "SourceUnreadable" => new("KVS-DISCOVERY-SOURCE-UNREADABLE", "The mapped source vault could not be read for eligibility validation.",
                "Verify the source exists and the runtime can read it through ARM, including cross-subscription authorization."),
            "SourceMapsToSelf" => new("KVS-DISCOVERY-SELF-MAPPING", "A target maps to itself as its source.",
                "Correct or remove the target's sync-source-keyvault-id tag."),
            "ChainedOrCyclicMapping" => new("KVS-DISCOVERY-CHAIN", "A vault participates in a chained or cyclic mapping.",
                "Use direct source-to-target mappings only; a vault cannot be both source and target."),
            "CrossTenantOrUnknownTenant" => new("KVS-DISCOVERY-TENANT", "The pair has different or unreadable tenant IDs.",
                "Use source and target vaults in the same Microsoft Entra tenant and restore readable ARM metadata."),
            "UnsupportedAuthorizationModel" => new("KVS-DISCOVERY-AUTH-MODEL", "One or both vaults do not use Azure RBAC authorization.",
                "Use Azure RBAC authorization for both vaults; access-policy support is not implemented."),
            _ => new("KVS-DISCOVERY-UNKNOWN", "Discovery emitted an unrecognized mapping decision.",
                "Inspect the private run record and update the diagnostic catalog before changing the mapping."),
        };

    /// <summary>Maps a pair terminal status to a stable diagnostic and remediation.</summary>
    public static AdminDiagnostic ClassifyPairStatus(string status) =>
        status switch
        {
            "SyncCompleted" => new("KVS-PAIR-COMPLETE", "The pair completed with no unapplied work.",
                "No administrator action is required."),
            "SyncCompletedWithUnappliedWork" => new("KVS-PAIR-UNAPPLIED", "The pair completed but retained blocked, conflicting, failed, or unresolved work.",
                "Follow the pair's plan diagnostic codes and inspect the private run record."),
            "PartialInventory" => new("KVS-PAIR-PARTIAL-INVENTORY", "The pair could not establish complete inventory evidence.",
                "Resolve source and target inventory diagnostics before a later run."),
            "SkippedPairAlreadyLocked" => new("KVS-PAIR-LOCKED", "Another runner held the pair's Blob lease.",
                "Confirm only the intended single active deployment is running; otherwise wait for the legitimate lease owner to finish."),
            "ExecutionBlockedPlanningIncomplete" => new("KVS-PAIR-PLANNING-BARRIER", "Execution was blocked because another admitted pair did not finish planning safely.",
                "Resolve the failed planning pair; no pair mutation should start until all admitted pairs are planned."),
            "Cancelled" => new("KVS-PAIR-CANCELLED", "The host cancelled pair processing.",
                "Inspect host shutdown, timeout, deployment, or scale events and any pending mutation intent before another run."),
            "Failed" => new("KVS-PAIR-FAILED", "Pair scanning or execution failed.",
                "Inspect the associated exception category and private run record before retrying."),
            "Running" or "Planned" or "Executing" => new("KVS-PAIR-INCOMPLETE", "The durable record contains a nonterminal pair status.",
                "Determine whether the process was interrupted and inspect lease state and pending intents before another run."),
            _ => new("KVS-PAIR-UNKNOWN", "The runner emitted an unrecognized pair status.",
                "Preserve the run record and update the diagnostic catalog before interpreting the outcome."),
        };

    /// <summary>Maps a run terminal status to a stable diagnostic and remediation.</summary>
    public static AdminDiagnostic ClassifyRunStatus(string status) =>
        status switch
        {
            "Complete" => new("KVS-RUN-COMPLETE", "The run completed and every admitted pair completed without unapplied work.",
                "No administrator action is required."),
            "NoConfiguredPairs" => new("KVS-RUN-NO-PAIRS", "Discovery found no enabled source/target mappings.",
                "No action is required for an intentional empty environment; otherwise validate target mapping and disabled tags."),
            "Partial" => new("KVS-RUN-PARTIAL", "The run completed with mapping issues or a non-complete pair.",
                "Follow discovery, pair, and plan diagnostic codes and inspect the durable run record."),
            "Cancelled" => new("KVS-RUN-CANCELLED", "The Function host cancelled the run.",
                "Inspect host shutdown, timeout, deployment, or scale events and any pending intents before another run."),
            "Failed" => new("KVS-RUN-FAILED", "Discovery or orchestration failed.",
                "Inspect the structured failure stage and exception type, then the durable run record if it was available."),
            "Running" => new("KVS-RUN-INCOMPLETE", "The durable record contains a nonterminal run status.",
                "Determine whether the Function process was interrupted and inspect all pair states and pending intents."),
            _ => new("KVS-RUN-UNKNOWN", "The runner emitted an unrecognized run status.",
                "Preserve available telemetry and update the diagnostic catalog before interpreting the outcome."),
        };

    /// <summary>Maps an infrastructure or orchestration stage to stable failure guidance.</summary>
    public static AdminDiagnostic ClassifySystemFailure(string stage) =>
        stage switch
        {
            "HmacConfiguration" => new("KVS-CONFIG-HMAC-INVALID", "Protected HMAC configuration is malformed.",
                "Restore a valid Base64-encoded 32-byte key and nonempty version label from protected configuration; never print or replace an established key."),
            "StorageInitialization" => new("KVS-STORAGE-INITIALIZE", "Blob container initialization failed.",
                "Verify storage URI, managed-identity authorization, public/private network reachability, DNS, and role propagation."),
            "RunRecordPersistence" => new("KVS-STORAGE-RUN-RECORD", "The durable run progress record could not be persisted.",
                "Restore Blob write access and reachability; telemetry alone is not authoritative run history."),
            "PairStatePersistence" => new("KVS-STORAGE-PAIR-STATE", "Lease- and ETag-protected pair state could not be persisted.",
                "Stop dependent mutation work and verify the Blob lease, ETag, authorization, and storage reachability."),
            "PairLeaseRenewal" => new("KVS-STORAGE-LEASE-RENEW", "The pair-state Blob lease could not be renewed.",
                "Treat the pair as failed, inspect pending intents, and restore storage reachability before a later run."),
            "PairLeaseRelease" => new("KVS-STORAGE-LEASE-RELEASE", "The pair-state Blob lease could not be released.",
                "Wait for the finite lease to expire and verify storage reachability; do not bypass the lease."),
            "PairScan" => new("KVS-PAIR-SCAN-FAILED", "Pair inventory or planning failed.",
                "Inspect the exception type and preceding stage diagnostics; no mutation should be inferred from a scan failure."),
            "PairExecution" => new("KVS-PAIR-EXECUTION-FAILED", "Pair execution failed outside a classified item outcome.",
                "Inspect pending intents, state persistence, and the private run record before another run."),
            "RunOrchestration" => new("KVS-RUN-ORCHESTRATION-FAILED", "Discovery or run orchestration failed.",
                "Inspect ARM, Key Vault, Blob, credential, and network diagnostics and any available durable progress record."),
            _ => new("KVS-SYSTEM-FAILURE", "An unclassified runtime stage failed.",
                "Preserve telemetry and the private run record, identify the failing stage, and update the diagnostic catalog."),
        };

    /// <summary>Maps an ARM RBAC failure to a stable diagnostic and remediation.</summary>
    public static AdminDiagnostic ClassifyRbacFailure(int httpStatus, string? errorCode)
    {
        if (httpStatus == 403)
        {
            return new("KVS-RBAC-403", "Azure denied a role-assignment mutation.",
                "Verify the runtime identity has effective Key Vault Data Access Administrator at the target scope, allow propagation, and check deny assignments or conditions.");
        }

        if (httpStatus == 429)
        {
            return new("KVS-RBAC-429", "Azure throttled a role-assignment request.",
                "Review ARM throttling and retry only in a later scheduled run after the outcome is conclusively known.");
        }

        return new(
            string.IsNullOrWhiteSpace(errorCode) ? $"KVS-RBAC-HTTP-{httpStatus}" : $"KVS-RBAC-{NormalizeCode(errorCode)}",
            "An ARM role-assignment request failed.",
            "Inspect the HTTP status, ARM error code, and private run record; verify target-scope authorization before retrying.");
    }

    /// <summary>Returns the bounded authorization scope category used in telemetry.</summary>
    public static string GetAuthorizationScopeKind(string? scope)
    {
        if (scope?.Contains("/secrets/", StringComparison.OrdinalIgnoreCase) == true)
        {
            return "Secret";
        }

        if (scope?.Contains("/keys/", StringComparison.OrdinalIgnoreCase) == true)
        {
            return "Key";
        }

        return "Vault";
    }

    /// <summary>Returns the bounded operator priority for a diagnostic code.</summary>
    internal static string GetPriority(string code) =>
        code switch
        {
            "KVS-RBAC-403" or "KVS-OBJECT-AMBIGUOUS" or "KVS-PLAN-UNRESOLVED-INTENT"
                or "KVS-STORAGE-PAIR-STATE" or "KVS-STORAGE-LEASE-RENEW" => "Critical",
            _ when code.StartsWith("KVS-INV-", StringComparison.Ordinal)
                || code.StartsWith("KVS-CONFIG-", StringComparison.Ordinal)
                || code.StartsWith("KVS-STORAGE-", StringComparison.Ordinal)
                || code.EndsWith("-FAILED", StringComparison.Ordinal)
                || code.Contains("UNKNOWN", StringComparison.Ordinal) => "High",
            _ when code.StartsWith("KVS-PLAN-", StringComparison.Ordinal)
                || code.StartsWith("KVS-RBAC-", StringComparison.Ordinal) => "Medium",
            _ => "None",
        };

    /// <summary>Returns whether the diagnostic requires review or is an observed no-action outcome.</summary>
    internal static string GetActionDecision(AdminDiagnostic diagnostic) =>
        GetPriority(diagnostic.Code) == "None" ? "NoActionRequired" : "AdminReviewRequired";

    /// <summary>Returns confidence in the catalog inference without claiming proof of live Azure state.</summary>
    internal static string GetConfidence(string code) =>
        code.Contains("UNKNOWN", StringComparison.Ordinal) ? "Low" : "High";

    /// <summary>Emits one bounded lifecycle transition for timeline reconstruction.</summary>
    public static void LogLifecycle(
        ILogger logger,
        string stage,
        string outcome,
        string actionDecision = "Continue")
    {
        logger.LogInformation(
            LifecycleEventId,
            "Lifecycle diagnostic {DiagnosticCode}. Stage {DiagnosticStage}; outcome {DiagnosticOutcome}; evidence type {EvidenceType}; action decision {ActionDecision}; confidence {Confidence}.",
            "KVS-LIFECYCLE",
            stage,
            outcome,
            "Evidence",
            actionDecision,
            "High");
    }

    /// <summary>Emits one bounded event per inventory warning, preserving exact text only in the private run record.</summary>
    public static void LogInventoryWarnings(ILogger logger, VaultInventory inventory, string vaultRole)
    {
        for (var index = 0; index < inventory.Warnings.Count; index++)
        {
            var diagnostic = ClassifyInventoryWarning(inventory.Warnings[index]);
            logger.LogWarning(
                InventoryWarningEventId,
                "Inventory diagnostic {DiagnosticCode}. Stage {DiagnosticStage}; outcome {DiagnosticOutcome}; vault role {VaultRole}; warning {WarningNumber} of {WarningCount}; priority {AdminPriority}; evidence type {EvidenceType}; action decision {ActionDecision}; confidence {Confidence}; summary {DiagnosticSummary}; administrator action {AdminAction}.",
                diagnostic.Code,
                "Inventory",
                "Warning",
                vaultRole,
                index + 1,
                inventory.Warnings.Count,
                GetPriority(diagnostic.Code),
                "Evidence",
                GetActionDecision(diagnostic),
                GetConfidence(diagnostic.Code),
                diagnostic.Summary,
                diagnostic.AdminAction);
        }
    }

    /// <summary>Emits a bounded infrastructure failure without exception messages or resource identifiers.</summary>
    public static void LogSystemFailure(ILogger logger, string stage, Exception exception)
    {
        var diagnostic = ClassifySystemFailure(stage);
        var requestFailure = exception as RequestFailedException;
        logger.LogError(
            SystemFailureEventId,
            "System diagnostic {DiagnosticCode}. Stage {DiagnosticStage}; outcome {DiagnosticOutcome}; exception type {ExceptionType}; HTTP {HttpStatus}; error {ErrorCode}; priority {AdminPriority}; evidence type {EvidenceType}; action decision {ActionDecision}; confidence {Confidence}; summary {DiagnosticSummary}; administrator action {AdminAction}.",
            diagnostic.Code,
            stage,
            "Failed",
            exception.GetType().Name,
            requestFailure?.Status,
            requestFailure?.ErrorCode ?? "unknown",
            GetPriority(diagnostic.Code),
            "Evidence",
            GetActionDecision(diagnostic),
            GetConfidence(diagnostic.Code),
            diagnostic.Summary,
            diagnostic.AdminAction);
    }

    /// <summary>Emits every grouped plan status so large plans remain diagnosable without one log per object.</summary>
    public static void LogPlanOutcomeGroups(ILogger logger, IReadOnlyList<PlanItem> plan, string phase)
    {
        foreach (var group in plan
                     .GroupBy(item => new { item.Status, item.ObjectType, item.Action })
                     .OrderBy(item => item.Key.Status, StringComparer.Ordinal)
                     .ThenBy(item => item.Key.ObjectType, StringComparer.Ordinal)
                     .ThenBy(item => item.Key.Action, StringComparer.Ordinal))
        {
            var diagnostic = ClassifyPlanStatus(group.Key.Status);
            logger.Log(
                RequiresAdminAttention(group.Key.Status) ? LogLevel.Warning : LogLevel.Information,
                PlanOutcomeSummaryEventId,
                "Plan diagnostic {DiagnosticCode}. Stage {DiagnosticStage}; outcome {DiagnosticOutcome}; status {PlanStatus}; object type {ObjectType}; action {ObjectAction}; count {ItemCount}; priority {AdminPriority}; evidence type {EvidenceType}; action decision {ActionDecision}; confidence {Confidence}; summary {DiagnosticSummary}; administrator action {AdminAction}.",
                diagnostic.Code,
                phase,
                group.Key.Status,
                group.Key.Status,
                group.Key.ObjectType,
                group.Key.Action,
                group.Count(),
                GetPriority(diagnostic.Code),
                "Evidence",
                GetActionDecision(diagnostic),
                GetConfidence(diagnostic.Code),
                diagnostic.Summary,
                diagnostic.AdminAction);
        }
    }

    /// <summary>Returns whether a plan status requires administrator attention.</summary>
    internal static bool RequiresAdminAttention(string status) =>
        status is not ("READY_CREATE_IF_TARGET_STAYS_EMPTY"
            or "VERIFY_SIGNATURES_THEN_RECONCILE"
            or "VERIFY_SIGNATURE_THEN_SOFT_DELETE"
            or "READY_CREATE_ROLE_ASSIGNMENT"
            or "READY_DELETE_ROLE_ASSIGNMENT"
            or "IN_SYNC_SIGNATURE_VERIFIED"
            or "OBJECT_REPLICATED_AND_VERIFIED"
            or "OBJECT_SOFT_DELETED_AND_VERIFIED"
            or "RBAC_ASSIGNMENT_IN_SYNC"
            or "RBAC_ASSIGNMENT_CREATED_AND_VERIFIED"
            or "RBAC_ASSIGNMENT_DELETED_AND_VERIFIED"
            or "RBAC_CREATED_AND_VERIFIED"
            or "RBAC_DELETED_AND_VERIFIED"
            or "RBAC_ALREADY_ABSENT"
            or "RBAC_ASSIGNMENT_INTENT_MATCH"
            or "ACCESS_POLICY_INTENT_MATCH"
            or "RBAC_DELETE_SKIPPED_SYNC_IDENTITY"
            or "SKIPPED_SYNC_IDENTITY_SELF_ASSIGNMENT");

    private static string NormalizeCode(string errorCode)
    {
        var characters = errorCode
            .Where(character => char.IsAsciiLetterOrDigit(character) || character == '-')
            .Select(char.ToUpperInvariant)
            .ToArray();
        return characters.Length == 0 ? "UNKNOWN" : new string(characters);
    }
}

/// <summary>One stable exported diagnostic category with value-free remediation guidance.</summary>
/// <param name="Code">Machine-readable code intended for KQL queries and the offline analyzer.</param>
/// <param name="Summary">Identifier-free administrator summary.</param>
/// <param name="AdminAction">Identifier-free next action; the private run record provides exact subjects.</param>
internal sealed record AdminDiagnostic(string Code, string Summary, string AdminAction);
