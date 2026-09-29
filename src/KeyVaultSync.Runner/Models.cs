namespace KeyVaultSync.Runner;

/// <summary>Well-known Azure resource tags that control KeyVaultSync pair admission.</summary>
internal static class KeyVaultSyncResourceTags
{
    /// <summary>Set this ARM tag to the case-insensitive value <c>true</c> to suppress a vault's pair.</summary>
    public const string SyncDisabled = "KeyVaultSyncDisabled";

    /// <summary>Set this tag on a target vault to the source vault ARM ID; multiple targets can reference one source.</summary>
    public const string SyncSourceKeyVaultId = "sync-source-keyvault-id";

    /// <summary>Returns whether the vault is explicitly excluded from synchronization.</summary>
    /// <param name="vault">The ARM metadata snapshot used for this discovery pass.</param>
    /// <returns>True only for a present tag whose trimmed value equals true, ignoring case; other values do not pause.</returns>
    /// <remarks>Tag-name matching follows the dictionary's comparer. ARM parsing supplies case-insensitive tag keys.</remarks>
    public static bool IsSyncDisabled(VaultResource vault)
    {
        return vault.Tags.TryGetValue(SyncDisabled, out var value)
            && string.Equals(value.Trim(), "true", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>An ARM discovery snapshot, not a data-plane client or proof that the vault is reachable.</summary>
internal sealed record VaultResource
{
    /// <summary>Gets the full ARM resource ID used for mapping, scope derivation, and pair identity.</summary>
    public required string Id { get; init; }
    /// <summary>Gets the vault's resource name, also used in diagnostics and the public-cloud endpoint.</summary>
    public required string Name { get; init; }
    /// <summary>Gets the ARM region string used by diagnostics and conservative native-restore planning.</summary>
    public required string Location { get; init; }
    /// <summary>Gets the containing resource-group name extracted from the ARM ID.</summary>
    public required string ResourceGroup { get; init; }
    /// <summary>Gets observed ARM tags, including the target mapping and pair-pause control.</summary>
    public required Dictionary<string, string> Tags { get; init; }
}

/// <summary>A directional source-to-target relationship admitted by discovery.</summary>
/// <param name="Source">Vault whose supported content is authoritative for this pair.</param>
/// <param name="Target">Existing destination vault; equal names or values alone do not establish object ownership.</param>
internal sealed record VaultPair(VaultResource Source, VaultResource Target)
{
    /// <summary>Gets the directional identity used for state addressing and HMAC domain binding.</summary>
    /// <remarks>Changing either endpoint changes the logical pair. Do not rename this identity as a cosmetic change.</remarks>
    public string PairId => $"{Source.Id}=>{Target.Id}";
}

/// <summary>Separates accepted pairs, intentional pauses, and mapping problems from the raw subscription inventory.</summary>
internal sealed record DiscoveryResult
{
    /// <summary>Gets the total listed subscription vaults before applying the source resource-group filter.</summary>
    public required int DiscoveredVaultCount { get; init; }
    /// <summary>Gets enabled, accepted pairs in discovery encounter order.</summary>
    public required IReadOnlyList<VaultPair> Pairs { get; init; }
    /// <summary>Gets the number of candidate pairs skipped when a source or resolved target pause tag was observed.</summary>
    public required int DisabledPairCount { get; init; }
    /// <summary>Gets distinct names recorded at pause decisions; short-circuiting means this is not both endpoints of every pair.</summary>
    public required IReadOnlyList<string> DisabledVaultNames { get; init; }
    /// <summary>Gets listed vaults neither selected as source candidates nor referenced by those candidates as targets.</summary>
    public required IReadOnlyList<string> UnmappedVaultNames { get; init; }
    /// <summary>Gets invalid/unreadable mapping diagnostics; intentional pauses do not count as mapping issues.</summary>
    public required IReadOnlyList<string> Issues { get; init; }
}

/// <summary>Value-free service metadata for an observed secret, key, or certificate version.</summary>
internal sealed record ObjectVersionSummary
{
    /// <summary>Gets the service version ID, or an empty string when the response did not supply it.</summary>
    public required string Version { get; init; }
    /// <summary>Gets the service creation timestamp when present; secret head inference uses dated versions only.</summary>
    public DateTimeOffset? CreatedOn { get; init; }
    /// <summary>Gets the service metadata-update timestamp when present; it is not used as a value checksum.</summary>
    public DateTimeOffset? UpdatedOn { get; init; }
    /// <summary>Gets the nullable service enabled setting; null means the response did not specify a value.</summary>
    public bool? Enabled { get; init; }
}

/// <summary>A secret's observed version and managed metadata, deliberately excluding its value.</summary>
/// <remarks>Metadata and version lists are separate service observations and are not an atomic snapshot.</remarks>
internal sealed record SecretSummary
{
    /// <summary>Gets the name used for source/target matching within the secret namespace.</summary>
    public required string Name { get; init; }
    /// <summary>Gets the inferred newest dated version, or an empty string when the head could not be determined.</summary>
    public required string CurrentVersion { get; init; }
    /// <summary>Gets observed version properties; collection order is not a latest-version guarantee.</summary>
    public required IReadOnlyList<ObjectVersionSummary> Versions { get; init; }
    /// <summary>Gets the observed enabled setting included in managed-metadata comparison.</summary>
    public bool? Enabled { get; init; }
    /// <summary>Gets the optional content type copied by supported secret operations.</summary>
    public string? ContentType { get; init; }
    /// <summary>Gets the optional service not-before timestamp, not a scheduling instruction for this runner.</summary>
    public DateTimeOffset? NotBefore { get; init; }
    /// <summary>Gets the optional service expiration timestamp included in metadata comparison.</summary>
    public DateTimeOffset? ExpiresOn { get; init; }
    /// <summary>Gets observed secret tags; these are data-plane metadata, not the vault's ARM discovery tags.</summary>
    public IReadOnlyDictionary<string, string> Tags { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    /// <summary>Gets a compatibility alias for CurrentVersion; it can be empty and performs no live head lookup.</summary>
    public string? LatestVersion => CurrentVersion;
}

/// <summary>Public key/version observations used for lifecycle planning, never private key export.</summary>
internal sealed record KeySummary
{
    /// <summary>Gets the key-namespace name used to compare source and target observations.</summary>
    public required string Name { get; init; }
    /// <summary>Gets the head returned by GetKey, with listing metadata as fallback; empty means unresolved.</summary>
    public required string CurrentVersion { get; init; }
    /// <summary>Gets observed version properties without assuming service enumeration order.</summary>
    public required IReadOnlyList<ObjectVersionSummary> Versions { get; init; }
    /// <summary>Gets the public key type/protection descriptor; matching types do not prove matching key material.</summary>
    public string? KeyType { get; init; }
    /// <summary>Gets a SHA-256 fingerprint of public JWK components only; private and symmetric key material is excluded.</summary>
    public string? PublicFingerprintSha256 { get; init; }
    /// <summary>Gets sorted declared key operations, not proof that any particular identity can perform them.</summary>
    public IReadOnlyList<string> KeyOperations { get; init; } = [];
    /// <summary>Gets the observed CurrentVersion alias without reading the service.</summary>
    public string? LatestVersion => CurrentVersion;
}

/// <summary>Public certificate observations and the references needed to treat its backing objects as one group.</summary>
internal sealed record CertificateSummary
{
    /// <summary>Gets the certificate name, conventionally shared by its backing key and secret.</summary>
    public required string Name { get; init; }
    /// <summary>Gets the observed head version, or an empty string when unavailable.</summary>
    public required string CurrentVersion { get; init; }
    /// <summary>Gets observed version properties; no private payloads are retained.</summary>
    public required IReadOnlyList<ObjectVersionSummary> Versions { get; init; }
    /// <summary>Gets the hex SHA-256 of public DER when read; it does not prove private-key equivalence or ownership.</summary>
    public string? ThumbprintSha256 { get; init; }
    /// <summary>Gets the backing secret identifier, or null when unavailable; its value is not fetched by inventory.</summary>
    public string? SecretId { get; init; }
    /// <summary>Gets the backing key identifier, or null when metadata could not establish the relationship.</summary>
    public string? KeyId { get; init; }
    /// <summary>Gets the observed CurrentVersion alias, which may be empty.</summary>
    public string? LatestVersion => CurrentVersion;
}

/// <summary>A legacy access-policy declaration, not an evaluated permission decision.</summary>
internal sealed record AccessPolicySummary
{
    /// <summary>Gets the declaration's Microsoft Entra tenant ID.</summary>
    public required string TenantId { get; init; }
    /// <summary>Gets the principal object ID within that tenant.</summary>
    public required string ObjectId { get; init; }
    /// <summary>Gets the optional application restriction on the policy.</summary>
    public string? ApplicationId { get; init; }
    /// <summary>Gets declared operation names grouped by Key Vault permission category.</summary>
    public required Dictionary<string, string[]> Permissions { get; init; }
}

/// <summary>An observed ARM role assignment whose role definition and principal membership are not expanded.</summary>
internal sealed record RoleAssignmentSummary
{
    /// <summary>Gets the full role-assignment ARM ID.</summary>
    public required string Id { get; init; }
    /// <summary>Gets the scope reported by ARM, with the queried scope used as fallback.</summary>
    public required string Scope { get; init; }
    /// <summary>Gets the assigned principal's object ID, not a resolved user/group membership list.</summary>
    public required string PrincipalId { get; init; }
    /// <summary>Gets the principal type when supplied by ARM.</summary>
    public string? PrincipalType { get; init; }
    /// <summary>Gets the role-definition ID; this model does not contain its actions or data actions.</summary>
    public required string RoleDefinitionId { get; init; }
    /// <summary>Gets the optional assignment condition as declared text; the runner does not evaluate it.</summary>
    public string? Condition { get; init; }
    /// <summary>Gets the condition version declared by ARM, when present.</summary>
    public string? ConditionVersion { get; init; }
    /// <summary>Gets the delegated managed-identity resource ID, when present.</summary>
    public string? DelegatedManagedIdentityResourceId { get; init; }
}

/// <summary>Authorization declarations for comparison and reporting, not proof of effective source/target access.</summary>
internal sealed record VaultAuthorizationSummary
{
    /// <summary>Gets whether ARM reports RBAC authorization enabled instead of the legacy access-policy model.</summary>
    public required bool UsesRbac { get; init; }
    /// <summary>Gets the vault's declared access policies, even if RBAC is the selected model.</summary>
    public required IReadOnlyList<AccessPolicySummary> AccessPolicies { get; init; }
    /// <summary>Gets role assignments returned from the queried vault/resource-group/subscription scopes.</summary>
    public required IReadOnlyList<RoleAssignmentSummary> RoleAssignments { get; init; }
    /// <summary>Gets scope-read failures that make authorization inventory incomplete.</summary>
    public required IReadOnlyList<string> Warnings { get; init; }
}

/// <summary>The complete shape of a vault observation; the Warnings collection determines whether it is considered partial.</summary>
/// <remarks>Lists exclude secret values and private payloads, but names, tags, and authorization metadata still need protection.</remarks>
internal sealed record VaultInventory
{
    /// <summary>Gets the full ARM ID that identifies the observed vault.</summary>
    public required string VaultId { get; init; }
    /// <summary>Gets the vault name used for human-readable reports and correlation.</summary>
    public required string VaultName { get; init; }
    /// <summary>Gets the ARM location, not the location of the process performing the scan.</summary>
    public required string Region { get; init; }
    /// <summary>Gets observed authorization declarations and any associated incompleteness warnings.</summary>
    public required VaultAuthorizationSummary Authorization { get; init; }
    /// <summary>Gets active secret-name observations, which may include certificate-managed backing secrets.</summary>
    public required IReadOnlyList<SecretSummary> Secrets { get; init; }
    /// <summary>Gets active key-name observations, including any certificate-managed backing keys.</summary>
    public required IReadOnlyList<KeySummary> Keys { get; init; }
    /// <summary>Gets active certificate-group observations.</summary>
    public required IReadOnlyList<CertificateSummary> Certificates { get; init; }
    /// <summary>Gets observed soft-deleted secret names; incomplete enumeration must be interpreted with Warnings.</summary>
    public required IReadOnlyList<string> DeletedSecretNames { get; init; }
    /// <summary>Gets observed soft-deleted key names, which are not automatically available for seeding.</summary>
    public required IReadOnlyList<string> DeletedKeyNames { get; init; }
    /// <summary>Gets observed soft-deleted certificate names, retained as conflicts rather than purged.</summary>
    public required IReadOnlyList<string> DeletedCertificateNames { get; init; }
    /// <summary>Gets the observed deleted-secret count, not a completeness assertion.</summary>
    public int DeletedSecretCount => DeletedSecretNames.Count;
    /// <summary>Gets the observed deleted-key count, not a completeness assertion.</summary>
    public int DeletedKeyCount => DeletedKeyNames.Count;
    /// <summary>Gets the observed deleted-certificate count, not a completeness assertion.</summary>
    public int DeletedCertificateCount => DeletedCertificateNames.Count;
    /// <summary>Gets all recorded metadata/deleted-list/authorization warnings used to reject complete-scan evidence.</summary>
    public required IReadOnlyList<string> Warnings { get; init; }
}

/// <summary>A planned action or its replacement execution outcome; action/status strings form a shared reporting contract.</summary>
/// <remarks>Authorization entries remain review-only proposals. Only guarded secret and native-seed executors can apply their supported object types.</remarks>
internal sealed record PlanItem
{
    /// <summary>Gets the discriminator: Secret, Key, CertificateGroup, Authorization, or Inventory.</summary>
    public required string ObjectType { get; init; }
    /// <summary>Gets the object or diagnostic subject name within its ObjectType namespace.</summary>
    public required string Name { get; init; }
    /// <summary>Gets the proposed operation; None and lifecycle/recovery proposals can be intentionally non-executable.</summary>
    public required string Action { get; init; }
    /// <summary>Gets the decision/outcome token consumed by executor eligibility and aggregate run classification.</summary>
    public required string Status { get; init; }
    /// <summary>Gets the observed or applied source version, when the object type/action has one.</summary>
    public string? SourceVersion { get; init; }
    /// <summary>Gets the observed or written target version, or null when unknown/absent.</summary>
    public string? TargetVersion { get; init; }
    /// <summary>Gets operator-facing reasoning without secret values or fingerprint contents.</summary>
    public string? Detail { get; init; }
}

/// <summary>A mutable progress report for one attempted pair within a run-history document.</summary>
internal sealed record PairScanReport
{
    /// <summary>Gets the directional pair identity shared with its durable state.</summary>
    public required string PairId { get; init; }
    /// <summary>Gets the source ARM ID captured for this attempt.</summary>
    public required string SourceVaultId { get; init; }
    /// <summary>Gets the target ARM ID captured for this attempt.</summary>
    public required string TargetVaultId { get; init; }
    /// <summary>Gets or sets Running, a scan/apply outcome, a lock skip, or a failure/cancellation status.</summary>
    public required string Status { get; set; }
    /// <summary>Gets the UTC time the pair attempt began, before lease acquisition.</summary>
    public required DateTimeOffset StartedAt { get; init; }
    /// <summary>Gets or sets the UTC completion time; null can indicate an in-progress or interrupted attempt.</summary>
    public DateTimeOffset? CompletedAt { get; set; }
    /// <summary>Gets or sets source observations; null means no inventory was obtained, not an empty vault.</summary>
    public VaultInventory? Source { get; set; }
    /// <summary>Gets or sets target observations; warnings can make a nonnull inventory partial.</summary>
    public VaultInventory? Target { get; set; }
    /// <summary>Gets proposals with executed secret entries replaced by their outcomes.</summary>
    public List<PlanItem> Plan { get; init; } = [];
    /// <summary>Gets pair-level failure, skip, or incompleteness explanations.</summary>
    public List<string> Errors { get; init; } = [];
}

/// <summary>A run-history snapshot repeatedly persisted as a mapping-driven cycle progresses.</summary>
/// <remarks>This is diagnostic history, not the authoritative per-secret baseline/intent state used for writes.</remarks>
internal sealed record RunRecord
{
    /// <summary>Gets the UTC timestamp-plus-random-ID correlation key and run-blob filename component.</summary>
    public required string RunId { get; init; }
    /// <summary>Gets the source-discovery subscription for the cycle.</summary>
    public required string SubscriptionId { get; init; }
    /// <summary>Gets the UTC start after state/HMAC initialization has succeeded.</summary>
    public required DateTimeOffset StartedAt { get; init; }
    /// <summary>Gets or sets the UTC finish time; null is retained if the process stops before finalization.</summary>
    public DateTimeOffset? CompletedAt { get; set; }
    /// <summary>Gets the execution model used for this cycle, currently <c>AutomaticSync</c>.</summary>
    public required string Mode { get; init; }
    /// <summary>Gets or sets Running, Complete, NoConfiguredPairs, Partial, Failed, or Cancelled.</summary>
    public required string Status { get; set; }
    /// <summary>Gets or sets subscription-wide discovered vault count, before source filtering.</summary>
    public int DiscoveredVaultCount { get; set; }
    /// <summary>Gets or sets accepted enabled pair count, despite the historical TaggedPairCount name.</summary>
    public int TaggedPairCount { get; set; }
    /// <summary>Gets or sets the count excluded by observed source/target pause tags.</summary>
    public int DisabledPairCount { get; set; }
    /// <summary>Gets distinct names that caused pause decisions during this discovery pass.</summary>
    public List<string> DisabledVaultNames { get; init; } = [];
    /// <summary>Gets or sets the count neither selected as sources nor referenced by those source candidates.</summary>
    public int UnmappedVaultCount { get; set; }
    /// <summary>Gets mapping diagnostics and any run-level failure/cancellation explanation.</summary>
    public List<string> DiscoveryIssues { get; init; } = [];
    /// <summary>Gets sequential pair-attempt reports accumulated so far, including lease-contention skips.</summary>
    public List<PairScanReport> Pairs { get; init; } = [];
}

/// <summary>A committed source/target relationship established only after exact target-version verification.</summary>
/// <remarks>
/// Fingerprints are integrity state, not secret values, and must not be emitted in logs. Unknown domain defaults
/// keep legacy/missing version metadata from silently becoming trusted current-format baselines.
/// </remarks>
internal sealed record SecretBaseline
{
    /// <summary>Gets the HMAC value-domain format version; unknown values require explicit recovery review.</summary>
    public string ValueDomainVersion { get; init; } = "unknown";
    /// <summary>Gets the canonical managed-metadata format version, independent of the HMAC key version.</summary>
    public string MetadataDomainVersion { get; init; } = "unknown";
    /// <summary>Gets the exact source version associated with the verified target.</summary>
    public required string SourceVersion { get; init; }
    /// <summary>Gets the exact target version the executor verified, not a movable latest-version alias.</summary>
    public required string TargetVersion { get; init; }
    /// <summary>Gets the keyed, domain-bound value fingerprint; never log this field.</summary>
    public required string ValueHmac { get; init; }
    /// <summary>Gets the operator's HMAC key-version label required for future baseline verification.</summary>
    public required string HmacKeyVersion { get; init; }
    /// <summary>Gets the SHA-256 of canonical managed metadata verified on the target.</summary>
    public required string MetadataDigest { get; init; }
    /// <summary>Gets the UTC verification/commit timestamp, not proof that the target stayed unchanged afterward.</summary>
    public required DateTimeOffset VerifiedAt { get; init; }
}

/// <summary>Records a target mutation that must be resolved before another write to the same secret.</summary>
/// <remarks>
/// Persisted before both value creation and metadata updates. Its presence means the operation must be
/// investigated, not that it definitely succeeded or failed. The normal runner does not auto-resolve it.
/// </remarks>
internal sealed record SecretWriteIntent
{
    /// <summary>Gets the run that prepared this operation, for recovery correlation.</summary>
    public required string RunId { get; init; }
    /// <summary>Gets the pinned source version read before preparing the intent.</summary>
    public required string SourceVersion { get; init; }
    /// <summary>Gets the expected post-write value HMAC, not the secret or key material.</summary>
    public required string ExpectedValueHmac { get; init; }
    /// <summary>Gets the expected post-write managed-metadata digest.</summary>
    public required string ExpectedMetadataDigest { get; init; }
    /// <summary>Gets the key-version label needed to interpret the expected HMAC.</summary>
    public required string HmacKeyVersion { get; init; }
    /// <summary>Gets the observed pre-write target head, or null when the name was observed absent.</summary>
    public string? TargetVersionBefore { get; init; }
    /// <summary>Gets the UTC preparation time; it is not a service write-acknowledgment time.</summary>
    public required DateTimeOffset CreatedAt { get; init; }
}

/// <summary>The lease/ETag-protected per-pair state used to coordinate writes across cooperating runner instances.</summary>
/// <remarks>
/// Field names/defaults are a persisted JSON contract. Preserve compatible deserialization and reject unsupported
/// schema/domain versions rather than silently adopting existing target contents. This model contains no HMAC key.
/// </remarks>
internal sealed record PairState
{
    /// <summary>The writer's state schema version; changing it requires an explicit compatibility/migration decision.</summary>
    public const int CurrentSchemaVersion = 4;
    /// <summary>Gets or sets the persisted schema marker validated when the Blob state is loaded.</summary>
    public int SchemaVersion { get; set; } = CurrentSchemaVersion;
    /// <summary>Gets the directional identity whose hash addresses this state blob.</summary>
    public required string PairId { get; init; }
    /// <summary>Gets the persisted source ARM ID checked against the current mapping before reuse.</summary>
    public required string SourceVaultId { get; init; }
    /// <summary>Gets the persisted target ARM ID checked against the current mapping before reuse.</summary>
    public required string TargetVaultId { get; init; }
    /// <summary>Gets or sets the last warning-free inventory checkpoint, not a successful-mutation guarantee.</summary>
    public DateTimeOffset? LastCompleteScanAt { get; set; }
    /// <summary>Gets or sets the run associated with LastCompleteScanAt, null before any such checkpoint.</summary>
    public string? LastCompleteRunId { get; set; }
    /// <summary>Gets per-secret committed verification baselines; existing targets without one are not automatically adopted.</summary>
    public Dictionary<string, SecretBaseline> SecretBaselines { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Gets unresolved value-write or metadata-update intents that block further writes to the corresponding names.</summary>
    public Dictionary<string, SecretWriteIntent> PendingSecretWrites { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Gets committed one-time key-seed outcomes; these never authorize overwriting or rotating a target.</summary>
    public Dictionary<string, NativeSeedBaseline> KeySeedBaselines { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Gets committed one-time certificate-group seed outcomes.</summary>
    public Dictionary<string, NativeSeedBaseline> CertificateGroupSeedBaselines { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Gets key restore attempts whose outcome must be resolved before another attempt.</summary>
    public Dictionary<string, NativeSeedIntent> PendingKeySeeds { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Gets certificate-group restore attempts whose outcome must be resolved before another attempt.</summary>
    public Dictionary<string, NativeSeedIntent> PendingCertificateGroupSeeds { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>A committed record for a verified, one-time native seed; it never grants overwrite authority.</summary>
internal sealed record NativeSeedBaseline
{
    /// <summary>Gets the pinned source head version included in the native backup.</summary>
    public required string SourceVersion { get; init; }
    /// <summary>Gets the exact restored target version that was read back and verified.</summary>
    public required string TargetVersion { get; init; }
    /// <summary>Gets the observed key type for a standalone key seed, when applicable.</summary>
    public string? KeyType { get; init; }
    /// <summary>Gets the public JWK or certificate DER fingerprint when one was available.</summary>
    public string? PublicFingerprintSha256 { get; init; }
    /// <summary>Gets the verified certificate-group backing key version, when applicable.</summary>
    public string? BackingKeyVersion { get; init; }
    /// <summary>Gets the public JWK fingerprint of the verified certificate-group backing key.</summary>
    public string? BackingKeyPublicFingerprintSha256 { get; init; }
    /// <summary>Gets the verified certificate-group backing secret version, without its value.</summary>
    public string? BackingSecretVersion { get; init; }
    /// <summary>Gets when the restore was verified; it does not assert the target remained unchanged afterward.</summary>
    public required DateTimeOffset VerifiedAt { get; init; }
}

/// <summary>Records a native restore that must be investigated before another restore is allowed.</summary>
/// <remarks>The encrypted backup payload is never stored in pair state.</remarks>
internal sealed record NativeSeedIntent
{
    /// <summary>Gets the run that prepared this restore attempt.</summary>
    public required string RunId { get; init; }
    /// <summary>Gets the pinned source head version used to create the backup.</summary>
    public required string SourceVersion { get; init; }
    /// <summary>Gets when the durable intent was saved, not when Key Vault accepted the restore.</summary>
    public required DateTimeOffset CreatedAt { get; init; }
}
