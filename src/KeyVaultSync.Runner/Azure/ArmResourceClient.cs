using System.Net.Http.Headers;
using System.Diagnostics;
using System.Text.Json;
using Azure.Core;
using Azure.Identity;
using Microsoft.Extensions.Logging;

namespace KeyVaultSync.Runner.Azure;

/// <summary>Discovers subscription Key Vault pairs and reads ARM-level authorization declarations.</summary>
/// <param name="credential">Credential requesting the public Azure Resource Manager scope; no data-plane values are read here.</param>
/// <param name="logger">Structured logger used for discovery decisions, pages, and bounded GET retries.</param>
/// <param name="httpClient">Optional reusable client for test transport injection; otherwise a client is created for this instance.</param>
/// <remarks>
/// All operations are reads. This client assumes public Azure management endpoints and consumes ARM-provided
/// pagination links. Authorization inventory describes declarations, not effective permission evaluation.
/// The class does not dispose the optional client or the credential supplied by its caller.
/// </remarks>
internal sealed class ArmResourceClient(TokenCredential credential, ILogger<ArmResourceClient> logger, HttpClient? httpClient = null)
{
    private static readonly EventId KeyVaultDiscoveredEventId = new(1100, "KeyVaultDiscovered");
    private static readonly EventId KeyVaultSyncPairEvaluatedEventId = new(1101, "KeyVaultSyncPairEvaluated");
    private static readonly EventId ArmDiscoveryPageCompletedEventId = new(1200, "ArmDiscoveryPageCompleted");
    private static readonly EventId RoleAssignmentPageCompletedEventId = new(1201, "RoleAssignmentPageCompleted");
    private static readonly TokenRequestContext ArmTokenContext = new(["https://management.azure.com/.default"]);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly HttpClient _httpClient = httpClient ?? new();

    /// <summary>Finds tagged source vaults, resolves targets, and records enabled, paused, and invalid pair decisions.</summary>
    /// <param name="options">Subscription, optional source resource-group filter, and target-resource-ID tag name.</param>
    /// <param name="cancellationToken">Cancellation passed to ARM enumeration and target lookups.</param>
    /// <returns>Subscription-wide discovery counts and the accepted pairs, disabled observations, and mapping issues.</returns>
    /// <remarks>
    /// <para>The resource-group filter selects sources only; mapped targets can be elsewhere and are fetched
    /// individually when absent from the subscription listing. Source pause tags short-circuit source-side mapping validation.</para>
    /// <para>Mappings can be declared by the configured source-side target-ID tag or by
    /// <see cref="KeyVaultSyncResourceTags.SyncSourceKeyVaultId"/> on a target. Duplicate declarations of the
    /// same edge are collapsed; one source may have several targets, while target ownership conflicts and chains are rejected.</para>
    /// <para>Pause tags are a discovery-time observation, not an in-flight kill switch. Subscription-list errors
    /// propagate, while individual target-lookup exceptions (including cancellation there) become mapping issues.</para>
    /// </remarks>
    public async Task<DiscoveryResult> DiscoverPairsAsync(RunnerOptions options, CancellationToken cancellationToken)
    {
        using var activity = RunnerTelemetry.ActivitySource.StartActivity("arm.discover-key-vault-pairs");
        var timer = Stopwatch.StartNew();
        logger.LogInformation("Listing subscription Key Vault resources for {SubscriptionId} using source tag {PairTagName} and target tag {SourceKeyVaultIdTagName}.",
            options.SubscriptionId, options.PairTag, KeyVaultSyncResourceTags.SyncSourceKeyVaultId);
        var allVaults = await ListKeyVaultResourcesAsync(options.SubscriptionId, cancellationToken);
        foreach (var vault in allVaults)
        {
            LogDiscoveredVault(vault, options.PairTag);
        }

        // List the entire subscription first for diagnostics and target reuse. Only source vaults
        // are resource-group filtered; discovery counts therefore remain subscription-wide.
        var byId = allVaults.ToDictionary(vault => NormalizeId(vault.Id), StringComparer.OrdinalIgnoreCase);
        var issues = new List<string>();
        var declarations = new List<PairDeclaration>();
        var disabledPairCount = 0;
        var disabledVaultNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var source in allVaults)
        {
            var targetId = GetTag(source, options.PairTag);
            if (!string.IsNullOrWhiteSpace(targetId)
                && IsSourceInRequestedGroup(source, options.ResourceGroup))
            {
                if (KeyVaultSyncResourceTags.IsSyncDisabled(source))
                {
                    disabledPairCount++;
                    disabledVaultNames.Add(source.Name);
                    LogPairDecision(source, null, targetId, syncEnabled: false, "SourceDisabled");
                    logger.LogInformation("Skipping Key Vault pair for source {SourceVault} because ARM tag {TagName}=true is set.",
                        source.Name, KeyVaultSyncResourceTags.SyncDisabled);
                    continue;
                }

                var normalizedTargetId = targetId.Trim();
                if (!TryValidateKeyVaultResourceId(normalizedTargetId, out var targetError))
                {
                    issues.Add($"Invalid {options.PairTag} on {source.Id}: {targetError}");
                    LogPairDecision(source, null, normalizedTargetId, syncEnabled: false, "InvalidSyncId", isMappingIssue: true);
                    continue;
                }

                declarations.Add(new PairDeclaration(source, normalizedTargetId));
            }
        }

        foreach (var target in allVaults)
        {
            var sourceId = GetTag(target, KeyVaultSyncResourceTags.SyncSourceKeyVaultId);
            if (string.IsNullOrWhiteSpace(sourceId))
            {
                continue;
            }

            var normalizedSourceId = sourceId.Trim();
            if (!TryValidateKeyVaultResourceId(normalizedSourceId, out var sourceError))
            {
                issues.Add($"Invalid {KeyVaultSyncResourceTags.SyncSourceKeyVaultId} on target {target.Id}: {sourceError}");
                continue;
            }

            if (!byId.TryGetValue(NormalizeId(normalizedSourceId), out var source))
            {
                issues.Add($"Source {normalizedSourceId} declared by target {target.Id} was not found in the subscription Key Vault inventory.");
                continue;
            }

            if (!IsSourceInRequestedGroup(source, options.ResourceGroup))
            {
                continue;
            }

            declarations.Add(new PairDeclaration(source, target.Id));
        }

        // A source-side tag and the corresponding target-side tag declare the same edge. Collapse
        // those duplicates before checking ownership so either declaration style can be migrated
        // without creating an artificial conflict.
        var distinctDeclarations = declarations
            .GroupBy(declaration => declaration, PairDeclarationComparer.Instance)
            .Select(group => group.First())
            .OrderBy(declaration => NormalizeId(declaration.Source.Id), StringComparer.OrdinalIgnoreCase)
            .ThenBy(declaration => NormalizeId(declaration.TargetId), StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var declarationsByTarget = distinctDeclarations
            .GroupBy(declaration => NormalizeId(declaration.TargetId), StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var conflictingTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in declarationsByTarget)
        {
            var owners = group
                .Select(declaration => NormalizeId(declaration.Source.Id))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (owners.Length <= 1)
            {
                continue;
            }

            conflictingTargets.Add(group.Key);
            var targetId = group.First().TargetId;
            issues.Add($"Target {targetId} is declared by multiple distinct sources; every mapping to that target was skipped.");
        }

        var sourceIds = distinctDeclarations
            .Select(declaration => NormalizeId(declaration.Source.Id))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var targetIds = distinctDeclarations
            .Select(declaration => NormalizeId(declaration.TargetId))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var chainedVaultIds = sourceIds
            .Where(targetIds.Contains)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var chainedVaultId in chainedVaultIds)
        {
            issues.Add($"Vault {chainedVaultId} is both a source and a target; chained or cyclic mappings are unsupported.");
        }

        var pairs = new List<VaultPair>();
        foreach (var declaration in distinctDeclarations)
        {
            var source = declaration.Source;
            var targetId = declaration.TargetId;
            var normalizedSourceId = NormalizeId(source.Id);
            var normalizedTargetId = NormalizeId(targetId);

            if (normalizedSourceId.Equals(normalizedTargetId, StringComparison.OrdinalIgnoreCase))
            {
                issues.Add($"Source {source.Id} maps to itself; pair was skipped.");
                LogPairDecision(source, source, targetId, syncEnabled: false, "SourceMapsToSelf", isMappingIssue: true);
                continue;
            }

            if (conflictingTargets.Contains(normalizedTargetId))
            {
                LogPairDecision(source, null, targetId, syncEnabled: false, "ConflictingTargetOwner", isMappingIssue: true);
                continue;
            }

            if (chainedVaultIds.Contains(normalizedSourceId) || chainedVaultIds.Contains(normalizedTargetId))
            {
                LogPairDecision(source, null, targetId, syncEnabled: false, "ChainedOrCyclicMapping", isMappingIssue: true);
                continue;
            }

            VaultResource target;
            if (!byId.TryGetValue(normalizedTargetId, out target!))
            {
                try
                {
                    target = await GetKeyVaultResourceAsync(targetId, cancellationToken);
                }
                catch (Exception exception)
                {
                    issues.Add($"Target {targetId} for source {source.Id} could not be read: {SafeError(exception)}");
                    LogPairDecision(source, null, targetId, syncEnabled: false, "TargetUnreadable", isMappingIssue: true);
                    continue;
                }
            }

            if (!TryValidateKeyVaultResourceId(target.Id, out _) || !normalizedTargetId.Equals(NormalizeId(target.Id), StringComparison.OrdinalIgnoreCase))
            {
                issues.Add($"Target {targetId} did not resolve to the declared Microsoft.KeyVault/vaults resource.");
                LogPairDecision(source, target, targetId, syncEnabled: false, "InvalidTargetType", isMappingIssue: true);
                continue;
            }

            if (!string.IsNullOrWhiteSpace(GetTag(target, options.PairTag)))
            {
                issues.Add($"Target {target.Id} is also tagged as a source; chained mappings are unsupported.");
                LogPairDecision(source, target, targetId, syncEnabled: false, "TargetIsAlsoSource", isMappingIssue: true);
                continue;
            }

            var targetSourceId = GetTag(target, KeyVaultSyncResourceTags.SyncSourceKeyVaultId);
            if (!string.IsNullOrWhiteSpace(targetSourceId)
                && !NormalizeId(targetSourceId).Equals(normalizedSourceId, StringComparison.OrdinalIgnoreCase))
            {
                issues.Add($"Target {target.Id} declares a different source in {KeyVaultSyncResourceTags.SyncSourceKeyVaultId}; pair was skipped.");
                LogPairDecision(source, target, targetId, syncEnabled: false, "ConflictingTargetSource", isMappingIssue: true);
                continue;
            }

            if (KeyVaultSyncResourceTags.IsSyncDisabled(source))
            {
                disabledPairCount++;
                disabledVaultNames.Add(source.Name);
                LogPairDecision(source, target, targetId, syncEnabled: false, "SourceDisabled");
                logger.LogInformation("Skipping Key Vault pair for source {SourceVault} because ARM tag {TagName}=true is set.",
                    source.Name, KeyVaultSyncResourceTags.SyncDisabled);
                continue;
            }

            if (KeyVaultSyncResourceTags.IsSyncDisabled(target))
            {
                disabledPairCount++;
                disabledVaultNames.Add(target.Name);
                LogPairDecision(source, target, targetId, syncEnabled: false, "TargetDisabled");
                logger.LogInformation("Skipping Key Vault pair for target {TargetVault} because ARM tag {TagName}=true is set.",
                    target.Name, KeyVaultSyncResourceTags.SyncDisabled);
                continue;
            }

            pairs.Add(new VaultPair(source, target));
            LogPairDecision(source, target, targetId, syncEnabled: true, "Enabled");
        }

        // "Unmapped" is relative to the selected source set: neither a source candidate nor a
        // referenced target. Sources outside the requested resource group remain out of scope.
        var referencedIds = distinctDeclarations
            .SelectMany(declaration => new[] { NormalizeId(declaration.Source.Id), NormalizeId(declaration.TargetId) })
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var untagged = allVaults
            .Where(vault => !IsSourceInRequestedGroup(vault, options.ResourceGroup)
                || string.IsNullOrWhiteSpace(GetTag(vault, options.PairTag)))
            .Where(vault => !referencedIds.Contains(NormalizeId(vault.Id)))
            .Select(vault => vault.Name)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        activity?.SetTag("vault.discovered_count", allVaults.Count);
        activity?.SetTag("sync.pair_count", pairs.Count);
        activity?.SetTag("sync.disabled_pair_count", disabledPairCount);
        activity?.SetTag("sync.mapping_issue_count", issues.Count);
        timer.Stop();
        activity?.SetTag("stage.duration_ms", timer.Elapsed.TotalMilliseconds);
        activity?.SetStatus(issues.Count == 0 ? ActivityStatusCode.Ok : ActivityStatusCode.Error,
            issues.Count == 0 ? null : "Mapping issues detected");
        logger.LogInformation("Subscription discovery found {VaultCount} vaults, {PairCount} enabled pairs, {DisabledPairCount} disabled pairs, and {IssueCount} mapping issues.",
            allVaults.Count, pairs.Count, disabledPairCount, issues.Count);

        return new DiscoveryResult
        {
            DiscoveredVaultCount = allVaults.Count,
            Pairs = pairs,
            DisabledPairCount = disabledPairCount,
            DisabledVaultNames = disabledVaultNames.Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            UnmappedVaultNames = untagged,
            Issues = issues,
        };
    }

    private static bool IsSourceInRequestedGroup(VaultResource source, string? resourceGroup)
    {
        return resourceGroup is null || source.ResourceGroup.Equals(resourceGroup, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Emits event 1100 and a discovery activity for every listed vault, including unmapped and paused vaults.</summary>
    /// <remarks>Tag-presence fields mean a nonblank value exists, not that the mapping is valid or enabled.</remarks>
    private void LogDiscoveredVault(VaultResource vault, string pairTagName)
    {
        var rawSyncId = GetTag(vault, pairTagName);
        var hasSyncId = !string.IsNullOrWhiteSpace(rawSyncId);
        var syncId = hasSyncId ? rawSyncId!.Trim() : null;
        var rawSourceId = GetTag(vault, KeyVaultSyncResourceTags.SyncSourceKeyVaultId);
        var hasSourceId = !string.IsNullOrWhiteSpace(rawSourceId);
        var sourceId = hasSourceId ? rawSourceId!.Trim() : null;
        var syncDisabled = KeyVaultSyncResourceTags.IsSyncDisabled(vault);
        using var activity = RunnerTelemetry.ActivitySource.StartActivity("arm.keyvault.discovered");
        activity?.SetTag("vault.name", vault.Name);
        activity?.SetTag("azure.resource.id", vault.Id);
        activity?.SetTag("azure.resource.group", vault.ResourceGroup);
        activity?.SetTag("cloud.region", vault.Location);
        activity?.SetTag("sync.pair_tag", pairTagName);
        activity?.SetTag("sync.has_id", hasSyncId);
        activity?.SetTag("sync.id", syncId);
        activity?.SetTag("sync.has_source_id", hasSourceId);
        activity?.SetTag("sync.source_id", sourceId);
        activity?.SetTag("sync.disabled", syncDisabled);
        activity?.SetStatus(ActivityStatusCode.Ok);

        logger.LogInformation(
            KeyVaultDiscoveredEventId,
            "Discovered Key Vault {KeyVaultName} in resource group {ResourceGroup} at {Region}. Source tag {PairTagName} is present: {HasSyncId}; target ID: {SyncId}; target source tag {SourceKeyVaultIdTagName} is present: {HasSourceId}; source ID: {SourceId}; sync disabled: {SyncDisabled}.",
            vault.Name, vault.ResourceGroup, vault.Location, pairTagName, hasSyncId, syncId,
            KeyVaultSyncResourceTags.SyncSourceKeyVaultId, hasSourceId, sourceId, syncDisabled);
    }

    /// <summary>Emits one structured event/activity explaining a candidate's enabled, paused, or rejected decision.</summary>
    /// <remarks>Targets may be unresolved. Mapping problems are warnings; deliberate pause decisions are informational.</remarks>
    private void LogPairDecision(
        VaultResource source,
        VaultResource? target,
        string? syncId,
        bool syncEnabled,
        string decision,
        bool isMappingIssue = false)
    {
        using var activity = RunnerTelemetry.ActivitySource.StartActivity("arm.keyvault.sync-pair");
        activity?.SetTag("vault.source.name", source.Name);
        activity?.SetTag("vault.source.id", source.Id);
        activity?.SetTag("vault.target.name", target?.Name);
        activity?.SetTag("vault.target.id", target?.Id ?? syncId);
        activity?.SetTag("sync.id", syncId);
        activity?.SetTag("sync.enabled", syncEnabled);
        activity?.SetTag("sync.decision", decision);
        activity?.SetStatus(isMappingIssue ? ActivityStatusCode.Error : ActivityStatusCode.Ok, decision);

        const string logMessage = "Key Vault sync pair evaluated. Source {SourceVaultName}; target {TargetVaultName}; sync enabled: {SyncEnabled}; sync ID: {SyncId}; decision: {Decision}.";
        if (isMappingIssue)
        {
            logger.LogWarning(KeyVaultSyncPairEvaluatedEventId, logMessage,
                source.Name, target?.Name, syncEnabled, syncId, decision);
        }
        else
        {
            logger.LogInformation(KeyVaultSyncPairEvaluatedEventId, logMessage,
                source.Name, target?.Name, syncEnabled, syncId, decision);
        }
    }

    /// <summary>Reads the authorization mode, access policies, and role-assignment declarations around a vault.</summary>
    /// <param name="vaultId">Full ARM resource ID used to derive vault, resource-group, and subscription scopes.</param>
    /// <param name="cancellationToken">Cancellation passed to each ARM read.</param>
    /// <returns>Observed declarations plus warnings for any role-assignment scope that could not be read.</returns>
    /// <remarks>
    /// This does not resolve group membership, role-definition permissions, deny assignments, management-group
    /// inheritance, PIM activation, or network access. It cannot prove effective access or safely clone authorization.
    /// The vault read must succeed; scope enumeration catches all exceptions and retains partial observations.
    /// </remarks>
    public async Task<VaultAuthorizationSummary> GetAuthorizationAsync(string vaultId, CancellationToken cancellationToken)
    {
        using var activity = RunnerTelemetry.ActivitySource.StartActivity("arm.read-vault-authorization");
        activity?.SetTag("vault.name", vaultId.Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault());
        using var vaultDocument = await GetJsonAsync($"{vaultId}?api-version=2023-07-01", cancellationToken);
        var properties = vaultDocument.RootElement.TryGetProperty("properties", out var value) ? value : default;
        var usesRbac = properties.ValueKind == JsonValueKind.Object
            && properties.TryGetProperty("enableRbacAuthorization", out var rbacValue)
            && rbacValue.ValueKind == JsonValueKind.True;
        var policies = new List<AccessPolicySummary>();
        if (properties.ValueKind == JsonValueKind.Object
            && properties.TryGetProperty("accessPolicies", out var policyArray)
            && policyArray.ValueKind == JsonValueKind.Array)
        {
            foreach (var policy in policyArray.EnumerateArray())
            {
                var permissions = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
                if (policy.TryGetProperty("permissions", out var permissionsElement)
                    && permissionsElement.ValueKind == JsonValueKind.Object)
                {
                    foreach (var permissionKind in permissionsElement.EnumerateObject())
                    {
                        permissions[permissionKind.Name] = permissionKind.Value.ValueKind == JsonValueKind.Array
                            ? permissionKind.Value.EnumerateArray().Select(item => item.GetString() ?? string.Empty).ToArray()
                            : [];
                    }
                }

                policies.Add(new AccessPolicySummary
                {
                    TenantId = GetString(policy, "tenantId") ?? string.Empty,
                    ObjectId = GetString(policy, "objectId") ?? string.Empty,
                    ApplicationId = GetString(policy, "applicationId"),
                    Permissions = permissions,
                });
            }
        }

        var roleAssignments = new List<RoleAssignmentSummary>();
        var warnings = new List<string>();
        // An unreadable ancestor must not be mistaken for "no assignments". Keep the observations
        // from other scopes, but carry an explicit incompleteness warning into the vault inventory.
        foreach (var scope in GetRoleScopes(vaultId))
        {
            try
            {
                roleAssignments.AddRange(await ListDirectRoleAssignmentsAsync(scope, cancellationToken));
            }
            catch (Exception exception)
            {
                warnings.Add($"Role-assignment inventory is incomplete at {scope}: {SafeError(exception)}");
                logger.LogWarning(exception, "Role-assignment inventory is incomplete at {Scope}.", scope);
            }
        }

        activity?.SetTag("authorization.rbac_enabled", usesRbac);
        activity?.SetTag("authorization.access_policy_count", policies.Count);
        activity?.SetTag("authorization.role_assignment_count", roleAssignments.Count);
        activity?.SetTag("authorization.warning_count", warnings.Count);
        logger.LogInformation("Authorization inventory for {VaultName} found {AccessPolicyCount} access policies, {RoleAssignmentCount} direct role assignments, and {WarningCount} warnings.",
            vaultId.Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault(), policies.Count, roleAssignments.Count, warnings.Count);

        return new VaultAuthorizationSummary
        {
            UsesRbac = usesRbac,
            AccessPolicies = policies,
            RoleAssignments = roleAssignments,
            Warnings = warnings,
        };
    }

    /// <summary>Follows ARM nextLink pages for the subscription resource listing and retains only Key Vault resources.</summary>
    /// <remarks>Per-page counts make progress visible; a page failure aborts enumeration rather than returning an empty page.</remarks>
    private async Task<IReadOnlyList<VaultResource>> ListKeyVaultResourcesAsync(string subscriptionId, CancellationToken cancellationToken)
    {
        var filter = Uri.EscapeDataString("resourceType eq 'Microsoft.KeyVault/vaults'");
        var requestUri = $"https://management.azure.com/subscriptions/{subscriptionId}/resources?api-version=2021-04-01&$filter={filter}";
        var vaults = new List<VaultResource>();
        var pageNumber = 0;
        while (!string.IsNullOrWhiteSpace(requestUri))
        {
            pageNumber++;
            using var document = await GetJsonAsync(requestUri, cancellationToken);
            var resourceCount = 0;
            var vaultCountBeforePage = vaults.Count;
            if (document.RootElement.TryGetProperty("value", out var resources) && resources.ValueKind == JsonValueKind.Array)
            {
                resourceCount = resources.GetArrayLength();
                foreach (var resource in resources.EnumerateArray())
                {
                    if (!string.Equals(GetString(resource, "type"), "Microsoft.KeyVault/vaults", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    vaults.Add(ParseVaultResource(resource));
                }
            }

            logger.LogInformation(ArmDiscoveryPageCompletedEventId,
                "ARM Key Vault discovery page completed. {SubscriptionId}; page {PageNumber}; {ResourceCount} resources; {PageVaultCount} Key Vaults on page; {TotalVaultCount} total Key Vaults.",
                subscriptionId, pageNumber, resourceCount, vaults.Count - vaultCountBeforePage, vaults.Count);
            requestUri = GetString(document.RootElement, "nextLink") ?? string.Empty;
        }

        return vaults;
    }

    /// <summary>Reads a mapped target not already available from subscription discovery using the Key Vault ARM API.</summary>
    private async Task<VaultResource> GetKeyVaultResourceAsync(string resourceId, CancellationToken cancellationToken)
    {
        using var document = await GetJsonAsync($"{resourceId}?api-version=2023-07-01", cancellationToken);
        return ParseVaultResource(document.RootElement);
    }

    /// <summary>Follows role-assignment pages using the ARM atScope filter and preserves returned conditions and principals.</summary>
    /// <remarks>Does not expand role definitions or evaluate condition expressions; GetAuthorizationAsync aggregates the scopes.</remarks>
    private async Task<IReadOnlyList<RoleAssignmentSummary>> ListDirectRoleAssignmentsAsync(string scope, CancellationToken cancellationToken)
    {
        var query = Uri.EscapeDataString("atScope()");
        var requestUri = $"https://management.azure.com{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter={query}";
        var assignments = new List<RoleAssignmentSummary>();
        var pageNumber = 0;
        while (!string.IsNullOrWhiteSpace(requestUri))
        {
            pageNumber++;
            using var document = await GetJsonAsync(requestUri, cancellationToken);
            var pageAssignmentCount = 0;
            if (document.RootElement.TryGetProperty("value", out var values) && values.ValueKind == JsonValueKind.Array)
            {
                pageAssignmentCount = values.GetArrayLength();
                foreach (var assignment in values.EnumerateArray())
                {
                    var properties = assignment.TryGetProperty("properties", out var value) ? value : default;
                    assignments.Add(new RoleAssignmentSummary
                    {
                        Id = GetString(assignment, "id") ?? string.Empty,
                        Scope = GetString(properties, "scope") ?? scope,
                        PrincipalId = GetString(properties, "principalId") ?? string.Empty,
                        PrincipalType = GetString(properties, "principalType"),
                        RoleDefinitionId = GetString(properties, "roleDefinitionId") ?? string.Empty,
                        Condition = GetString(properties, "condition"),
                    });
                }
            }

            logger.LogInformation(RoleAssignmentPageCompletedEventId,
                "ARM role-assignment page completed. {Scope}; page {PageNumber}; {PageAssignmentCount} assignments on page; {TotalAssignmentCount} total assignments.",
                scope, pageNumber, pageAssignmentCount, assignments.Count);
            requestUri = GetString(document.RootElement, "nextLink") ?? string.Empty;
        }

        return assignments;
    }

    /// <summary>Yields the vault, containing resource group, and subscription scopes from a conventional Key Vault resource ID.</summary>
    /// <remarks>No tenant/management-group lookup is attempted; malformed IDs can produce only the scopes derivable from them.</remarks>
    private static IEnumerable<string> GetRoleScopes(string vaultId)
    {
        yield return vaultId;
        var resourceGroupMarker = "/providers/Microsoft.KeyVault/vaults/";
        var markerIndex = vaultId.IndexOf(resourceGroupMarker, StringComparison.OrdinalIgnoreCase);
        if (markerIndex < 0)
        {
            yield break;
        }

        var resourceGroupScope = vaultId[..markerIndex];
        yield return resourceGroupScope;

        var subscriptionMarker = "/resourceGroups/";
        var groupIndex = resourceGroupScope.IndexOf(subscriptionMarker, StringComparison.OrdinalIgnoreCase);
        if (groupIndex > 0)
        {
            yield return resourceGroupScope[..groupIndex];
        }
    }

    /// <summary>Performs an authenticated ARM GET with at most three attempts for selected transient read failures.</summary>
    /// <param name="requestUri">An ARM-relative path or an absolute HTTPS URL such as an ARM nextLink.</param>
    /// <param name="cancellationToken">Cancels token acquisition, transport, body reads, or retry delays.</param>
    /// <returns>A parsed document owned by the caller, which must dispose it after copying needed values.</returns>
    /// <exception cref="InvalidOperationException">ARM returns a final unsuccessful HTTP response.</exception>
    /// <exception cref="JsonException">A successful response does not contain valid JSON.</exception>
    /// <remarks>
    /// Retries apply only to this GET path: 429/5xx responses, transport failures, and timeouts not requested
    /// by the caller. Token acquisition occurs once before the retry loop. Authentication/authorization
    /// failures and malformed successful JSON are not retried here. Never reuse this policy for secret writes.
    /// </remarks>
    private async Task<JsonDocument> GetJsonAsync(string requestUri, CancellationToken cancellationToken)
    {
        var absoluteUri = Uri.TryCreate(requestUri, UriKind.Absolute, out var parsedUri)
            && parsedUri is not null
            && parsedUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                ? parsedUri
                : new Uri($"https://management.azure.com/{requestUri.TrimStart('/')}");
        requestUri = absoluteUri.AbsoluteUri;

        // The public-cloud endpoint/scope is fixed. Absolute pagination links are trusted as
        // ARM responses; this helper is not a general-purpose fetcher for untrusted user URLs.
        var accessToken = await credential.GetTokenAsync(ArmTokenContext, cancellationToken);
        const int maximumAttempts = 3;
        for (var attempt = 1; ; attempt++)
        {
            using var activity = RunnerTelemetry.ActivitySource.StartActivity("arm.http-get");
            activity?.SetTag("http.request.method", "GET");
            activity?.SetTag("http.request.path", absoluteUri.AbsolutePath);
            activity?.SetTag("retry.attempt", attempt);

            try
            {
                logger.LogTrace("ARM GET request starting. {RequestPath}; attempt {Attempt}/{MaximumAttempts}.",
                    absoluteUri.AbsolutePath, attempt, maximumAttempts);
                using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken.Token);
                using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                logger.LogTrace("ARM GET response received. {RequestPath}; attempt {Attempt}; HTTP {StatusCode}.",
                    absoluteUri.AbsolutePath, attempt, (int)response.StatusCode);
                var content = await response.Content.ReadAsStringAsync(cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    var isTransientStatus = response.StatusCode is System.Net.HttpStatusCode.TooManyRequests
                        || (int)response.StatusCode >= 500;
                    if (isTransientStatus && attempt < maximumAttempts)
                    {
                        var delay = GetRetryDelay(response, attempt);
                        activity?.SetTag("http.response.status_code", (int)response.StatusCode);
                        activity?.SetTag("retry.delay_ms", delay.TotalMilliseconds);
                        logger.LogWarning("Transient ARM GET failure HTTP {StatusCode} on attempt {Attempt}/{MaximumAttempts}; retrying after {DelayMs} ms.",
                            (int)response.StatusCode, attempt, maximumAttempts, delay.TotalMilliseconds);
                        await Task.Delay(delay, cancellationToken);
                        continue;
                    }

                    activity?.SetStatus(ActivityStatusCode.Error, $"HTTP {(int)response.StatusCode}");
                    logger.LogWarning("ARM GET {RequestPath} failed with HTTP {StatusCode}.",
                        response.RequestMessage?.RequestUri?.AbsolutePath, (int)response.StatusCode);
                    throw new InvalidOperationException($"ARM GET failed with HTTP {(int)response.StatusCode}: {ExtractArmError(content)}");
                }

                activity?.SetStatus(ActivityStatusCode.Ok);
                return JsonDocument.Parse(content);
            }
            catch (HttpRequestException exception) when (attempt < maximumAttempts)
            {
                var delay = GetRetryDelay(null, attempt);
                activity?.SetTag("retry.delay_ms", delay.TotalMilliseconds);
                logger.LogWarning(exception, "Transient transport failure on ARM GET attempt {Attempt}/{MaximumAttempts}; retrying after {DelayMs} ms.",
                    attempt, maximumAttempts, delay.TotalMilliseconds);
                await Task.Delay(delay, cancellationToken);
            }
            catch (TaskCanceledException exception) when (!cancellationToken.IsCancellationRequested && attempt < maximumAttempts)
            {
                var delay = GetRetryDelay(null, attempt);
                activity?.SetTag("retry.delay_ms", delay.TotalMilliseconds);
                logger.LogWarning(exception, "ARM GET timed out on attempt {Attempt}/{MaximumAttempts}; retrying after {DelayMs} ms.",
                    attempt, maximumAttempts, delay.TotalMilliseconds);
                await Task.Delay(delay, cancellationToken);
            }
        }
    }

    /// <summary>Honors a delta Retry-After up to ten seconds, otherwise uses exponential backoff plus sub-250 ms jitter.</summary>
    /// <remarks>Attempt numbers are one-based; an HTTP-date Retry-After is not interpreted by this implementation.</remarks>
    private static TimeSpan GetRetryDelay(HttpResponseMessage? response, int attempt)
    {
        if (response?.Headers.RetryAfter?.Delta is { } retryAfter)
        {
            return TimeSpan.FromMilliseconds(Math.Clamp(retryAfter.TotalMilliseconds, 0, 10_000));
        }

        var exponentialMilliseconds = 250 * Math.Pow(2, attempt - 1);
        return TimeSpan.FromMilliseconds(exponentialMilliseconds + Random.Shared.Next(0, 250));
    }

    /// <summary>Copies discovery metadata from a JSON document into a resource record with case-insensitive tags.</summary>
    /// <remarks>Missing strings become empty values; this parser does not establish data-plane reachability or permissions.</remarks>
    private static VaultResource ParseVaultResource(JsonElement resource)
    {
        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (resource.TryGetProperty("tags", out var tagsElement) && tagsElement.ValueKind == JsonValueKind.Object)
        {
            foreach (var tag in tagsElement.EnumerateObject())
            {
                tags[tag.Name] = tag.Value.ValueKind == JsonValueKind.String ? tag.Value.GetString() ?? string.Empty : tag.Value.ToString();
            }
        }

        var id = GetString(resource, "id") ?? string.Empty;
        var name = GetString(resource, "name") ?? string.Empty;
        var resourceGroup = string.Empty;
        var groupMarker = "/resourceGroups/";
        var groupIndex = id.IndexOf(groupMarker, StringComparison.OrdinalIgnoreCase);
        var providerIndex = id.IndexOf("/providers/", StringComparison.OrdinalIgnoreCase);
        if (groupIndex >= 0 && providerIndex > groupIndex)
        {
            resourceGroup = id[(groupIndex + groupMarker.Length)..providerIndex];
        }

        return new VaultResource
        {
            Id = id,
            Name = name,
            Location = GetString(resource, "location") ?? string.Empty,
            ResourceGroup = resourceGroup,
            Tags = tags,
        };
    }

    /// <summary>Returns a tag value without normalization; parsed ARM tag dictionaries compare names case-insensitively.</summary>
    private static string? GetTag(VaultResource resource, string name)
    {
        return resource.Tags.TryGetValue(name, out var value) ? value : null;
    }

    /// <summary>Reads only JSON string properties, returning null for missing properties or other value kinds.</summary>
    private static string? GetString(JsonElement element, string propertyName)
    {
        return element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(propertyName, out var value)
            && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }

    /// <summary>Removes surrounding whitespace and trailing slashes; callers supply case-insensitive comparison.</summary>
    private static string NormalizeId(string resourceId) => resourceId.Trim().TrimEnd('/');

    private sealed record PairDeclaration(VaultResource Source, string TargetId);

    private sealed class PairDeclarationComparer : IEqualityComparer<PairDeclaration>
    {
        public static PairDeclarationComparer Instance { get; } = new();

        public bool Equals(PairDeclaration? left, PairDeclaration? right)
        {
            return left is not null
                && right is not null
                && NormalizeId(left.Source.Id).Equals(NormalizeId(right.Source.Id), StringComparison.OrdinalIgnoreCase)
                && NormalizeId(left.TargetId).Equals(NormalizeId(right.TargetId), StringComparison.OrdinalIgnoreCase);
        }

        public int GetHashCode(PairDeclaration declaration)
        {
            return HashCode.Combine(
                StringComparer.OrdinalIgnoreCase.GetHashCode(NormalizeId(declaration.Source.Id)),
                StringComparer.OrdinalIgnoreCase.GetHashCode(NormalizeId(declaration.TargetId)));
        }
    }

    /// <summary>Performs a lightweight subscription-prefix and vault-suffix shape check on a configured target ID.</summary>
    /// <remarks>This is not a full ARM identifier parser, subscription GUID validator, or existence/permission check.</remarks>
    private static bool TryValidateKeyVaultResourceId(string resourceId, out string error)
    {
        var segments = resourceId.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var valid = resourceId.StartsWith("/subscriptions/", StringComparison.OrdinalIgnoreCase)
            && segments.Length >= 8
            && segments[^3].Equals("Microsoft.KeyVault", StringComparison.OrdinalIgnoreCase)
            && segments[^2].Equals("vaults", StringComparison.OrdinalIgnoreCase);
        error = valid ? string.Empty : "Expected a full ARM ID ending in /providers/Microsoft.KeyVault/vaults/{name}.";
        return valid;
    }

    /// <summary>Extracts the ARM error message for diagnostics, falling back when the response is not recognized JSON.</summary>
    /// <remarks>The service message is retained; this helper is not a general-purpose redactor for response content.</remarks>
    private static string ExtractArmError(string content)
    {
        try
        {
            using var document = JsonDocument.Parse(content);
            return GetString(document.RootElement.GetProperty("error"), "message") ?? "Unknown ARM error.";
        }
        catch
        {
            return "The response body was not valid ARM error JSON.";
        }
    }

    /// <summary>Formats a compact issue description without a stack trace; the exception message is not sanitized.</summary>
    private static string SafeError(Exception exception) => exception.GetType().Name + ": " + exception.Message;
}
