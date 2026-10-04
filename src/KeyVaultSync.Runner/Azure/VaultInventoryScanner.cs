using System.Security.Cryptography;
using System.Diagnostics;
using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Logging;

namespace KeyVaultSync.Runner.Azure;

/// <summary>Builds a value-free inventory; secret values are fetched only by an explicitly enabled executor.</summary>
/// <param name="credential">Credential for data-plane list/metadata reads; Key Vault authorization is configured separately.</param>
/// <param name="arm">Reader for ARM authorization declarations added to the inventory.</param>
/// <param name="logger">Logger for per-stage progress, per-key discovery, and metadata diagnostics.</param>
/// <remarks>
/// Sequential SDK calls are observations, not an atomic vault snapshot. Secret values, private key material,
/// and certificate private payloads are never fetched here. Public key/certificate metadata can be read.
/// Warnings are part of the result contract and must not be discarded when planning or advancing checkpoints.
/// </remarks>
internal sealed class VaultInventoryScanner(TokenCredential credential, ArmResourceClient arm, ILogger<VaultInventoryScanner> logger)
{
    private const int ProgressLogInterval = 25;
    private static readonly EventId InventoryStageStartedEventId = new(2000, "InventoryStageStarted");
    private static readonly EventId InventoryStageCompletedEventId = new(2001, "InventoryStageCompleted");
    private static readonly EventId InventoryProgressEventId = new(2002, "InventoryProgress");
    private static readonly EventId KeyVaultKeyDiscoveredEventId = new(2100, "KeyVaultKeyDiscovered");

    /// <summary>Collects active names/versions, soft-deleted names, and authorization observations for one vault.</summary>
    /// <param name="vault">ARM identity used to construct the public-cloud data-plane endpoint and diagnostic context.</param>
    /// <param name="cancellationToken">Cancellation passed to SDK and ARM reads.</param>
    /// <returns>An observed inventory that may carry completeness warnings even when this task succeeds.</returns>
    /// <remarks>
    /// Active-list failures generally propagate and fail the scan. Selected certificate metadata and deleted-list
    /// failures instead preserve partial results with warnings. Authorization warnings are included in the same
    /// aggregate list, preventing a warning-bearing result from becoming a complete-scan checkpoint.
    /// </remarks>
    public async Task<VaultInventory> ScanAsync(VaultResource vault, CancellationToken cancellationToken)
    {
        using var activity = RunnerTelemetry.ActivitySource.StartActivity("keyvault.inventory");
        var timer = Stopwatch.StartNew();
        activity?.SetTag("vault.name", vault.Name);
        activity?.SetTag("cloud.region", vault.Location);
        logger.LogInformation("Key Vault inventory started for {VaultName} in {Region}.", vault.Name, vault.Location);

        var vaultUri = BuildVaultUri(vault.Id);
        var secretClient = new SecretClient(vaultUri, credential);
        var keyClient = new KeyClient(vaultUri, credential);
        var certificateClient = new CertificateClient(vaultUri, credential);
        var warnings = new List<string>();

        try
        {
            // Read every supported surface before planning. In particular, a missing active name
            // is not available for creation when it exists in the corresponding soft-deleted list.
            var secrets = await TraceStageAsync("keyvault.inventory.secrets", vault.Name,
                () => ScanSecretsAsync(vault.Name, secretClient, warnings, cancellationToken), result => result.Count);
            var keys = await TraceStageAsync("keyvault.inventory.keys", vault.Name,
                () => ScanKeysAsync(vault.Name, keyClient, warnings, cancellationToken), result => result.Count);
            var certificates = await TraceStageAsync("keyvault.inventory.certificates", vault.Name,
                () => ScanCertificatesAsync(vault.Name, certificateClient, warnings, cancellationToken), result => result.Count);
            var deletedSecretNames = await TraceStageAsync("keyvault.inventory.deleted-secrets", vault.Name,
                () => ListDeletedSecretsAsync(vault.Name, secretClient, warnings, cancellationToken), result => result.Count);
            var deletedKeyNames = await TraceStageAsync("keyvault.inventory.deleted-keys", vault.Name,
                () => ListDeletedKeysAsync(vault.Name, keyClient, warnings, cancellationToken), result => result.Count);
            var deletedCertificateNames = await TraceStageAsync("keyvault.inventory.deleted-certificates", vault.Name,
                () => ListDeletedCertificatesAsync(vault.Name, certificateClient, warnings, cancellationToken), result => result.Count);
            var vaultAuthorization = await TraceStageAsync("keyvault.inventory.authorization", vault.Name,
                () => arm.GetAuthorizationAsync(vault.Id, cancellationToken),
                result => result.AccessPolicies.Count + result.RoleAssignments.Count);
            var objectAssignments = new List<RoleAssignmentSummary>();
            var authorizationWarnings = vaultAuthorization.Warnings.ToList();
            foreach (var scope in secrets.Select(secret => $"{vault.Id}/secrets/{Uri.EscapeDataString(secret.Name)}")
                         .Concat(keys.Select(key => $"{vault.Id}/keys/{Uri.EscapeDataString(key.Name)}")))
            {
                try
                {
                    objectAssignments.AddRange(await arm.ListDirectRoleAssignmentsAsync(scope, cancellationToken));
                }
                catch (Exception exception)
                {
                    authorizationWarnings.Add(
                        $"Object role-assignment inventory is incomplete: {exception.GetType().Name}.");
                    logger.LogWarning(exception,
                        "Object role-assignment inventory is incomplete for one {VaultName} child scope.",
                        vault.Name);
                }
            }

            var authorization = vaultAuthorization with
            {
                // Object-scope queries repeat the vault-scope rows their scope inherits from.
                RoleAssignments = vaultAuthorization.RoleAssignments.Concat(objectAssignments)
                    .DistinctBy(assignment => assignment.Id, StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                Warnings = authorizationWarnings,
            };
            warnings.AddRange(authorization.Warnings);

            activity?.SetTag("inventory.secret_count", secrets.Count);
            activity?.SetTag("inventory.key_count", keys.Count);
            activity?.SetTag("inventory.certificate_count", certificates.Count);
            activity?.SetTag("inventory.warning_count", warnings.Count);
            var inventory = new VaultInventory
            {
                VaultId = vault.Id,
                VaultName = vault.Name,
                Region = vault.Location,
                Authorization = authorization,
                Secrets = secrets,
                Keys = keys,
                Certificates = certificates,
                DeletedSecretNames = deletedSecretNames,
                DeletedKeyNames = deletedKeyNames,
                DeletedCertificateNames = deletedCertificateNames,
                Warnings = warnings,
            };

            if (warnings.Count == 0)
            {
                activity?.SetStatus(ActivityStatusCode.Ok);
            }
            else
            {
                activity?.SetStatus(ActivityStatusCode.Error, "Partial inventory");
            }

            logger.LogInformation(
                "Key Vault inventory finished for {VaultName}: {SecretCount} secrets, {KeyCount} keys, {CertificateCount} certificates, {WarningCount} warnings.",
                vault.Name, secrets.Count, keys.Count, certificates.Count, warnings.Count);
            return inventory;
        }
        catch (Exception exception)
        {
            RunnerTelemetry.RecordException(activity, exception);
            activity?.SetStatus(ActivityStatusCode.Error, exception.GetType().Name);
            RunnerTelemetry.Failures.Add(1, new("sync.stage", "keyvault.inventory"), new("error.type", exception.GetType().Name));
            logger.LogError(exception, "Key Vault inventory failed for {VaultName}.", vault.Name);
            throw;
        }
        finally
        {
            timer.Stop();
            activity?.SetTag("inventory.duration_ms", timer.Elapsed.TotalMilliseconds);
        }
    }

    /// <summary>Wraps an inventory operation with stage timing, activity status, and optional item counts.</summary>
    /// <typeparam name="T">The stage's result type; the wrapper returns it unchanged.</typeparam>
    /// <param name="stage">Stable activity/stage name used to identify the type of inventory work.</param>
    /// <param name="vaultName">Non-secret resource name for diagnostic correlation.</param>
    /// <param name="operation">The asynchronous read operation, including its captured cancellation token.</param>
    /// <param name="getItemCount">Optional projection for the stage's count, not a completeness assertion.</param>
    /// <returns>The operation's result without changing any embedded warnings.</returns>
    /// <remarks>A successful task marks this stage OK even when its result is partial; ScanAsync evaluates aggregate warnings.</remarks>
    private async Task<T> TraceStageAsync<T>(string stage, string vaultName, Func<Task<T>> operation, Func<T, int>? getItemCount = null)
    {
        using var activity = RunnerTelemetry.ActivitySource.StartActivity(stage);
        var timer = Stopwatch.StartNew();
        activity?.SetTag("vault.name", vaultName);
        logger.LogDebug(InventoryStageStartedEventId,
            "Key Vault inventory stage started. {KeyVaultName}; {StageName}.", vaultName, stage);
        try
        {
            var result = await operation();
            timer.Stop();
            var itemCount = getItemCount?.Invoke(result);
            activity?.SetTag("stage.duration_ms", timer.Elapsed.TotalMilliseconds);
            activity?.SetTag("stage.item_count", itemCount);
            activity?.SetStatus(ActivityStatusCode.Ok);
            logger.LogInformation(InventoryStageCompletedEventId,
                "Key Vault inventory stage completed. {KeyVaultName}; {StageName}; {ItemCount} items; {DurationMs} ms.",
                vaultName, stage, itemCount, timer.Elapsed.TotalMilliseconds);
            return result;
        }
        catch (Exception exception)
        {
            timer.Stop();
            activity?.SetTag("stage.duration_ms", timer.Elapsed.TotalMilliseconds);
            RunnerTelemetry.RecordException(activity, exception);
            activity?.SetStatus(ActivityStatusCode.Error, exception.GetType().Name);
            logger.LogError(exception, "Key Vault inventory stage {Stage} failed for {VaultName}.", stage, vaultName);
            throw;
        }
    }

    /// <summary>Lists secret properties and version properties without calling GetSecret or retrieving any secret value.</summary>
    /// <remarks>
    /// Uses creation timestamps to infer the latest version and records a warning when the inference fails.
    /// Name-level metadata and version metadata come from separate reads; apply must re-read the selected version.
    /// Results are sorted by name for stable plans and reports, not to establish service version order.
    /// </remarks>
    private async Task<IReadOnlyList<SecretSummary>> ScanSecretsAsync(
        string vaultName,
        SecretClient client,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        var secrets = new List<SecretSummary>();
        var versionsProcessed = 0;
        await foreach (var secret in client.GetPropertiesOfSecretsAsync(cancellationToken))
        {
            var versions = new List<ObjectVersionSummary>();
            await foreach (var version in client.GetPropertiesOfSecretVersionsAsync(secret.Name, cancellationToken))
            {
                versionsProcessed++;
                LogInventoryProgress(vaultName, "secret-versions", versionsProcessed);
                logger.LogTrace("Inventoried secret version metadata. {KeyVaultName}; {SecretName}; version {Version}; enabled {Enabled}.",
                    vaultName, secret.Name, version.Version, version.Enabled);
                versions.Add(new ObjectVersionSummary
                {
                    Version = version.Version ?? string.Empty,
                    CreatedOn = version.CreatedOn,
                    UpdatedOn = version.UpdatedOn,
                    Enabled = version.Enabled,
                });
            }

            // Listing order is not a head guarantee. Do not silently choose an arbitrary version
            // when the newest dated version is ambiguous; preserve the missing-head warning.
            var latestVersion = ResolveLatestVersion(versions);
            if (latestVersion is null)
            {
                warnings.Add($"Secret head version could not be determined for {secret.Name}; version metadata is missing or ambiguous.");
            }

            secrets.Add(new SecretSummary
            {
                Name = secret.Name,
                CurrentVersion = latestVersion ?? string.Empty,
                Versions = versions,
                Enabled = secret.Enabled,
                ContentType = secret.ContentType,
                NotBefore = secret.NotBefore,
                ExpiresOn = secret.ExpiresOn,
                Tags = secret.Tags is null
                    ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    : new Dictionary<string, string>(secret.Tags, StringComparer.OrdinalIgnoreCase),
            });
                    logger.LogDebug("Inventoried secret metadata. {KeyVaultName}; {SecretName}; {VersionCount} versions; current version {CurrentVersion}.",
                    vaultName, secret.Name, versions.Count, latestVersion);
                    LogInventoryProgress(vaultName, "secrets", secrets.Count);
        }

        return secrets.OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    /// <summary>Lists key versions and reads the current public key descriptor and declared operations.</summary>
    /// <remarks>
    /// GetKey returns public metadata, not private key export. Each key name is logged at Information;
    /// per-version details are Trace. A missing head ID becomes a warning, while request failures propagate.
    /// </remarks>
    private async Task<IReadOnlyList<KeySummary>> ScanKeysAsync(
        string vaultName,
        KeyClient client,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        var keys = new List<KeySummary>();
        var versionsProcessed = 0;
        await foreach (var key in client.GetPropertiesOfKeysAsync(cancellationToken))
        {
            logger.LogInformation(
                KeyVaultKeyDiscoveredEventId,
                "Discovered Key Vault key {KeyName} in {KeyVaultName}.",
                key.Name, vaultName);

            var versions = new List<ObjectVersionSummary>();
            await foreach (var version in client.GetPropertiesOfKeyVersionsAsync(key.Name, cancellationToken))
            {
                versionsProcessed++;
                LogInventoryProgress(vaultName, "key-versions", versionsProcessed);
                logger.LogTrace("Inventoried key version metadata. {KeyVaultName}; {KeyName}; version {Version}; enabled {Enabled}.",
                    vaultName, key.Name, version.Version, version.Enabled);
                versions.Add(new ObjectVersionSummary
                {
                    Version = version.Version ?? string.Empty,
                    CreatedOn = version.CreatedOn,
                    UpdatedOn = version.UpdatedOn,
                    Enabled = version.Enabled,
                });
            }

            var currentKey = await client.GetKeyAsync(key.Name, cancellationToken: cancellationToken);
            var operations = currentKey.Value.KeyOperations?
                .Select(operation => operation.ToString())
                .Order(StringComparer.Ordinal)
                .ToArray() ?? [];
            var currentVersion = currentKey.Value.Properties.Version ?? key.Version ?? string.Empty;
            if (currentVersion.Length == 0)
            {
                warnings.Add($"Key head version could not be determined for {key.Name}.");
            }
            else if (!versions.Any(version => string.Equals(version.Version, currentVersion, StringComparison.Ordinal)))
            {
                warnings.Add($"Key version inventory does not contain the observed head for {key.Name}.");
            }

            keys.Add(new KeySummary
            {
                Name = key.Name,
                CurrentVersion = currentVersion,
                Versions = versions,
                KeyType = currentKey.Value.Key.KeyType.ToString(),
                PublicFingerprintSha256 = KeyVaultPublicFingerprint.Compute(currentKey.Value.Key),
                KeyOperations = operations,
                Enabled = currentKey.Value.Properties.Enabled,
                NotBefore = currentKey.Value.Properties.NotBefore,
                ExpiresOn = currentKey.Value.Properties.ExpiresOn,
                Tags = new Dictionary<string, string>(currentKey.Value.Properties.Tags, StringComparer.OrdinalIgnoreCase),
            });
            logger.LogDebug("Key inventory metadata completed. {KeyVaultName}; {KeyName}; key type {KeyType}; {VersionCount} versions; current version {CurrentVersion}; {OperationCount} operations.",
                vaultName, key.Name, currentKey.Value.Key.KeyType, versions.Count, currentVersion, operations.Length);
            LogInventoryProgress(vaultName, "keys", keys.Count);
        }

        return keys.OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    /// <summary>Lists certificate versions and observes current public DER plus backing secret/key references.</summary>
    /// <remarks>
    /// Metadata read failures retain the certificate with a warning and possibly missing backing IDs.
    /// The SHA-256 value describes only public DER; it does not establish private-key equivalence or ownership.
    /// This method never dereferences the backing secret to retrieve a PFX/PEM private payload.
    /// </remarks>
    private async Task<IReadOnlyList<CertificateSummary>> ScanCertificatesAsync(
        string vaultName,
        CertificateClient client,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        var certificates = new List<CertificateSummary>();
        var versionsProcessed = 0;
        await foreach (var certificate in client.GetPropertiesOfCertificatesAsync(false, cancellationToken))
        {
            var versions = new List<ObjectVersionSummary>();
            await foreach (var version in client.GetPropertiesOfCertificateVersionsAsync(certificate.Name, cancellationToken))
            {
                versionsProcessed++;
                LogInventoryProgress(vaultName, "certificate-versions", versionsProcessed);
                logger.LogTrace("Inventoried certificate version metadata. {KeyVaultName}; {CertificateName}; version {Version}; enabled {Enabled}.",
                    vaultName, certificate.Name, version.Version, version.Enabled);
                versions.Add(new ObjectVersionSummary
                {
                    Version = version.Version ?? string.Empty,
                    CreatedOn = version.CreatedOn,
                    UpdatedOn = version.UpdatedOn,
                    Enabled = version.Enabled,
                });
            }

            string? thumbprint = null;
            string? secretId = null;
            string? keyId = null;
            bool? exportable = null;
            bool? enabled = certificate.Enabled;
            DateTimeOffset? notBefore = certificate.NotBefore;
            DateTimeOffset? expiresOn = certificate.ExpiresOn;
            IReadOnlyDictionary<string, string> tags =
                new Dictionary<string, string>(certificate.Tags, StringComparer.OrdinalIgnoreCase);
            var currentVersion = certificate.Version ?? string.Empty;
            try
            {
                var current = await client.GetCertificateAsync(certificate.Name, cancellationToken: cancellationToken);
                currentVersion = current.Value.Properties.Version ?? currentVersion;
                if (current.Value.Cer is { Length: > 0 } certificateDer)
                {
                    // Public-certificate diagnostics only; this is not a secret-value HMAC or a
                    // sufficient precondition for restoring/replacing a certificate group.
                    thumbprint = Convert.ToHexString(SHA256.HashData(certificateDer));
                }

                secretId = current.Value.SecretId?.ToString();
                keyId = current.Value.KeyId?.ToString();
                exportable = current.Value.Policy?.Exportable;
                enabled = current.Value.Properties.Enabled;
                notBefore = current.Value.Properties.NotBefore;
                expiresOn = current.Value.Properties.ExpiresOn;
                tags = new Dictionary<string, string>(current.Value.Properties.Tags, StringComparer.OrdinalIgnoreCase);
            }
            catch (RequestFailedException exception)
            {
                warnings.Add($"Certificate metadata/backing references could not be read for {certificate.Name}: HTTP {exception.Status}.");
                logger.LogWarning(exception, "Could not read certificate metadata or backing references for {VaultName}.", certificate.Name);
            }

            if (currentVersion.Length == 0)
            {
                warnings.Add($"Certificate head version could not be determined for {certificate.Name}.");
            }
            else if (!versions.Any(version => string.Equals(version.Version, currentVersion, StringComparison.Ordinal)))
            {
                warnings.Add($"Certificate version inventory does not contain the observed head for {certificate.Name}.");
            }

            certificates.Add(new CertificateSummary
            {
                Name = certificate.Name,
                CurrentVersion = currentVersion,
                Versions = versions,
                ThumbprintSha256 = thumbprint,
                SecretId = secretId,
                KeyId = keyId,
                Exportable = exportable,
                Enabled = enabled,
                NotBefore = notBefore,
                ExpiresOn = expiresOn,
                Tags = tags,
            });
            logger.LogDebug("Certificate inventory metadata completed. {KeyVaultName}; {CertificateName}; {VersionCount} versions; current version {CurrentVersion}; backing secret present {HasBackingSecret}; backing key present {HasBackingKey}.",
                vaultName, certificate.Name, versions.Count, currentVersion, secretId is not null, keyId is not null);
            LogInventoryProgress(vaultName, "certificates", certificates.Count);
        }

        return certificates.OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    /// <summary>Infers a head only when the latest valid creation timestamp has one distinct version ID.</summary>
    /// <param name="versions">Observed versions; undated entries and blank version IDs are ignored by this heuristic.</param>
    /// <returns>The sole newest dated version, or null when no usable entry exists or newest entries disagree.</returns>
    /// <remarks>This is not a service-side head lookup and cannot compensate for an incomplete version listing.</remarks>
    private static string? ResolveLatestVersion(IReadOnlyList<ObjectVersionSummary> versions)
    {
        var datedVersions = versions
            .Where(version => version.CreatedOn.HasValue && !string.IsNullOrWhiteSpace(version.Version))
            .ToArray();
        if (datedVersions.Length == 0)
        {
            return null;
        }

        var newestCreatedOn = datedVersions.Max(version => version.CreatedOn!.Value);
        var newestVersions = datedVersions
            .Where(version => version.CreatedOn!.Value == newestCreatedOn)
            .Select(version => version.Version)
            .Distinct(StringComparer.Ordinal)
            .Take(2)
            .ToArray();

        return newestVersions.Length == 1 ? newestVersions[0] : null;
    }

    /// <summary>Collects soft-deleted secret names so planning can distinguish an unused name from a deletion conflict.</summary>
    /// <remarks>Request failures append a warning and return names collected so far; an empty list then proves nothing.</remarks>
    private async Task<IReadOnlyList<string>> ListDeletedSecretsAsync(
        string vaultName,
        SecretClient client,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        var names = new List<string>();
        try
        {
            await foreach (var deleted in client.GetDeletedSecretsAsync(cancellationToken))
            {
                names.Add(deleted.Name);
                logger.LogTrace("Discovered soft-deleted secret name. {KeyVaultName}; {SecretName}.", vaultName, deleted.Name);
                LogInventoryProgress(vaultName, "deleted-secrets", names.Count);
            }
        }
        catch (RequestFailedException exception)
        {
            warnings.Add($"Deleted-secret inventory is incomplete: HTTP {exception.Status}.");
            logger.LogWarning(exception, "Deleted-secret inventory is incomplete.");
        }

        return names;
    }

    /// <summary>Collects soft-deleted key names without recovering or purging them.</summary>
    /// <remarks>A failed page preserves prior names and adds a warning rather than reporting a complete empty inventory.</remarks>
    private async Task<IReadOnlyList<string>> ListDeletedKeysAsync(
        string vaultName,
        KeyClient client,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        var names = new List<string>();
        try
        {
            await foreach (var deleted in client.GetDeletedKeysAsync(cancellationToken))
            {
                names.Add(deleted.Name);
                logger.LogTrace("Discovered soft-deleted key name. {KeyVaultName}; {KeyName}.", vaultName, deleted.Name);
                LogInventoryProgress(vaultName, "deleted-keys", names.Count);
            }
        }
        catch (RequestFailedException exception)
        {
            warnings.Add($"Deleted-key inventory is incomplete: HTTP {exception.Status}.");
            logger.LogWarning(exception, "Deleted-key inventory is incomplete.");
        }

        return names;
    }

    /// <summary>Collects soft-deleted certificate names for certificate-group collision checks.</summary>
    /// <remarks>Request failures preserve partial names and add warnings; no private certificate payload is read.</remarks>
    private async Task<IReadOnlyList<string>> ListDeletedCertificatesAsync(
        string vaultName,
        CertificateClient client,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        var names = new List<string>();
        try
        {
            await foreach (var deleted in client.GetDeletedCertificatesAsync(false, cancellationToken))
            {
                names.Add(deleted.Name);
                logger.LogTrace("Discovered soft-deleted certificate name. {KeyVaultName}; {CertificateName}.", vaultName, deleted.Name);
                LogInventoryProgress(vaultName, "deleted-certificates", names.Count);
            }
        }
        catch (RequestFailedException exception)
        {
            warnings.Add($"Deleted-certificate inventory is incomplete: HTTP {exception.Status}.");
            logger.LogWarning(exception, "Deleted-certificate inventory is incomplete.");
        }

        return names;
    }

    /// <summary>Logs an Information-level heartbeat every 25 observations in a stage, not on every SDK page.</summary>
    /// <remarks>Object and version totals are separate progress counters; the final stage event reports the final count.</remarks>
    private void LogInventoryProgress(string vaultName, string stageName, int itemsProcessed)
    {
        if (itemsProcessed > 0 && itemsProcessed % ProgressLogInterval == 0)
        {
            logger.LogInformation(InventoryProgressEventId,
                "Key Vault inventory is progressing. {KeyVaultName}; {StageName}; {ItemsProcessed} items processed.",
                vaultName, stageName, itemsProcessed);
        }
    }

    /// <summary>Derives a public Azure Key Vault HTTPS endpoint from the final segment of an ARM resource ID.</summary>
    /// <remarks>The suffix is fixed to vault.azure.net; sovereign-cloud endpoint discovery is not implemented here.</remarks>
    internal static Uri BuildVaultUri(string resourceId)
    {
        var vaultName = resourceId.Split('/', StringSplitOptions.RemoveEmptyEntries).Last();
        return new Uri($"https://{vaultName}.vault.azure.net/");
    }
}
