namespace KeyVaultSync.Runner;

/// <summary>Holds the environment configuration consumed by the timer Function.</summary>
/// <remarks>
/// <para>Use <see cref="Parse"/> to validate the Function App settings.
/// An enabled source/target mapping is the runtime opt-in for supported synchronization operations.</para>
/// <para>Unmapped vaults are not synchronized. Never log this record wholesale: it contains the configured HMAC key.</para>
/// </remarks>
internal sealed record RunnerOptions
{
    /// <summary>Gets the distinct subscriptions whose Key Vault resources are enumerated as one complete discovery graph.</summary>
    public required IReadOnlyList<string> SubscriptionIds { get; init; }
    /// <summary>Gets the HTTPS Blob service endpoint used for state, leases, and run history, not a container URI.</summary>
    public required Uri StorageAccountUri { get; init; }
    /// <summary>Gets the Blob container for per-pair state and cooperative writer leases.</summary>
    public string StateContainer { get; init; } = "keyvaultsync-state";
    /// <summary>Gets the Blob container for dated run records, separate from mutable pair state.</summary>
    public string RunsContainer { get; init; } = "keyvaultsync-runs";
    /// <summary>Gets protected Base64 HMAC key material supplied only through the environment; never log it.</summary>
    /// <remarks>The HMAC service, not the option parser, validates decoding and the exact 32-byte length.</remarks>
    public string? HmacKeyBase64 { get; init; }
    /// <summary>Gets the non-secret key-version label persisted with baselines to detect incompatible key changes.</summary>
    public string HmacKeyVersion { get; init; } = "app-config-v1";
    /// <summary>Gets the runtime managed identity object ID used to prevent self-revocation during RBAC cleanup.</summary>
    public string? SyncPrincipalId { get; init; }
    /// <summary>Resolves Function App configuration and rejects invalid or retired settings.</summary>
    /// <param name="args">Must be empty. Runtime configuration is environment-only.</param>
    /// <returns>Validated options; supported writes are selected by an enabled source/target mapping.</returns>
    /// <exception cref="ArgumentException">A required value is missing/invalid, or a retired runtime gate is present.</exception>
    /// <remarks>
    /// Subscription IDs accept comma, semicolon, or whitespace separators. HMAC material is never accepted as an argument.
    /// </remarks>
    public static RunnerOptions Parse(string[] args)
    {
        foreach (var retiredSetting in new[]
        {
            "KEYVAULTSYNC_APPLY_SECRETS",
            "KEYVAULTSYNC_SEED_MISSING_KEYS_AND_CERTIFICATES",
            "KEYVAULTSYNC_SINGLE_WRITER_MODE",
        })
        {
            if (Environment.GetEnvironmentVariable(retiredSetting) is not null)
            {
                throw new ArgumentException(
                    $"{retiredSetting} is no longer supported. Remove it; an enabled source/target mapping automatically enables supported synchronization operations.");
            }
        }

        if (args.Length != 0)
        {
            throw new ArgumentException("Command-line configuration is no longer supported. Configure the Azure Function through application settings.");
        }

        foreach (var retiredSetting in new[]
        {
            "AZURE_SUBSCRIPTION_ID",
            "KEYVAULTSYNC_RESOURCE_GROUP",
            "KEYVAULTSYNC_PAIR_TAG",
            "KEYVAULTSYNC_REBASELINE",
        })
        {
            if (Environment.GetEnvironmentVariable(retiredSetting) is not null)
            {
                throw new ArgumentException($"{retiredSetting} is no longer supported. Use KEYVAULTSYNC_SUBSCRIPTIONS and target-side sync-source-keyvault-id mappings.");
            }
        }

        var subscriptionIds = ParseSubscriptionIds(Environment.GetEnvironmentVariable("KEYVAULTSYNC_SUBSCRIPTIONS"));
        var storageUriText = Environment.GetEnvironmentVariable("KEYVAULTSYNC_STORAGE_ACCOUNT_URI")
            ?? throw new ArgumentException("KEYVAULTSYNC_STORAGE_ACCOUNT_URI is required.");
        if (!Uri.TryCreate(storageUriText, UriKind.Absolute, out var storageUri) || storageUri.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("KEYVAULTSYNC_STORAGE_ACCOUNT_URI must be an HTTPS Blob service URI.");
        }

        // Keep key material out of shell history and process arguments. Secret writes are blocked
        // by the planner when the key is absent; its version label is a baseline compatibility marker.
        var hmacKeyBase64 = Environment.GetEnvironmentVariable("KEYVAULTSYNC_HMAC_KEY");
        var hmacKeyVersion = Environment.GetEnvironmentVariable("KEYVAULTSYNC_HMAC_KEY_VERSION") ?? "app-config-v1";
        var syncPrincipalId = Environment.GetEnvironmentVariable("KEYVAULTSYNC_PRINCIPAL_ID");
        if (!string.IsNullOrWhiteSpace(syncPrincipalId) && !Guid.TryParse(syncPrincipalId, out _))
        {
            throw new ArgumentException("KEYVAULTSYNC_PRINCIPAL_ID must be a Microsoft Entra object GUID when configured.");
        }

        return new RunnerOptions
        {
            SubscriptionIds = subscriptionIds,
            StorageAccountUri = storageUri,
            StateContainer = Environment.GetEnvironmentVariable("KEYVAULTSYNC_STATE_CONTAINER") ?? "keyvaultsync-state",
            RunsContainer = Environment.GetEnvironmentVariable("KEYVAULTSYNC_RUNS_CONTAINER") ?? "keyvaultsync-runs",
            HmacKeyBase64 = hmacKeyBase64,
            HmacKeyVersion = hmacKeyVersion,
            SyncPrincipalId = syncPrincipalId,
        };
    }

    private static IReadOnlyList<string> ParseSubscriptionIds(string? configuredValue)
    {
        if (string.IsNullOrWhiteSpace(configuredValue))
        {
            throw new ArgumentException("KEYVAULTSYNC_SUBSCRIPTIONS is required.");
        }

        var subscriptionIds = configuredValue
            .Split([',', ';', ' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (subscriptionIds.Length == 0 || subscriptionIds.Any(subscriptionId => !Guid.TryParse(subscriptionId, out _)))
        {
            throw new ArgumentException("KEYVAULTSYNC_SUBSCRIPTIONS must contain one or more Azure subscription GUIDs separated by commas, semicolons, or whitespace.");
        }

        return subscriptionIds;
    }
}
