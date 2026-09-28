namespace KeyVaultSync.Runner;

/// <summary>Holds the configuration shared by the console host and the timer Function.</summary>
/// <remarks>
/// <para>Use <see cref="Parse"/> to apply command-line/environment precedence and validate configuration.
/// An enabled source/target mapping is the runtime opt-in for supported synchronization operations.</para>
/// <para>Unmapped vaults are not synchronized. Never log this record wholesale: it contains the configured HMAC key.</para>
/// </remarks>
internal sealed record RunnerOptions
{
    /// <summary>Gets the subscription whose ARM Key Vault resources are enumerated for source discovery.</summary>
    public required string SubscriptionId { get; init; }
    /// <summary>Gets the HTTPS Blob service endpoint used for state, leases, and run history, not a container URI.</summary>
    public required Uri StorageAccountUri { get; init; }
    /// <summary>Gets the optional source resource-group filter; null means all discovered resource groups.</summary>
    public string? ResourceGroup { get; init; }
    /// <summary>Gets the source ARM tag whose value is the target Key Vault's full resource ID.</summary>
    public string PairTag { get; init; } = "sync-vault-id";
    /// <summary>Gets the Blob container for per-pair state and cooperative writer leases.</summary>
    public string StateContainer { get; init; } = "keyvaultsync-state";
    /// <summary>Gets the Blob container for dated run records, separate from mutable pair state.</summary>
    public string RunsContainer { get; init; } = "keyvaultsync-runs";
    /// <summary>Gets protected Base64 HMAC key material supplied only through the environment; never log it.</summary>
    /// <remarks>The HMAC service, not the option parser, validates decoding and the exact 32-byte length.</remarks>
    public string? HmacKeyBase64 { get; init; }
    /// <summary>Gets the non-secret key-version label persisted with baselines to detect incompatible key changes.</summary>
    public string HmacKeyVersion { get; init; } = "app-config-v1";
    /// <summary>Gets the positive console watch interval in minutes; it does not configure the Function timer.</summary>
    public int IntervalMinutes { get; init; } = 10;
    /// <summary>Gets whether the console repeats cycles; the Function always invokes one cycle per trigger.</summary>
    public bool Watch { get; init; }

    /// <summary>Resolves host configuration and rejects invalid or retired runtime-gate settings.</summary>
    /// <param name="args">Console arguments, or an empty array for environment-only Function configuration.</param>
    /// <returns>Validated options; supported writes are selected by an enabled source/target mapping.</returns>
    /// <exception cref="ArgumentException">A required value is missing/invalid, or a retired runtime gate is present.</exception>
    /// <remarks>
    /// Value options prefer the command line to the environment. HMAC material is never a CLI option.
    /// <c>--help</c> prints usage and exits the process. Unrecognized positional arguments are ignored;
    /// unrecognized long options still consume a following value but are not otherwise validated.
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

        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var switches = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < args.Length; index++)
        {
            var current = args[index];
            if (!current.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            if (current.Equals("--apply-secrets", StringComparison.OrdinalIgnoreCase)
                || current.Equals("--seed-missing-keys-and-certificates", StringComparison.OrdinalIgnoreCase)
                || current.Equals("--single-writer-mode", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    $"{current} is no longer supported. An enabled source/target mapping automatically enables supported synchronization operations.");
            }

            if (current is "--watch" or "--help")
            {
                switches.Add(current);
                continue;
            }

            if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Expected a value after {current}.");
            }

            values[current] = args[++index];
        }

        if (switches.Contains("--help"))
        {
            PrintUsage();
            Environment.Exit(0);
        }

        var subscriptionId = Get(values, "--subscription", "AZURE_SUBSCRIPTION_ID")
            ?? throw new ArgumentException("--subscription (or AZURE_SUBSCRIPTION_ID) is required.");
        var storageUriText = Get(values, "--storage-account-uri", "KEYVAULTSYNC_STORAGE_ACCOUNT_URI")
            ?? throw new ArgumentException("--storage-account-uri (or KEYVAULTSYNC_STORAGE_ACCOUNT_URI) is required.");
        var intervalText = Get(values, "--interval-minutes", "KEYVAULTSYNC_INTERVAL_MINUTES") ?? "10";
        if (!int.TryParse(intervalText, out var intervalMinutes) || intervalMinutes < 1)
        {
            throw new ArgumentException("--interval-minutes must be a positive integer.");
        }

        if (!Uri.TryCreate(storageUriText, UriKind.Absolute, out var storageUri) || storageUri.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("--storage-account-uri must be an HTTPS Blob service URI.");
        }

        // Keep key material out of shell history and process arguments. Secret writes are blocked
        // by the planner when the key is absent; its version label is a baseline compatibility marker.
        var hmacKeyBase64 = Environment.GetEnvironmentVariable("KEYVAULTSYNC_HMAC_KEY");
        var hmacKeyVersion = Environment.GetEnvironmentVariable("KEYVAULTSYNC_HMAC_KEY_VERSION") ?? "app-config-v1";

        return new RunnerOptions
        {
            SubscriptionId = subscriptionId,
            StorageAccountUri = storageUri,
            ResourceGroup = NullIfWhiteSpace(Get(values, "--resource-group", "KEYVAULTSYNC_RESOURCE_GROUP")),
            PairTag = Get(values, "--pair-tag", "KEYVAULTSYNC_PAIR_TAG") ?? "sync-vault-id",
            StateContainer = Get(values, "--state-container", "KEYVAULTSYNC_STATE_CONTAINER") ?? "keyvaultsync-state",
            RunsContainer = Get(values, "--runs-container", "KEYVAULTSYNC_RUNS_CONTAINER") ?? "keyvaultsync-runs",
            HmacKeyBase64 = hmacKeyBase64,
            HmacKeyVersion = hmacKeyVersion,
            IntervalMinutes = intervalMinutes,
            Watch = switches.Contains("--watch"),
        };
    }

    /// <summary>Writes console usage without starting Azure work or displaying configured secret material.</summary>
    /// <remarks>Mapped pairs automatically run supported guarded secret sync and eligible one-time native seeds.</remarks>
    public static void PrintUsage()
    {
        Console.WriteLine("KeyVaultSync local runner (enabled mappings are automatic synchronization opt-ins)");
        Console.WriteLine();
        Console.WriteLine("  dotnet run --project src/KeyVaultSync.Runner -- [options]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --subscription <id>                 Azure subscription to inventory");
        Console.WriteLine("  --resource-group <name>             Optional resource-group filter");
        Console.WriteLine("  --storage-account-uri <https-uri>   Blob endpoint for state and run history");
        Console.WriteLine("  --pair-tag <tag>                    Source-to-target ARM ID tag (default sync-vault-id)");
        Console.WriteLine("  --watch                             Repeat scans every --interval-minutes");
        Console.WriteLine("  --interval-minutes <n>              Scan interval (default 10)");
        Console.WriteLine("  KEYVAULTSYNC_HMAC_KEY               Protected Base64 256-bit key; required for secret writes");
        Console.WriteLine("  KEYVAULTSYNC_HMAC_KEY_VERSION       Non-secret version label for the configured HMAC key");
        Console.WriteLine();
        Console.WriteLine("An enabled sync-vault-id or sync-source-keyvault-id mapping automatically opts that pair into guarded secret sync");
        Console.WriteLine("and eligible one-time key/certificate-group seeds. Seeds are not recurring rotation.");
        Console.WriteLine("Configure the runner as the sole writer to target objects; no runtime acknowledgment switch is provided.");
        Console.WriteLine("  --help                              Show this help");
        Console.WriteLine();
        Console.WriteLine("Azure auth: DefaultAzureCredential; AZURE_CLIENT_ID selects the hosted user-assigned identity, and local runs can use az login.");
    }

    /// <summary>Returns an explicitly supplied CLI value before consulting its environment fallback.</summary>
    /// <remarks>Empty values are preserved; only settings that explicitly normalize them treat them as missing.</remarks>
    private static string? Get(IReadOnlyDictionary<string, string?> values, string option, string environmentVariable)
    {
        return values.TryGetValue(option, out var value) ? value : Environment.GetEnvironmentVariable(environmentVariable);
    }

    /// <summary>Maps a blank resource-group setting to an unfiltered scan without trimming nonblank names.</summary>
    private static string? NullIfWhiteSpace(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
}
