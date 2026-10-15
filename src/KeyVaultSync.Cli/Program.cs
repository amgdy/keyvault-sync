using Azure.Identity;
using KeyVaultSync.Runner;
using Microsoft.Extensions.Logging;

// Terminal host: runs exactly one synchronization cycle with the same RunnerApplication the timer Function uses,
// streaming structured Serilog logs to the console and, by default, to a per-run compact JSON (CLEF) file. It adds no scheduling, retries, or alternate mutation path; pair Blob
// leases still make an overlapping Function invocation skip the locked pair rather than write concurrently.

const int ExitSucceeded = 0;
const int ExitFailed = 1;
const int ExitNeedsAttention = 2;
const int ExitUsage = 3;
const int ExitCancelled = 130;

TerminalArguments arguments;
try
{
    arguments = TerminalConfiguration.ParseArguments(args);
}
catch (ArgumentException exception)
{
    Console.Error.WriteLine(exception.Message);
    Console.Error.WriteLine("Run with --help for usage.");
    return ExitUsage;
}

if (arguments.ShowHelp)
{
    PrintUsage();
    return ExitSucceeded;
}

TerminalConfigurationReport configuration;
try
{
    configuration = TerminalConfiguration.Apply(
        arguments,
        Directory.GetCurrentDirectory(),
        Environment.GetEnvironmentVariable,
        (name, value) => Environment.SetEnvironmentVariable(name, value));
}
catch (Exception exception) when (exception is ArgumentException or FileNotFoundException or InvalidDataException or IOException or UnauthorizedAccessException)
{
    Console.Error.WriteLine($"[KVS-CONFIG-SOURCE] Could not load configuration: {exception.Message}");
    return ExitUsage;
}

if (configuration.MissingRequiredSettings.Count > 0)
{
    Console.Error.WriteLine($"""
        [KVS-CONFIG-MISSING] Missing required settings: {string.Join(", ", configuration.MissingRequiredSettings)}.
        Provide them in one of these ways:
          1. Run from the repository after 'azd provision' (or pass --azd-env <name>) to reuse the deployment's
             state storage account, subscriptions, and HMAC key. No deployed Function App is required.
          2. Pass --settings <local.settings.json>.
          3. Pass --subscriptions <ids> --storage-account-uri <https://account.blob.core.windows.net/>, and supply
             the HMAC key with --hmac-key-file <path> or KEYVAULTSYNC_HMAC_KEY.
        """);
    return ExitUsage;
}

// Same chain as the Function host: Azure CLI / developer sign-in locally, AZURE_CLIENT_ID selects a managed identity.
var credential = new DefaultAzureCredential();
TelemetryRuntime telemetryRuntime;
try
{
    telemetryRuntime = TelemetryRuntime.Configure(
        Environment.GetEnvironmentVariable("APPLICATIONINSIGHTS_CONNECTION_STRING"),
        credential,
        new TelemetryLogOptions
        {
            ConsoleFormat = arguments.ConsoleFormat,
            FilePath = TerminalConfiguration.ResolveLogFilePath(arguments, Directory.GetCurrentDirectory(), DateTimeOffset.UtcNow),
        });
}
catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
{
    Console.Error.WriteLine($"[KVS-LOG-FILE] Could not create the log file: {exception.Message} Use --log-file <path> or --no-log-file.");
    return ExitUsage;
}

using var telemetry = telemetryRuntime;
var logger = telemetry.LoggerFactory.CreateLogger("KeyVaultSync.Cli");

// Names only; values (including the HMAC key) are never written to the console.
if (configuration.ArgumentSettingNames.Count > 0)
{
    logger.LogInformation("Applied {SettingCount} settings from arguments: {SettingNames}.",
        configuration.ArgumentSettingNames.Count, configuration.ArgumentSettingNames);
}

if (arguments.SettingsPath is not null)
{
    logger.LogInformation("Loaded {SettingCount} settings from {SettingsPath} without overriding the environment: {SettingNames}.",
        configuration.SettingsFileSettingNames.Count, arguments.SettingsPath, configuration.SettingsFileSettingNames);
}

if (configuration.AzdEnvironmentName is not null)
{
    logger.LogInformation("Imported {SettingCount} runner settings from azd environment {AzdEnvironment} without overriding the environment: {SettingNames}.",
        configuration.AzdSettingNames.Count, configuration.AzdEnvironmentName, configuration.AzdSettingNames);
    if (configuration.AzdNetworkProfile?.StartsWith("private", StringComparison.OrdinalIgnoreCase) == true)
    {
        logger.LogWarning("azd environment {AzdEnvironment} uses network profile {NetworkProfile}; its state storage account disables public access, so this terminal must run on a network with private endpoint access.",
            configuration.AzdEnvironmentName, configuration.AzdNetworkProfile);
    }
}

if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("KEYVAULTSYNC_HMAC_KEY")))
{
    logger.LogWarning("KEYVAULTSYNC_HMAC_KEY is not set; secret and certificate writes will be blocked. Planning and RBAC work still run.");
}

if (!await ResolveRunningPrincipalAsync(credential, logger))
{
    return 3;
}

logger.LogInformation("Logging at {MinimumLogLevel} to the console ({ConsoleLogFormat}) and {LogFileTarget}; Azure Monitor export {AzureMonitorEnabled}.",
    telemetry.MinimumLogLevel, arguments.ConsoleFormat, telemetry.LogFilePath ?? "no file", telemetry.AzureMonitorEnabled ? "enabled" : "disabled");

RunnerApplication runner;
try
{
    runner = new RunnerApplication(credential, telemetry.LoggerFactory);
}
catch (ArgumentException exception)
{
    logger.LogError("Configuration is invalid: {ConfigurationError}", exception.Message);
    return ExitUsage;
}

// The first Ctrl+C requests cooperative cancellation so in-flight writes can finish their verification and
// state bookkeeping. A second Ctrl+C falls through to the default handler and terminates the process.
using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    if (cancellation.IsCancellationRequested)
    {
        return;
    }

    eventArgs.Cancel = true;
    logger.LogWarning("Cancellation requested; finishing the current step. Press Ctrl+C again to terminate immediately.");
    cancellation.Cancel();
};

try
{
    var result = await runner.ExecuteScheduledRunAsync(cancellation.Token);
    var summary = result.Summary;
    logger.LogInformation(
        "Run {RunId} finished with status {RunStatus}: {CompletedPairCount}/{EnabledPairCount} pairs completed, {AttentionPairCount} need attention, {FailedPairCount} failed; {PlanItemCount} plan items, {AttentionItemCount} need attention; {VerifiedObjectChangeCount} object and {VerifiedRbacChangeCount} RBAC changes verified. Run record: {RunRecordUri}",
        result.RunId, result.Status,
        summary.CompletedPairCount, summary.EnabledPairCount, summary.AttentionPairCount, summary.FailedPairCount,
        summary.PlanItemCount, summary.AttentionItemCount,
        summary.VerifiedObjectChangeCount, summary.VerifiedRbacChangeCount,
        result.RunRecordLocation.BlobUri);

    return result.Status switch
    {
        "Complete" or "NoConfiguredPairs" => ExitSucceeded,
        "Failed" => ExitFailed,
        "Cancelled" => ExitCancelled,
        _ => ExitNeedsAttention,
    };
}
catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
{
    logger.LogWarning("Run cancelled.");
    return ExitCancelled;
}
catch (Exception exception)
{
    logger.LogError(exception, "Run failed with {ExceptionType}.", exception.GetType().Name);
    return ExitFailed;
}

// The terminal acts as the signed-in identity, so that identity (not the Function's managed identity) is the one the
// runner must never revoke during target-only RBAC cleanup. Without it, cleanup is blocked rather than unsafe.
// A configured ID that differs from the signed-in identity would protect the wrong principal, so the run stops.
static async Task<bool> ResolveRunningPrincipalAsync(DefaultAzureCredential credential, ILogger logger)
{
    string? signedInObjectId;
    try
    {
        var token = await credential.GetTokenAsync(
            new Azure.Core.TokenRequestContext(["https://management.azure.com/.default"]),
            CancellationToken.None);
        signedInObjectId = AccessTokenClaims.TryGetObjectId(token.Token);
    }
    catch (AuthenticationFailedException exception)
    {
        logger.LogWarning("Could not sign in to resolve the running identity: {AuthenticationError}. Run 'az login' first.", exception.Message);
        return true;
    }

    var configuredPrincipalId = Environment.GetEnvironmentVariable("KEYVAULTSYNC_PRINCIPAL_ID");
    if (string.IsNullOrWhiteSpace(configuredPrincipalId))
    {
        if (signedInObjectId is null)
        {
            logger.LogWarning("Could not read the signed-in object ID; target-only RBAC cleanup stays blocked. Pass --principal-id to enable it.");
            return true;
        }

        Environment.SetEnvironmentVariable("KEYVAULTSYNC_PRINCIPAL_ID", signedInObjectId);
        logger.LogInformation("Running as signed-in principal {PrincipalId}; it is excluded from target-only RBAC cleanup.", signedInObjectId);
    }
    else if (signedInObjectId is not null
        && !(Guid.TryParse(configuredPrincipalId, out var configuredGuid)
            && Guid.TryParse(signedInObjectId, out var signedInGuid)
            && configuredGuid == signedInGuid))
    {
        Console.Error.WriteLine("[KVS-CONFIG-PRINCIPAL] Configuration error: KEYVAULTSYNC_PRINCIPAL_ID differs from the signed-in identity.");
        logger.LogError("KEYVAULTSYNC_PRINCIPAL_ID {ConfiguredPrincipalId} differs from the signed-in principal {PrincipalId}. Target-only RBAC cleanup would protect the wrong identity, so the run stopped. Unset KEYVAULTSYNC_PRINCIPAL_ID (it then defaults to the signed-in identity) or sign in as that principal.",
            configuredPrincipalId, signedInObjectId);
        return false;
    }

    return true;
}

static void PrintUsage()
{
    Console.WriteLine("""
        Runs one KeyVaultSync cycle in the terminal as the signed-in Azure identity and streams its logs.
        It does not call or require a deployed Function App.

        Usage: dotnet run --project src/KeyVaultSync.Cli -- [options]

        Configuration sources (highest precedence first):
          1. Arguments below.
          2. Environment variables already set in the shell.
          3. --settings file.
          4. azd environment: --azd-env <name>, or the default azd environment when --settings is not given.

          -e, --azd-env <name>           Import runner settings (subscriptions, state storage URI, HMAC key, ...)
                                         from .azure/<name>/.env. Only KEYVAULTSYNC_* runner settings are read.
              --no-azd                   Do not look for a default azd environment.
          -s, --settings <path>          Load the "Values" of a Functions local.settings.json file.
              --subscriptions <ids>      KEYVAULTSYNC_SUBSCRIPTIONS (comma-separated subscription GUIDs).
              --storage-account-uri <u>  KEYVAULTSYNC_STORAGE_ACCOUNT_URI (https://<account>.blob.core.windows.net/).
              --hmac-key-file <path>     Read KEYVAULTSYNC_HMAC_KEY from a file. The key is never accepted as an argument.
              --principal-id <guid>      KEYVAULTSYNC_PRINCIPAL_ID. Defaults to the signed-in identity's object ID.
              --state-container <name>   KEYVAULTSYNC_STATE_CONTAINER.
              --runs-container <name>    KEYVAULTSYNC_RUNS_CONTAINER.
              --log-level <level>        KEYVAULTSYNC_LOG_LEVEL (Trace, Debug, Information, Warning, Error).
              --log-file <path>          Structured log file (compact JSON / CLEF, one event per line).
                                         Default: logs/keyvaultsync-<UTC time>-<pid>.clef under the current directory.
              --no-log-file              Log to the console only.
              --console-format <format>  text (default; message plus structured properties) or json (CLEF lines).
          -h, --help                     Show this help.

        Share the deployment's state storage account and HMAC key with any Function that syncs the same pairs;
        separate state makes each host treat the other's targets as unmanaged. The signed-in identity needs the
        same Key Vault roles as the runtime identity plus Storage Blob Data Contributor on the state account
        (scripts/grant-keyvault-access.sh --include-signed-in-user).

        This performs a live synchronization of every enabled, unpaused mapping.

        Exit codes: 0 complete or no pairs, 1 failed, 2 needs attention (for example Partial),
                    3 usage or configuration error, 130 cancelled.
        """);
}
