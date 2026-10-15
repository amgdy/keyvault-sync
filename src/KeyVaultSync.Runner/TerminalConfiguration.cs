using System.Globalization;
using System.Text;
using System.Text.Json;

namespace KeyVaultSync.Runner;

/// <summary>Command-line options accepted by the terminal host.</summary>
/// <remarks>
/// Only non-secret values are accepted as arguments. The HMAC key is read from a file path, the environment, a
/// settings file, or an azd environment so it never appears in shell history or the process list.
/// </remarks>
internal sealed record TerminalArguments
{
    /// <summary>Whether help was requested.</summary>
    public bool ShowHelp { get; init; }

    /// <summary>Optional Functions-style <c>local.settings.json</c> path.</summary>
    public string? SettingsPath { get; init; }

    /// <summary>Explicit azd environment name; when absent the azd default environment is used if one is found.</summary>
    public string? AzdEnvironmentName { get; init; }

    /// <summary>Disables implicit azd environment discovery.</summary>
    public bool NoAzd { get; init; }

    /// <summary>Path to a file containing the Base64 HMAC key.</summary>
    public string? HmacKeyFilePath { get; init; }

    /// <summary>Explicit structured log file path; when absent the host chooses a default file.</summary>
    public string? LogFilePath { get; init; }

    /// <summary>Disables the structured log file.</summary>
    public bool NoLogFile { get; init; }

    /// <summary>Console output format.</summary>
    public ConsoleLogFormat ConsoleFormat { get; init; } = ConsoleLogFormat.Text;

    /// <summary>Runner settings supplied directly as arguments; these override every other source.</summary>
    public IReadOnlyDictionary<string, string> SettingOverrides { get; init; } = new Dictionary<string, string>();
}

/// <summary>Result of resolving terminal-host configuration into process environment variables.</summary>
internal sealed record TerminalConfigurationReport
{
    /// <summary>Setting names applied from command-line arguments, including the HMAC key file.</summary>
    public IReadOnlyList<string> ArgumentSettingNames { get; init; } = [];

    /// <summary>Setting names applied from the settings file.</summary>
    public IReadOnlyList<string> SettingsFileSettingNames { get; init; } = [];

    /// <summary>Resolved azd environment name, or <see langword="null"/> when no azd environment was used.</summary>
    public string? AzdEnvironmentName { get; init; }

    /// <summary>Setting names imported from the azd environment.</summary>
    public IReadOnlyList<string> AzdSettingNames { get; init; } = [];

    /// <summary>The azd environment's networking profile, used only to warn about private storage reachability.</summary>
    public string? AzdNetworkProfile { get; init; }

    /// <summary>Required runner settings that are still missing after every source was applied.</summary>
    public IReadOnlyList<string> MissingRequiredSettings { get; init; } = [];
}

/// <summary>Resolves terminal-host configuration from arguments, the environment, a settings file, and azd.</summary>
/// <remarks>
/// Precedence is arguments, then existing environment variables, then the settings file, then the azd environment.
/// The azd environment is imported through an allowlist of runner settings because it also holds deployment outputs
/// and retired names that <see cref="RunnerOptions.Parse"/> rejects. Values are applied to this process only and are
/// never logged or returned; callers receive setting names.
/// </remarks>
internal static class TerminalConfiguration
{
    /// <summary>Runner settings that may be imported from an azd environment.</summary>
    public static readonly IReadOnlyList<string> AzdImportableSettings =
    [
        "KEYVAULTSYNC_SUBSCRIPTIONS",
        "KEYVAULTSYNC_STORAGE_ACCOUNT_URI",
        "KEYVAULTSYNC_HMAC_KEY",
        "KEYVAULTSYNC_HMAC_KEY_VERSION",
        "KEYVAULTSYNC_PRINCIPAL_ID",
        "KEYVAULTSYNC_STATE_CONTAINER",
        "KEYVAULTSYNC_RUNS_CONTAINER",
        "KEYVAULTSYNC_LOG_LEVEL",
    ];

    /// <summary>Settings without which the runner cannot start.</summary>
    public static readonly IReadOnlyList<string> RequiredSettings =
    [
        "KEYVAULTSYNC_SUBSCRIPTIONS",
        "KEYVAULTSYNC_STORAGE_ACCOUNT_URI",
    ];

    private static readonly IReadOnlyDictionary<string, string> ValueOptions = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["--subscriptions"] = "KEYVAULTSYNC_SUBSCRIPTIONS",
        ["--storage-account-uri"] = "KEYVAULTSYNC_STORAGE_ACCOUNT_URI",
        ["--principal-id"] = "KEYVAULTSYNC_PRINCIPAL_ID",
        ["--state-container"] = "KEYVAULTSYNC_STATE_CONTAINER",
        ["--runs-container"] = "KEYVAULTSYNC_RUNS_CONTAINER",
        ["--log-level"] = "KEYVAULTSYNC_LOG_LEVEL",
    };

    /// <summary>Parses terminal-host arguments.</summary>
    /// <exception cref="ArgumentException">An argument is unknown, repeated, or missing its value.</exception>
    public static TerminalArguments ParseArguments(IReadOnlyList<string> args)
    {
        var overrides = new Dictionary<string, string>(StringComparer.Ordinal);
        string? settingsPath = null;
        string? azdEnvironmentName = null;
        string? hmacKeyFilePath = null;
        string? logFilePath = null;
        string? consoleFormat = null;
        var noLogFile = false;
        var noAzd = false;
        var showHelp = false;

        for (var index = 0; index < args.Count; index++)
        {
            var argument = args[index];
            switch (argument)
            {
                case "-h" or "--help":
                    showHelp = true;
                    continue;
                case "--no-azd":
                    noAzd = true;
                    continue;
                case "--no-log-file":
                    noLogFile = true;
                    continue;
                case "--hmac-key":
                    throw new ArgumentException("--hmac-key is not supported because arguments are visible in shell history and the process list. Use --hmac-key-file, KEYVAULTSYNC_HMAC_KEY, --settings, or an azd environment.");
            }

            string ReadValue()
            {
                if (index + 1 >= args.Count || string.IsNullOrWhiteSpace(args[index + 1]) || args[index + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    throw new ArgumentException($"{argument} requires a value.");
                }

                return args[++index];
            }

            switch (argument)
            {
                case "-s" or "--settings":
                    settingsPath = SetOnce(settingsPath, ReadValue(), argument);
                    break;
                case "-e" or "--azd-env":
                    azdEnvironmentName = SetOnce(azdEnvironmentName, ReadValue(), argument);
                    break;
                case "--hmac-key-file":
                    hmacKeyFilePath = SetOnce(hmacKeyFilePath, ReadValue(), argument);
                    break;
                case "--log-file":
                    logFilePath = SetOnce(logFilePath, ReadValue(), argument);
                    break;
                case "--console-format":
                    consoleFormat = SetOnce(consoleFormat, ReadValue(), argument);
                    break;
                default:
                    if (!ValueOptions.TryGetValue(argument, out var settingName))
                    {
                        throw new ArgumentException($"Unrecognized argument: {argument}");
                    }

                    if (!overrides.TryAdd(settingName, ReadValue()))
                    {
                        throw new ArgumentException($"{argument} was specified more than once.");
                    }

                    break;
            }
        }

        if (noAzd && azdEnvironmentName is not null)
        {
            throw new ArgumentException("--no-azd cannot be combined with --azd-env.");
        }

        if (noLogFile && logFilePath is not null)
        {
            throw new ArgumentException("--no-log-file cannot be combined with --log-file.");
        }

        var parsedConsoleFormat = consoleFormat switch
        {
            null => ConsoleLogFormat.Text,
            _ when consoleFormat.Equals("text", StringComparison.OrdinalIgnoreCase) => ConsoleLogFormat.Text,
            _ when consoleFormat.Equals("json", StringComparison.OrdinalIgnoreCase) => ConsoleLogFormat.Json,
            _ => throw new ArgumentException($"--console-format must be 'text' or 'json', not '{consoleFormat}'."),
        };

        return new TerminalArguments
        {
            ShowHelp = showHelp,
            SettingsPath = settingsPath,
            AzdEnvironmentName = azdEnvironmentName,
            NoAzd = noAzd,
            HmacKeyFilePath = hmacKeyFilePath,
            LogFilePath = logFilePath,
            NoLogFile = noLogFile,
            ConsoleFormat = parsedConsoleFormat,
            SettingOverrides = overrides,
        };
    }

    /// <summary>Resolves the structured log file: the explicit path, none, or a per-run file under <c>logs/</c>.</summary>
    /// <param name="arguments">Parsed terminal arguments.</param>
    /// <param name="currentDirectory">Base directory for relative and default paths.</param>
    /// <param name="startedAtUtc">Run start time used for a unique, sortable default file name.</param>
    /// <returns>A full path, or <see langword="null"/> when <c>--no-log-file</c> was given.</returns>
    public static string? ResolveLogFilePath(TerminalArguments arguments, string currentDirectory, DateTimeOffset startedAtUtc)
    {
        if (arguments.NoLogFile)
        {
            return null;
        }

        var path = arguments.LogFilePath
            ?? Path.Combine("logs", string.Create(
                CultureInfo.InvariantCulture,
                $"keyvaultsync-{startedAtUtc.UtcDateTime:yyyyMMdd'T'HHmmss'Z'}-{Environment.ProcessId}.clef"));
        return Path.GetFullPath(path, currentDirectory);
    }

    /// <summary>Applies every configuration source to the environment in precedence order.</summary>
    /// <param name="arguments">Parsed terminal arguments.</param>
    /// <param name="startDirectory">Directory from which the azd project root is searched upward.</param>
    /// <param name="getVariable">Reads an environment variable.</param>
    /// <param name="setVariable">Sets an environment variable for this process only.</param>
    /// <exception cref="FileNotFoundException">A referenced file or explicitly named azd environment is missing.</exception>
    /// <exception cref="InvalidDataException">A referenced file is malformed or empty.</exception>
    public static TerminalConfigurationReport Apply(
        TerminalArguments arguments,
        string startDirectory,
        Func<string, string?> getVariable,
        Action<string, string> setVariable)
    {
        // Arguments override the environment, so they are written first and then protected by the
        // "do not overwrite" rule that every lower-precedence source follows.
        var argumentNames = new List<string>();
        foreach (var (name, value) in arguments.SettingOverrides)
        {
            setVariable(name, value);
            argumentNames.Add(name);
        }

        if (arguments.HmacKeyFilePath is not null)
        {
            setVariable("KEYVAULTSYNC_HMAC_KEY", ReadHmacKeyFile(arguments.HmacKeyFilePath));
            argumentNames.Add("KEYVAULTSYNC_HMAC_KEY");
        }

        IReadOnlyList<string> settingsNames = [];
        if (arguments.SettingsPath is not null)
        {
            settingsNames = LocalSettingsFile.Apply(arguments.SettingsPath, getVariable, setVariable);
        }

        string? azdName = null;
        string? networkProfile = null;
        var azdNames = new List<string>();
        var azdEnvironment = ResolveAzdEnvironment(arguments, startDirectory, getVariable);
        if (azdEnvironment is not null)
        {
            azdName = azdEnvironment.Value.Name;
            var values = DotEnvFile.Parse(File.ReadAllText(azdEnvironment.Value.Path));
            values.TryGetValue("KEYVAULTSYNC_NETWORK_PROFILE", out networkProfile);
            foreach (var name in AzdImportableSettings)
            {
                if (values.TryGetValue(name, out var value)
                    && !string.IsNullOrEmpty(value)
                    && string.IsNullOrEmpty(getVariable(name)))
                {
                    setVariable(name, value);
                    azdNames.Add(name);
                }
            }
        }

        return new TerminalConfigurationReport
        {
            ArgumentSettingNames = argumentNames,
            SettingsFileSettingNames = settingsNames,
            AzdEnvironmentName = azdName,
            AzdSettingNames = azdNames,
            AzdNetworkProfile = networkProfile,
            MissingRequiredSettings = RequiredSettings.Where(name => string.IsNullOrWhiteSpace(getVariable(name))).ToArray(),
        };
    }

    /// <summary>Finds the azd environment file to import, or <see langword="null"/> when none applies.</summary>
    /// <remarks>
    /// An explicit <c>--azd-env</c> must exist. Implicit discovery (no settings file, no <c>--no-azd</c>) uses
    /// <c>AZURE_ENV_NAME</c> or the project's default environment and silently yields nothing when absent.
    /// </remarks>
    internal static (string Name, string Path)? ResolveAzdEnvironment(
        TerminalArguments arguments,
        string startDirectory,
        Func<string, string?> getVariable)
    {
        var explicitName = arguments.AzdEnvironmentName;
        if (explicitName is null && (arguments.NoAzd || arguments.SettingsPath is not null))
        {
            return null;
        }

        var azureDirectory = FindAzdDirectory(startDirectory);
        var environmentName = explicitName
            ?? NullIfWhiteSpace(getVariable("AZURE_ENV_NAME"))
            ?? (azureDirectory is null ? null : ReadDefaultEnvironment(azureDirectory));
        if (azureDirectory is null || environmentName is null)
        {
            return explicitName is null
                ? null
                : throw new FileNotFoundException($"azd environment '{explicitName}' was requested, but no azd project (azure.yaml with .azure) was found in or above {startDirectory}.");
        }

        if (environmentName.IndexOfAny([.. Path.GetInvalidFileNameChars(), '/', '\\']) >= 0 || environmentName is "." or "..")
        {
            throw new ArgumentException($"azd environment name '{environmentName}' is not a valid directory name.");
        }

        var environmentFile = Path.Combine(azureDirectory, environmentName, ".env");
        if (!File.Exists(environmentFile))
        {
            return explicitName is null
                ? null
                : throw new FileNotFoundException($"azd environment '{explicitName}' does not exist. Run 'azd env list' to see available environments.", environmentFile);
        }

        return (environmentName, environmentFile);
    }

    private static string ReadHmacKeyFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("The HMAC key file does not exist.", path);
        }

        var key = File.ReadAllText(path).Trim();
        return key.Length == 0
            ? throw new InvalidDataException("The HMAC key file is empty.")
            : key;
    }

    private static string? FindAzdDirectory(string startDirectory)
    {
        for (var directory = new DirectoryInfo(startDirectory); directory is not null; directory = directory.Parent)
        {
            // azure.yaml marks an azd project; it keeps the Azure CLI's ~/.azure profile directory from matching.
            var candidate = Path.Combine(directory.FullName, ".azure");
            if (Directory.Exists(candidate) && File.Exists(Path.Combine(directory.FullName, "azure.yaml")))
            {
                return candidate;
            }
        }

        return null;
    }

    private static string? ReadDefaultEnvironment(string azureDirectory)
    {
        var configPath = Path.Combine(azureDirectory, "config.json");
        if (!File.Exists(configPath))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(configPath));
            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("defaultEnvironment", out var name)
                && name.ValueKind == JsonValueKind.String
                    ? NullIfWhiteSpace(name.GetString())
                    : null;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"{configPath} is not valid JSON: {exception.Message}", exception);
        }
    }

    private static string SetOnce(string? current, string value, string argument) =>
        current is null ? value : throw new ArgumentException($"{argument} was specified more than once.");

    private static string? NullIfWhiteSpace(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

/// <summary>Minimal parser for the dotenv files azd writes under <c>.azure/&lt;environment&gt;/.env</c>.</summary>
/// <remarks>
/// Supports <c>KEY=value</c>, optional <c>export</c>, comments, single-quoted literals, and double-quoted values
/// with the backslash escapes azd emits. Later duplicate keys win, matching dotenv loaders.
/// </remarks>
internal static class DotEnvFile
{
    /// <summary>Parses dotenv text into a case-sensitive name/value map.</summary>
    public static IReadOnlyDictionary<string, string> Parse(string text)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r').Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            if (line.StartsWith("export ", StringComparison.Ordinal))
            {
                line = line["export ".Length..].TrimStart();
            }

            var separator = line.IndexOf('=');
            if (separator <= 0)
            {
                continue;
            }

            var name = line[..separator].Trim();
            values[name] = ParseValue(line[(separator + 1)..].Trim());
        }

        return values;
    }

    private static string ParseValue(string value)
    {
        if (value.Length >= 2 && value[0] == '\'' && value[^1] == '\'')
        {
            return value[1..^1];
        }

        if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
        {
            var builder = new StringBuilder(value.Length);
            for (var index = 1; index < value.Length - 1; index++)
            {
                var character = value[index];
                if (character == '\\' && index + 1 < value.Length - 1)
                {
                    var escaped = value[++index];
                    builder.Append(escaped switch
                    {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        _ => escaped,
                    });
                }
                else
                {
                    builder.Append(character);
                }
            }

            return builder.ToString();
        }

        var comment = value.IndexOf(" #", StringComparison.Ordinal);
        return (comment >= 0 ? value[..comment] : value).Trim();
    }
}

/// <summary>Reads identity claims from a Microsoft Entra access token without validating it.</summary>
/// <remarks>
/// The token was just issued to this process by the credential chain; the claim is used only to name the identity the
/// runner must never revoke, never for an authorization decision.
/// </remarks>
internal static class AccessTokenClaims
{
    /// <summary>Returns the <c>oid</c> claim when it is a GUID, otherwise <see langword="null"/>.</summary>
    public static string? TryGetObjectId(string accessToken)
    {
        var segments = accessToken.Split('.');
        if (segments.Length < 2)
        {
            return null;
        }

        try
        {
            var payload = segments[1].Replace('-', '+').Replace('_', '/');
            payload = payload.PadRight(payload.Length + ((4 - (payload.Length % 4)) % 4), '=');
            using var document = JsonDocument.Parse(Convert.FromBase64String(payload));
            return document.RootElement.TryGetProperty("oid", out var objectId)
                && objectId.ValueKind == JsonValueKind.String
                && Guid.TryParse(objectId.GetString(), out _)
                    ? objectId.GetString()
                    : null;
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            return null;
        }
    }
}
