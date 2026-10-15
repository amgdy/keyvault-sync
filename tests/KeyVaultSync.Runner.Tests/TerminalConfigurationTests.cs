using System.Text;
using KeyVaultSync.Runner;
using Xunit;

namespace KeyVaultSync.Runner.Tests;

public sealed class TerminalConfigurationTests : IDisposable
{
    private const string SubscriptionId = "00000000-0000-0000-0000-000000000001";
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"keyvaultsync-terminal-{Guid.NewGuid():N}");
    private readonly Dictionary<string, string> _environment = new(StringComparer.Ordinal);

    public TerminalConfigurationTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void ParsesValueOptionsIntoRunnerSettings()
    {
        var arguments = TerminalConfiguration.ParseArguments(
            ["--subscriptions", SubscriptionId, "--storage-account-uri", "https://state.blob.core.windows.net/", "-e", "dev", "--log-level", "Debug"]);

        Assert.Equal("dev", arguments.AzdEnvironmentName);
        Assert.Equal(SubscriptionId, arguments.SettingOverrides["KEYVAULTSYNC_SUBSCRIPTIONS"]);
        Assert.Equal("https://state.blob.core.windows.net/", arguments.SettingOverrides["KEYVAULTSYNC_STORAGE_ACCOUNT_URI"]);
        Assert.Equal("Debug", arguments.SettingOverrides["KEYVAULTSYNC_LOG_LEVEL"]);
    }

    [Fact]
    public void DefaultsToPerRunLogFileUnderLogsDirectory()
    {
        var startedAt = new DateTimeOffset(2026, 10, 15, 13, 37, 39, TimeSpan.Zero);

        var path = TerminalConfiguration.ResolveLogFilePath(TerminalConfiguration.ParseArguments([]), _root, startedAt);

        Assert.Equal(Path.Combine(_root, "logs", $"keyvaultsync-20261015T133739Z-{Environment.ProcessId}.clef"), path);
    }

    [Fact]
    public void ResolvesExplicitLogFileAndConsoleFormat()
    {
        var arguments = TerminalConfiguration.ParseArguments(["--log-file", "out/run.clef", "--console-format", "JSON"]);

        Assert.Equal(ConsoleLogFormat.Json, arguments.ConsoleFormat);
        Assert.Equal(Path.Combine(_root, "out", "run.clef"), TerminalConfiguration.ResolveLogFilePath(arguments, _root, DateTimeOffset.UtcNow));
        Assert.Null(TerminalConfiguration.ResolveLogFilePath(TerminalConfiguration.ParseArguments(["--no-log-file"]), _root, DateTimeOffset.UtcNow));
    }

    [Theory]
    [InlineData("--hmac-key", "secret")]
    [InlineData("--unknown")]
    [InlineData("--subscriptions")]
    [InlineData("--settings", "--no-azd")]
    [InlineData("--log-level", "Debug", "--log-level", "Trace")]
    [InlineData("--no-azd", "--azd-env", "dev")]
    [InlineData("--no-log-file", "--log-file", "run.clef")]
    [InlineData("--console-format", "xml")]
    public void RejectsInvalidArguments(params string[] args)
    {
        Assert.Throws<ArgumentException>(() => TerminalConfiguration.ParseArguments(args));
    }

    [Fact]
    public void ImportsOnlyAllowlistedSettingsFromDefaultAzdEnvironment()
    {
        WriteAzdEnvironment("dev", isDefault: true, $"""
            AZURE_SUBSCRIPTION_ID="{SubscriptionId}"
            AZURE_FUNCTIONAPP_NAME="func-example"
            KEYVAULTSYNC_SUBSCRIPTIONS="{SubscriptionId}"
            KEYVAULTSYNC_STORAGE_ACCOUNT_URI="https://state.blob.core.windows.net/"
            KEYVAULTSYNC_HMAC_KEY="a2V5\"quoted\\"
            KEYVAULTSYNC_NETWORK_PROFILE="private-managed"
            KEYVAULTSYNC_IDENTITY_RESOURCE_ID="/subscriptions/example/identity"
            """);

        var report = Apply(TerminalConfiguration.ParseArguments([]), Path.Combine(_root, "src"));

        Assert.Equal("dev", report.AzdEnvironmentName);
        Assert.Equal("private-managed", report.AzdNetworkProfile);
        Assert.Equal(["KEYVAULTSYNC_SUBSCRIPTIONS", "KEYVAULTSYNC_STORAGE_ACCOUNT_URI", "KEYVAULTSYNC_HMAC_KEY"], report.AzdSettingNames);
        Assert.Equal("a2V5\"quoted\\", _environment["KEYVAULTSYNC_HMAC_KEY"]);
        // Retired or deployment-only names must never reach RunnerOptions.Parse.
        Assert.False(_environment.ContainsKey("AZURE_SUBSCRIPTION_ID"));
        Assert.False(_environment.ContainsKey("KEYVAULTSYNC_NETWORK_PROFILE"));
        Assert.False(_environment.ContainsKey("KEYVAULTSYNC_IDENTITY_RESOURCE_ID"));
        Assert.Empty(report.MissingRequiredSettings);
    }

    [Fact]
    public void AppliesArgumentsThenEnvironmentThenSettingsFileThenAzd()
    {
        WriteAzdEnvironment("dev", isDefault: false, """
            KEYVAULTSYNC_SUBSCRIPTIONS=azd
            KEYVAULTSYNC_STORAGE_ACCOUNT_URI=azd
            KEYVAULTSYNC_STATE_CONTAINER=azd
            KEYVAULTSYNC_RUNS_CONTAINER=azd
            """);
        var settingsPath = Path.Combine(_root, "local.settings.json");
        File.WriteAllText(settingsPath, """
            { "Values": { "KEYVAULTSYNC_SUBSCRIPTIONS": "file", "KEYVAULTSYNC_STORAGE_ACCOUNT_URI": "file", "KEYVAULTSYNC_STATE_CONTAINER": "file" } }
            """);
        _environment["KEYVAULTSYNC_SUBSCRIPTIONS"] = "shell";
        _environment["KEYVAULTSYNC_STORAGE_ACCOUNT_URI"] = "shell";

        var report = Apply(TerminalConfiguration.ParseArguments(
            ["--settings", settingsPath, "--azd-env", "dev", "--storage-account-uri", "argument"]), _root);

        Assert.Equal("argument", _environment["KEYVAULTSYNC_STORAGE_ACCOUNT_URI"]);
        Assert.Equal("shell", _environment["KEYVAULTSYNC_SUBSCRIPTIONS"]);
        Assert.Equal("file", _environment["KEYVAULTSYNC_STATE_CONTAINER"]);
        Assert.Equal("azd", _environment["KEYVAULTSYNC_RUNS_CONTAINER"]);
        Assert.Equal(["KEYVAULTSYNC_STORAGE_ACCOUNT_URI"], report.ArgumentSettingNames);
        Assert.Equal(["KEYVAULTSYNC_RUNS_CONTAINER"], report.AzdSettingNames);
    }

    [Fact]
    public void SettingsFileDisablesImplicitAzdDiscovery()
    {
        WriteAzdEnvironment("dev", isDefault: true, "KEYVAULTSYNC_SUBSCRIPTIONS=azd");
        var settingsPath = Path.Combine(_root, "local.settings.json");
        File.WriteAllText(settingsPath, """{ "Values": {} }""");

        var report = Apply(TerminalConfiguration.ParseArguments(["--settings", settingsPath]), _root);

        Assert.Null(report.AzdEnvironmentName);
        Assert.Equal(TerminalConfiguration.RequiredSettings, report.MissingRequiredSettings);
    }

    [Fact]
    public void AzureEnvNameSelectsTheImplicitEnvironment()
    {
        WriteAzdEnvironment("dev", isDefault: true, "KEYVAULTSYNC_STATE_CONTAINER=dev");
        WriteAzdEnvironment("prod", isDefault: false, "KEYVAULTSYNC_STATE_CONTAINER=prod");
        _environment["AZURE_ENV_NAME"] = "prod";

        var report = Apply(TerminalConfiguration.ParseArguments([]), _root);

        Assert.Equal("prod", report.AzdEnvironmentName);
        Assert.Equal("prod", _environment["KEYVAULTSYNC_STATE_CONTAINER"]);
    }

    [Fact]
    public void ReportsMissingSettingsWhenNoSourceExists()
    {
        var report = Apply(TerminalConfiguration.ParseArguments([]), _root);

        Assert.Null(report.AzdEnvironmentName);
        Assert.Equal(TerminalConfiguration.RequiredSettings, report.MissingRequiredSettings);
    }

    [Fact]
    public void ExplicitMissingAzdEnvironmentFails()
    {
        WriteAzdEnvironment("dev", isDefault: true, string.Empty);

        Assert.Throws<FileNotFoundException>(() => Apply(TerminalConfiguration.ParseArguments(["--azd-env", "missing"]), _root));
    }

    [Theory]
    [InlineData("../dev")]
    [InlineData("..")]
    public void RejectsAzdEnvironmentNamesThatLeaveTheAzureDirectory(string name)
    {
        WriteAzdEnvironment("dev", isDefault: true, string.Empty);

        Assert.Throws<ArgumentException>(() => Apply(TerminalConfiguration.ParseArguments(["--azd-env", name]), _root));
    }

    [Fact]
    public void HmacKeyFileOverridesEnvironmentAndIsTrimmed()
    {
        var keyPath = Path.Combine(_root, "hmac.key");
        File.WriteAllText(keyPath, "  file-key\n");
        _environment["KEYVAULTSYNC_HMAC_KEY"] = "shell-key";

        var report = Apply(TerminalConfiguration.ParseArguments(["--no-azd", "--hmac-key-file", keyPath]), _root);

        Assert.Equal("file-key", _environment["KEYVAULTSYNC_HMAC_KEY"]);
        Assert.Contains("KEYVAULTSYNC_HMAC_KEY", report.ArgumentSettingNames);
    }

    [Fact]
    public void EmptyHmacKeyFileFails()
    {
        var keyPath = Path.Combine(_root, "hmac.key");
        File.WriteAllText(keyPath, "\n");

        Assert.Throws<InvalidDataException>(() => Apply(TerminalConfiguration.ParseArguments(["--hmac-key-file", keyPath]), _root));
    }

    [Fact]
    public void DotEnvParserHandlesQuotingCommentsAndExport()
    {
        var values = DotEnvFile.Parse("""
            # comment
            export PLAIN=value # trailing
            SINGLE='lit\eral'
            DOUBLE="line\nnext"
            EMPTY=
            not-a-setting
            """);

        Assert.Equal("value", values["PLAIN"]);
        Assert.Equal("lit\\eral", values["SINGLE"]);
        Assert.Equal("line\nnext", values["DOUBLE"]);
        Assert.Equal(string.Empty, values["EMPTY"]);
        Assert.Equal(4, values.Count);
    }

    [Fact]
    public void ReadsObjectIdClaimFromAccessToken()
    {
        var objectId = Guid.NewGuid().ToString();
        static string Encode(string json) => Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        Assert.Equal(objectId, AccessTokenClaims.TryGetObjectId($"{Encode("{}")}.{Encode($$"""{"oid":"{{objectId}}"}""")}.signature"));
        Assert.Null(AccessTokenClaims.TryGetObjectId($"{Encode("{}")}.{Encode("""{"oid":"not-a-guid"}""")}.signature"));
        Assert.Null(AccessTokenClaims.TryGetObjectId("not-a-token"));
        Assert.Null(AccessTokenClaims.TryGetObjectId("a.!!!.c"));
    }

    private TerminalConfigurationReport Apply(TerminalArguments arguments, string startDirectory) =>
        TerminalConfiguration.Apply(
            arguments,
            startDirectory,
            name => _environment.GetValueOrDefault(name),
            (name, value) => _environment[name] = value);

    private void WriteAzdEnvironment(string name, bool isDefault, string content)
    {
        var environmentDirectory = Path.Combine(_root, ".azure", name);
        Directory.CreateDirectory(environmentDirectory);
        Directory.CreateDirectory(Path.Combine(_root, "src"));
        File.WriteAllText(Path.Combine(_root, "azure.yaml"), "name: example\n");
        File.WriteAllText(Path.Combine(environmentDirectory, ".env"), content);
        if (isDefault)
        {
            File.WriteAllText(Path.Combine(_root, ".azure", "config.json"), $$"""{"version":1,"defaultEnvironment":"{{name}}"}""");
        }
    }
}
