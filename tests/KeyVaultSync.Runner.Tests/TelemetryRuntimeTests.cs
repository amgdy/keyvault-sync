using System.Text.Json;
using Azure.Identity;
using KeyVaultSync.Runner;
using Microsoft.Extensions.Logging;
using Xunit;

namespace KeyVaultSync.Runner.Tests;

public sealed class TelemetryRuntimeTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"keyvaultsync-telemetry-{Guid.NewGuid():N}");

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public void WritesStructuredCompactJsonEventsToTheLogFile()
    {
        var logFilePath = Path.Combine(_root, "logs", "run.clef");
        using (var telemetry = TelemetryRuntime.Configure(null, new DefaultAzureCredential(), new TelemetryLogOptions { FilePath = logFilePath }))
        {
            Assert.Equal(logFilePath, telemetry.LogFilePath);
            var logger = telemetry.LoggerFactory.CreateLogger("KeyVaultSync.Tests");
            using (logger.BeginScope(new Dictionary<string, object> { ["RunId"] = "run-1" }))
            {
                logger.LogWarning("Pair {PairId} needs attention with {ItemCount} items.", "pair-a", 3);
            }
        }

        var logEvent = File.ReadLines(logFilePath)
            .Select(line => JsonDocument.Parse(line).RootElement)
            .Single(element => element.TryGetProperty("PairId", out _));

        Assert.Equal("Warning", logEvent.GetProperty("@l").GetString());
        Assert.Equal("Pair \"pair-a\" needs attention with 3 items.", logEvent.GetProperty("@m").GetString());
        Assert.Equal(3, logEvent.GetProperty("ItemCount").GetInt32());
        Assert.Equal("run-1", logEvent.GetProperty("RunId").GetString());
        Assert.Equal("KeyVaultSync.Tests", logEvent.GetProperty("SourceContext").GetString());
        Assert.True(logEvent.TryGetProperty("@t", out _));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(logFilePath));
        }
    }

    [Fact]
    public void LogsToConsoleOnlyWhenNoFileIsConfigured()
    {
        using var telemetry = TelemetryRuntime.Configure(null, new DefaultAzureCredential());

        Assert.Null(telemetry.LogFilePath);
        Assert.False(Directory.Exists(_root));
    }
}
