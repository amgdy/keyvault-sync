using System.Text.Json;
using Azure.Identity;
using KeyVaultSync.Runner;
using KeyVaultSync.Runner.Azure;
using Microsoft.Extensions.Logging;
using Xunit;

namespace KeyVaultSync.Runner.Tests;

public sealed class ArmResourceReferenceTests : IDisposable
{
    private const string SourceId = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-source/providers/Microsoft.KeyVault/vaults/kv-source";
    private const string TargetId = "/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/rg-target/providers/Microsoft.KeyVault/vaults/kv-target";
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"keyvaultsync-armref-{Guid.NewGuid():N}");

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Theory]
    [InlineData(SourceId, "00000000-0000-0000-0000-000000000001", "rg-source", "kv-source")]
    [InlineData("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-1/secrets/app", "sub-1", "rg-1", "app")]
    [InlineData("/SUBSCRIPTIONS/sub-1/RESOURCEGROUPS/rg-1/PROVIDERS/Microsoft.KeyVault/vaults/kv-1/", "sub-1", "rg-1", "kv-1")]
    [InlineData("/subscriptions/sub-1/resourceGroups/rg-1", "sub-1", "rg-1", null)]
    [InlineData("/subscriptions/sub-1", "sub-1", null, null)]
    [InlineData("not-an-arm-id", null, null, "not-an-arm-id")]
    [InlineData("  ", null, null, null)]
    [InlineData(null, null, null, null)]
    public void ParseSplitsResourceIdentifiersIntoReadableParts(string? resourceId, string? subscriptionId, string? resourceGroup, string? name)
    {
        Assert.Equal(new ArmResourceReference(subscriptionId, resourceGroup, name), ArmResourceReference.Parse(resourceId));
    }

    [Fact]
    public void PairScopeLogsReadablePartsWithoutFullResourceIds()
    {
        var pair = new VaultPair(CreateVault(SourceId, "kv-source"), CreateVault(TargetId, "kv-target"));
        var logFilePath = Path.Combine(_root, "pair.clef");
        using (var telemetry = TelemetryRuntime.Configure(null, new DefaultAzureCredential(), new TelemetryLogOptions { FilePath = logFilePath }))
        {
            var logger = telemetry.LoggerFactory.CreateLogger("KeyVaultSync.Tests");
            using (PairLogScope.Begin(logger, pair, new Dictionary<string, object?> { ["PairNumber"] = 1 }))
            {
                logger.LogInformation("Scoped pair event.");
            }

            using (PairLogScope.Begin(logger, pair.PairId))
            {
                logger.LogInformation("Persisted pair event.");
            }
        }

        var lines = File.ReadAllLines(logFilePath);
        Assert.DoesNotContain(lines, line => line.Contains("/subscriptions/", StringComparison.OrdinalIgnoreCase));
        foreach (var message in new[] { "Scoped pair event.", "Persisted pair event." })
        {
            var logEvent = lines.Select(line => JsonDocument.Parse(line).RootElement)
                .Single(element => element.GetProperty("@m").GetString() == message);
            Assert.Equal("kv-source", logEvent.GetProperty("SourceVaultName").GetString());
            Assert.Equal("rg-source", logEvent.GetProperty("SourceResourceGroup").GetString());
            Assert.Equal("00000000-0000-0000-0000-000000000001", logEvent.GetProperty("SourceSubscriptionId").GetString());
            Assert.Equal("kv-target", logEvent.GetProperty("TargetVaultName").GetString());
            Assert.Equal("rg-target", logEvent.GetProperty("TargetResourceGroup").GetString());
            Assert.Equal("00000000-0000-0000-0000-000000000002", logEvent.GetProperty("TargetSubscriptionId").GetString());
        }
    }

    private static VaultResource CreateVault(string id, string name) => new()
    {
        Id = id,
        Name = name,
        Location = "westeurope",
        ResourceGroup = ArmResourceReference.Parse(id).ResourceGroup!,
        Tags = [],
    };
}
