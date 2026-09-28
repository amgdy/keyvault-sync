using System.Diagnostics;
using System.Text.Json;
using Azure.Identity;
using KeyVaultSync.Runner;
using Microsoft.Extensions.Logging;

// Parse before constructing Azure clients so invalid configuration fails without starting a scan.
// DefaultAzureCredential reads the hosted AZURE_CLIENT_ID to select the user-assigned identity
// and retains developer credential sources, including Azure CLI, for local execution.
var options = RunnerOptions.Parse(args);
var credential = new DefaultAzureCredential();
// This host owns telemetry for the process lifetime. ILogger events go independently to the
// Serilog console provider and, when configured, the OpenTelemetry Azure Monitor exporter.
// Disposal flushes buffered telemetry on normal exit; abrupt process termination can lose it.
using var telemetry = TelemetryRuntime.Configure(Environment.GetEnvironmentVariable("APPLICATIONINSIGHTS_CONNECTION_STRING"), credential);
var logger = telemetry.LoggerFactory.CreateLogger("KeyVaultSync.Runner");
logger.LogInformation("Runner logging initialized with minimum level {MinimumLogLevel}.", telemetry.MinimumLogLevel);
logger.LogInformation("Runner initialized. Azure Monitor export is {TelemetryStatus}.", telemetry.AzureMonitorEnabled ? "enabled" : "disabled");
// These checks report local listener/instrument registration, not successful remote ingestion.
using (var traceSelfCheck = RunnerTelemetry.ActivitySource.StartActivity("telemetry.self-check"))
{
	logger.LogInformation("OpenTelemetry trace self-check: activity created {ActivityCreated}; recording enabled {RecordingEnabled}.",
		traceSelfCheck is not null, traceSelfCheck?.IsAllDataRequested ?? false);
}

logger.LogInformation("OpenTelemetry runner meter {MeterName} instrument state: run counter {RunCounterEnabled}, object counter {ObjectCounterEnabled}, duration histogram {DurationHistogramEnabled}.",
	RunnerTelemetry.Meter.Name, RunnerTelemetry.RunsStarted.Enabled, RunnerTelemetry.InventoriedObjects.Enabled, RunnerTelemetry.RunDuration.Enabled);
if (!telemetry.AzureMonitorEnabled)
{
	logger.LogWarning("APPLICATIONINSIGHTS_CONNECTION_STRING is not set; telemetry will be written to the console only.");
}

var runner = new RunnerApplication(options, credential, telemetry.LoggerFactory);
var exitCode = 0;
do
{
	// A cycle is awaited in full, so --watch never overlaps this process's runs. Unlike the
	// Function host, this console entry point does not supply a shutdown cancellation token.
	var cycleStarted = DateTimeOffset.UtcNow;
	var run = await runner.RunOnceAsync(CancellationToken.None);
	// Print a compact operational projection in addition to structured logs. Full inventory
	// and run records are persisted by the runner; this projection omits object payloads.
	Console.WriteLine(JsonSerializer.Serialize(new
	{
		run.RunId,
		run.Mode,
		run.Status,
		run.DiscoveredVaultCount,
		run.TaggedPairCount,
		run.DisabledPairCount,
		run.DisabledVaultNames,
		run.UnmappedVaultCount,
		run.DiscoveryIssues,
		Pairs = run.Pairs.Select(pair => new
		{
			pair.PairId,
			pair.Status,
			Source = SummarizeInventory(pair.Source),
			Target = SummarizeInventory(pair.Target),
			Plan = pair.Plan,
			pair.Errors,
		}),
	}, new JsonSerializerOptions { WriteIndented = true }));

	// NoConfiguredPairs is an intentional no-op. A degraded cycle makes the exit code sticky
	// for the rest of this process; a later successful watch cycle does not reset it.
	if (run.Status is "Failed" or "Cancelled" or "Partial" or "PartialInventory"
		or "SyncCompletedWithUnappliedWork")
	{
		exitCode = 1;
	}

	if (!options.Watch)
	{
		break;
	}

	// Maintain an approximate start-to-start interval. Long cycles start their successor
	// immediately rather than queueing missed intervals; the Function uses its own timer.
	var elapsed = DateTimeOffset.UtcNow - cycleStarted;
	var delay = TimeSpan.FromMinutes(options.IntervalMinutes) - elapsed;
	if (delay > TimeSpan.Zero)
	{
		await Task.Delay(delay);
	}
}
while (true);

return exitCode;

// A missing inventory means that side was not obtained, not that the vault was empty.
// Counts describe the observed scan and must be interpreted together with its warnings.
static object? SummarizeInventory(VaultInventory? inventory)
{
	if (inventory is null)
	{
		return null;
	}

	return new
	{
		inventory.VaultName,
		SecretCount = inventory.Secrets.Count,
		KeyCount = inventory.Keys.Count,
		CertificateCount = inventory.Certificates.Count,
		inventory.DeletedSecretCount,
		inventory.DeletedKeyCount,
		inventory.DeletedCertificateCount,
		UsesRbac = inventory.Authorization.UsesRbac,
		AccessPolicyCount = inventory.Authorization.AccessPolicies.Count,
		RoleAssignmentCount = inventory.Authorization.RoleAssignments.Count,
		inventory.Warnings,
	};
}
