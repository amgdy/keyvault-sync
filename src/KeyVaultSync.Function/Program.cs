using Azure.Core;
using Azure.Identity;
using Azure.Monitor.OpenTelemetry.Exporter;
using KeyVaultSync.Runner;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Azure.Functions.Worker.OpenTelemetry;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

// The isolated worker owns dependency injection, invocation correlation, and host shutdown.
// RunnerApplication supplies the same orchestration as the console, without a watch loop.
var builder = FunctionsApplication.CreateBuilder(args);

// This is the worker's default application threshold. Functions host filtering in host.json
// is a separate configuration surface, and category-specific filters can further affect logs.
var configuredLogLevel = builder.Configuration["KEYVAULTSYNC_LOG_LEVEL"];
var minimumLogLevel = TelemetryRuntime.TryParseMinimumLogLevel(configuredLogLevel, out var configuredMinimumLogLevel)
	? configuredMinimumLogLevel
	: LogLevel.Information;
builder.Logging.SetMinimumLevel(minimumLogLevel);

// Bicep supplies AZURE_CLIENT_ID for user-assigned identity selection. The same default
// credential chain retains Azure CLI and other developer sign-ins for local Core Tools.
var credential = new DefaultAzureCredential();
RunnerTelemetry.Initialize();

// Reuse credentials and Azure clients across invocations. RunnerApplication's public constructor
// resolves its environment-only options once when the singleton is first constructed.
builder.Services.AddSingleton<TokenCredential>(credential);
builder.Services.AddSingleton<RunnerApplication>();
// Invocation, run, pair, and secret scopes must be explicitly included in exported worker logs.
builder.Logging.AddOpenTelemetry(logging => logging.IncludeScopes = true);

// Keep the native worker integration as the only application export pipeline. Do not also call
// TelemetryRuntime.Configure or add a Serilog Application Insights sink here. The exporter reads
// APPLICATIONINSIGHTS_CONNECTION_STRING for routing and uses the supplied Entra credential.
builder.Services.AddOpenTelemetry()
	.WithTracing(tracing => tracing
		.AddSource(RunnerTelemetry.ActivitySourceName, "Azure.Core", "Azure.Identity")
		.AddHttpClientInstrumentation())
	.WithMetrics(metrics => metrics
		.AddMeter(RunnerTelemetry.MeterName)
		.AddRuntimeInstrumentation())
	.UseFunctionsWorkerDefaults()
	.UseAzureMonitorExporter(exporterOptions =>
	{
		exporterOptions.Credential = credential;
		exporterOptions.SamplingRatio = 1.0F;
	});

var host = builder.Build();
var startupLogger = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("KeyVaultSync.Function.Startup");
startupLogger.LogInformation("Function worker logging initialized with minimum level {MinimumLogLevel}.", minimumLogLevel);
if (!string.IsNullOrWhiteSpace(configuredLogLevel) && !TelemetryRuntime.TryParseMinimumLogLevel(configuredLogLevel, out _))
{
	startupLogger.LogWarning("Ignoring unsupported KEYVAULTSYNC_LOG_LEVEL value {ConfiguredLogLevel}; using {MinimumLogLevel}.",
		configuredLogLevel, minimumLogLevel);
}

host.Run();