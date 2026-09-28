using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Reflection;
using Azure.Monitor.OpenTelemetry.Exporter;
using Azure.Core;
using Microsoft.Extensions.Logging;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Serilog;
using Serilog.Events;

namespace KeyVaultSync.Runner;

/// <summary>Owns the console host's logging and optional OpenTelemetry providers for one process lifetime.</summary>
/// <remarks>
/// Serilog formats console output; a separate OpenTelemetry logger provider exports the same
/// <see cref="Microsoft.Extensions.Logging.ILogger"/> events to Azure Monitor. The Function host
/// configures its native worker pipeline instead and must not also construct this runtime.
/// Dispose after all work finishes to flush buffered telemetry on normal shutdown.
/// </remarks>
internal sealed class TelemetryRuntime : IDisposable
{
    private readonly TracerProvider? _tracerProvider;
    private readonly MeterProvider? _meterProvider;

    /// <summary>Takes ownership of the factory and any providers created by <see cref="Configure"/>.</summary>
    private TelemetryRuntime(
        ILoggerFactory loggerFactory,
        TracerProvider? tracerProvider,
        MeterProvider? meterProvider,
        bool azureMonitorEnabled,
        LogLevel minimumLogLevel)
    {
        LoggerFactory = loggerFactory;
        _tracerProvider = tracerProvider;
        _meterProvider = meterProvider;
        AzureMonitorEnabled = azureMonitorEnabled;
        MinimumLogLevel = minimumLogLevel;
    }

    /// <summary>Gets the shared factory whose providers carry structured properties and run/pair scopes.</summary>
    public ILoggerFactory LoggerFactory { get; }
    /// <summary>Gets whether exporters were configured, not whether Azure Monitor accepted any telemetry.</summary>
    public bool AzureMonitorEnabled { get; }
    /// <summary>Gets the effective application log threshold after fallback validation.</summary>
    public LogLevel MinimumLogLevel { get; }

    /// <summary>Creates console logging and, when a connection string is supplied, Azure Monitor export.</summary>
    /// <param name="connectionString">Application Insights routing configuration; null/blank means console-only logs.</param>
    /// <param name="credential">Entra credential for export; the identity requires the relevant Azure Monitor permission.</param>
    /// <returns>A runtime that the console entry point must dispose when its work has finished.</returns>
    /// <remarks>
    /// Reads <c>KEYVAULTSYNC_LOG_LEVEL</c> once. Invalid values fall back to Information with a warning.
    /// The connection string identifies the telemetry destination; the supplied credential authenticates export.
    /// Exporter configuration and local instrumentation do not verify remote ingestion or redaction.
    /// </remarks>
    public static TelemetryRuntime Configure(string? connectionString, TokenCredential credential)
    {
        RunnerTelemetry.Initialize();
        var azureMonitorEnabled = !string.IsNullOrWhiteSpace(connectionString);
        var serviceVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "unknown";
        var resource = ResourceBuilder.CreateDefault()
            .AddService(
                serviceName: RunnerTelemetry.ServiceName,
                serviceNamespace: "KeyVaultSync",
                serviceVersion: serviceVersion);
        var configuredLevel = Environment.GetEnvironmentVariable("KEYVAULTSYNC_LOG_LEVEL");
        var minimumLevel = TryParseMinimumLogLevel(configuredLevel, out var parsedLevel)
            ? parsedLevel
            : LogLevel.Information;
        var serilogLogger = new LoggerConfiguration()
            .MinimumLevel.Is(ToSerilogLevel(minimumLevel))
            .Enrich.FromLogContext()
            .WriteTo.Console(outputTemplate: "{Timestamp:O} [{Level:u3}] {SourceContext} {Message:lj} {Properties:j}{NewLine}{Exception}")
            .CreateLogger();

        var loggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(builder =>
        {
            builder.SetMinimumLevel(minimumLevel);
            // Both providers receive ILogger events directly. Forwarding Serilog to another
            // Application Insights sink here would introduce a second export path.
            builder.AddSerilog(serilogLogger, dispose: true);

            if (azureMonitorEnabled)
            {
                builder.AddOpenTelemetry(logging =>
                {
                    logging.IncludeFormattedMessage = true;
                    logging.IncludeScopes = true;
                    logging.SetResourceBuilder(resource);
                    logging.AddAzureMonitorLogExporter(exporterOptions =>
                    {
                        exporterOptions.ConnectionString = connectionString;
                        exporterOptions.Credential = credential;
                    });
                });
            }
        });

        if (!string.IsNullOrWhiteSpace(configuredLevel) && !TryParseMinimumLogLevel(configuredLevel, out _))
        {
            loggerFactory.CreateLogger("KeyVaultSync.Logging").LogWarning(
                "Ignoring unsupported KEYVAULTSYNC_LOG_LEVEL value {ConfiguredLogLevel}; using {MinimumLogLevel}.",
                configuredLevel, minimumLevel);
        }

        if (!azureMonitorEnabled)
        {
            // No trace/metric listener is installed by this branch. StartActivity can return null;
            // instrumentation call sites must continue to work with logging alone.
            return new TelemetryRuntime(loggerFactory, null, null, false, minimumLevel);
        }

        // Subscribe to the application's source plus Azure SDK and HTTP dependencies. Trace
        // sampling is independent of the log threshold; all eligible traces are requested here.
        var tracerProvider = Sdk.CreateTracerProviderBuilder()
            .SetResourceBuilder(resource)
            .AddSource(RunnerTelemetry.ActivitySourceName, "Azure.Core", "Azure.Identity")
            .AddHttpClientInstrumentation()
            .AddAzureMonitorTraceExporter(exporterOptions =>
            {
                exporterOptions.ConnectionString = connectionString;
                exporterOptions.Credential = credential;
                exporterOptions.SamplingRatio = 1.0F;
            })
            .Build();
        var meterProvider = Sdk.CreateMeterProviderBuilder()
            .SetResourceBuilder(resource)
            .AddMeter(RunnerTelemetry.MeterName)
            .AddRuntimeInstrumentation()
            .AddAzureMonitorMetricExporter(exporterOptions =>
            {
                exporterOptions.ConnectionString = connectionString;
                exporterOptions.Credential = credential;
            })
            .Build();

        return new TelemetryRuntime(loggerFactory, tracerProvider, meterProvider, true, minimumLevel);
    }

    /// <summary>Parses a supported logging threshold shared by both hosts, excluding the silent None level.</summary>
    /// <param name="configuredLevel">An enum name (case-insensitive) or a numeric value recognized by enum parsing.</param>
    /// <param name="minimumLogLevel">The parsed defined severity, or Information when parsing fails.</param>
    /// <returns>True for Trace through Critical; false for null, invalid, undefined, or None values.</returns>
    /// <remarks>Callers decide whether a fallback warrants a warning; an absent setting is an ordinary default.</remarks>
    internal static bool TryParseMinimumLogLevel(string? configuredLevel, out LogLevel minimumLogLevel)
    {
        if (Enum.TryParse(configuredLevel, true, out minimumLogLevel)
            && Enum.IsDefined(minimumLogLevel)
            && minimumLogLevel != LogLevel.None)
        {
            return true;
        }

        minimumLogLevel = LogLevel.Information;
        return false;
    }

    /// <summary>Maps Microsoft logging severities to Serilog, including Trace/Verbose and Critical/Fatal.</summary>
    private static LogEventLevel ToSerilogLevel(LogLevel level)
    {
        return level switch
        {
            LogLevel.Trace => LogEventLevel.Verbose,
            LogLevel.Debug => LogEventLevel.Debug,
            LogLevel.Information => LogEventLevel.Information,
            LogLevel.Warning => LogEventLevel.Warning,
            LogLevel.Error => LogEventLevel.Error,
            LogLevel.Critical => LogEventLevel.Fatal,
            _ => LogEventLevel.Fatal,
        };
    }

    /// <summary>Flushes trace/metric providers, then disposes them and the logger providers owned by the factory.</summary>
    /// <remarks>Best-effort shutdown delivery is not an acknowledgment of ingestion; abrupt termination bypasses it.</remarks>
    public void Dispose()
    {
        _meterProvider?.ForceFlush();
        _tracerProvider?.ForceFlush();
        _meterProvider?.Dispose();
        _tracerProvider?.Dispose();
        LoggerFactory.Dispose();
    }
}

/// <summary>Defines the stable activity source, meter, and instruments used by the shared runner in either host.</summary>
/// <remarks>
/// Hosts subscribe to these process-wide instruments; application code never constructs exporters here.
/// Keep dimensions bounded (object type, vault role, mode, status), and use logs/traces for object identifiers.
/// Recording an observation does not imply that a listener or a remote exporter is active.
/// </remarks>
internal static class RunnerTelemetry
{
    /// <summary>The runner's OpenTelemetry service identity; the Function sets its own host resource identity.</summary>
    public const string ServiceName = "KeyVaultSync.Runner";
    /// <summary>The exact source name both hosts must register to receive shared-runner activities.</summary>
    public const string ActivitySourceName = "KeyVaultSync.Runner";
    /// <summary>The exact meter name both hosts must register to receive shared-runner measurements.</summary>
    public const string MeterName = "KeyVaultSync.Runner";

    /// <summary>The process-wide source for run, pair, inventory, and mutation activities.</summary>
    public static readonly ActivitySource ActivitySource = new(ActivitySourceName);
    /// <summary>The process-wide meter that owns the following counters and millisecond histograms.</summary>
    public static readonly Meter Meter = new(MeterName);
    /// <summary>Counts cycle starts, including cycles that later fail or discover no configured pairs.</summary>
    public static readonly Counter<long> RunsStarted = Meter.CreateCounter<long>("keyvaultsync.runs.started", "{run}");
    /// <summary>Counts cycles reaching the final summary; propagated cancellation can bypass this counter.</summary>
    public static readonly Counter<long> RunsCompleted = Meter.CreateCounter<long>("keyvaultsync.runs.completed", "{run}");
    /// <summary>Counts processed pair attempts, with outcome supplied by the orchestration call site.</summary>
    public static readonly Counter<long> PairsProcessed = Meter.CreateCounter<long>("keyvaultsync.pairs.processed", "{pair}");
    /// <summary>Counts failures recorded at explicit call sites; it is not a count of every error log.</summary>
    public static readonly Counter<long> Failures = Meter.CreateCounter<long>("keyvaultsync.failures", "{failure}");
    /// <summary>Counts observed active names and deleted objects per scan, not unique objects across runs.</summary>
    public static readonly Counter<long> InventoriedObjects = Meter.CreateCounter<long>("keyvaultsync.objects.inventoried", "{object}");
    /// <summary>Records end-to-end cycle elapsed time in milliseconds.</summary>
    public static readonly Histogram<double> RunDuration = Meter.CreateHistogram<double>("keyvaultsync.run.duration", "ms");
    /// <summary>Records elapsed time for each processed pair attempt in milliseconds.</summary>
    public static readonly Histogram<double> PairDuration = Meter.CreateHistogram<double>("keyvaultsync.pair.duration", "ms");

    /// <summary>Forces source/instrument initialization before hosts inspect or subscribe to telemetry.</summary>
    /// <remarks>This installs no providers and emits no measurements or health checks.</remarks>
    public static void Initialize()
    {
        _ = ActivitySource;
        _ = RunsStarted;
        _ = RunsCompleted;
        _ = PairsProcessed;
        _ = Failures;
        _ = InventoriedObjects;
        _ = RunDuration;
        _ = PairDuration;
    }

    /// <summary>Adds a conventional exception event to an activity, if a listener created one.</summary>
    /// <param name="activity">The current operation's activity, or null when tracing is not listening.</param>
    /// <param name="exception">The failure whose type, message, and full exception text are recorded.</param>
    /// <remarks>
    /// This helper does not sanitize exception text or set activity status. Callers must avoid exceptions
    /// containing sensitive payloads; the presence of this helper is not a redaction guarantee.
    /// </remarks>
    public static void RecordException(Activity? activity, Exception exception)
    {
        if (activity is null)
        {
            return;
        }

        var tags = new ActivityTagsCollection
        {
            { "exception.type", exception.GetType().FullName ?? exception.GetType().Name },
            { "exception.message", exception.Message },
            { "exception.stacktrace", exception.ToString() },
        };
        activity.AddEvent(new ActivityEvent("exception", tags: tags));
    }

    /// <summary>Records observed inventory totals using bounded object-type and vault-role dimensions.</summary>
    /// <param name="inventory">The observed inventory; warnings may indicate that its counts are incomplete.</param>
    /// <param name="vaultRole">The stable role label, normally source or target, never a vault name or ID.</param>
    public static void RecordInventory(VaultInventory inventory, string vaultRole)
    {
        InventoriedObjects.Add(inventory.Secrets.Count, new("object.type", "secret"), new("vault.role", vaultRole));
        InventoriedObjects.Add(inventory.Keys.Count, new("object.type", "key"), new("vault.role", vaultRole));
        InventoriedObjects.Add(inventory.Certificates.Count, new("object.type", "certificate"), new("vault.role", vaultRole));
        InventoriedObjects.Add(inventory.DeletedSecretCount, new("object.type", "secret.deleted"), new("vault.role", vaultRole));
        InventoriedObjects.Add(inventory.DeletedKeyCount, new("object.type", "key.deleted"), new("vault.role", vaultRole));
        InventoriedObjects.Add(inventory.DeletedCertificateCount, new("object.type", "certificate.deleted"), new("vault.role", vaultRole));
    }
}