using System.Runtime.CompilerServices;

// Expose internal planning, configuration, and security helpers to the focused safety suite
// without turning these implementation contracts into public application APIs.
[assembly: InternalsVisibleTo("KeyVaultSync.Runner.Tests")]
// The isolated Function reuses internal telemetry source names, level parsing, and the timer invocation
// handler that owns its structured start/completion records; its orchestration entry point remains
// RunnerApplication.ExecuteScheduledRunAsync.
[assembly: InternalsVisibleTo("KeyVaultSync.Function")]
// The terminal host runs one cycle through RunnerApplication and reuses the console telemetry runtime and the
// local settings-file loader; it adds no separate orchestration or mutation path.
[assembly: InternalsVisibleTo("KeyVaultSync.Cli")]
