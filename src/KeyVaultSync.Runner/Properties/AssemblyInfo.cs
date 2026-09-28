using System.Runtime.CompilerServices;

// Expose internal planning, configuration, and security helpers to the focused safety suite
// without turning these implementation contracts into public application APIs.
[assembly: InternalsVisibleTo("KeyVaultSync.Runner.Tests")]
// The isolated Function reuses internal telemetry source names and level parsing from the runner;
// its public orchestration entry point remains RunnerApplication.ExecuteScheduledRunAsync.
[assembly: InternalsVisibleTo("KeyVaultSync.Function")]