# KeyVaultSync Local Development

## Prerequisites

- .NET 10 SDK.
- Azure Functions Core Tools v4 for the isolated worker.
- Azurite for local Function host storage.
- An Azure login usable by `DefaultAzureCredential` when scanning Azure resources.

The console runner and the timer Function share the same orchestration and safety rules. An enabled, unpaused mapping automatically runs supported operations, so pause the pair with `KeyVaultSyncDisabled=true` on either vault unless synchronization is intended. Standalone secret writes require a stable protected HMAC key; eligible native key/certificate-group seeds are evaluated automatically and require source backup/target restore permissions, but not the HMAC key. Operators must ensure this runner is the sole writer to target objects being changed.

## Build and Test

From the repository root:

```sh
dotnet build src/KeyVaultSync.Function/KeyVaultSync.Function.csproj --no-restore
dotnet test tests/KeyVaultSync.Runner.Tests/KeyVaultSync.Runner.Tests.csproj --no-restore
```

The focused test project covers planner safety, HMAC validation, pending-write blocking, mapping-driven execution, and one-time native seed recovery. Do not treat passing unit tests as evidence that live Key Vault writes are safe.

## VS Code Launch

The checked-in `.vscode/launch.json` contains two debug entries:

- **.NET: Launch KeyVaultSync Runner** builds the console project and launches the runner from the workspace. Provide the required subscription and Blob endpoint through the VS Code process environment before starting it. The launch file contains no credentials or HMAC values.
- **.NET: Attach to KeyVaultSync Function** attaches the debugger to the isolated worker selected by `${command:pickProcess}`. Start the `Azure Functions: Start KeyVaultSync locally` task first, or run `func start --verbose` from `src/KeyVaultSync.Function`, and ensure the ignored `local.settings.json` exists.

Use the VS Code Run and Debug view to select an entry. Keep `local.settings.json`, shell environment values, and any local HMAC key outside tracked files. The Function task uses the same Core Tools/Azurite workflow described below.

## Console Scan

Set `AZURE_SUBSCRIPTION_ID`, `KEYVAULTSYNC_STORAGE_ACCOUNT_URI`, and the intended container settings in the shell environment. Then run:

```sh
dotnet run --project src/KeyVaultSync.Runner/KeyVaultSync.Runner.csproj
```

The console runner requires an explicit subscription and Blob endpoint. It does not use the old lab resource defaults. Before running it, verify whether any enabled mappings and effective permissions permit writes. Secret actions are blocked if `KEYVAULTSYNC_HMAC_KEY` is absent; eligible one-time native seeds do not use that key.

The console runner uses Serilog for structured terminal output and the Azure Monitor OpenTelemetry exporter for App Insights. `KEYVAULTSYNC_LOG_LEVEL` applies to both the console runner and Function worker. Supported minimum levels are `Trace`, `Debug`, `Information`, `Warning`, `Error`, and `Critical`; invalid values and `None` fall back to `Information`. Use `Trace` for per-version/request diagnostics, `Debug` for object/precondition details, and `Information` for the normal run timeline. `Trace` can be high-volume and includes operational names/version IDs, never values or HMACs. When `APPLICATIONINSIGHTS_CONNECTION_STRING` is configured, the runner exports logs, traces, and metrics using `DefaultAzureCredential`. Restore packages from NuGet.org or a trusted organization mirror configured for your environment; the repository does not require a private feed.

## Timer Function

1. Start Azurite and ensure `AzureWebJobsStorage` in local settings is `UseDevelopmentStorage=true`.
2. Create `local.settings.json` from the example in `src/KeyVaultSync.Function/` without committing it.
3. Set the subscription, Blob endpoint, Function schedule, and Application Insights settings for the lab. The HMAC placeholder is not a usable key. Keep `KeyVaultSyncDisabled=true` on a mapped pair unless automatic operations are intended.
4. From `src/KeyVaultSync.Function/`, run:

```sh
func start --verbose
```

The timer uses `RunOnStartup=false` and the configured NCRONTAB schedule. A host shutdown cancels the current invocation; verify that an incomplete run does not advance the pair checkpoint.
The Function worker sends structured `ILogger` records through OpenTelemetry to Azure Monitor, with scopes enabled for run/pair correlation. `KEYVAULTSYNC_LOG_LEVEL` controls the worker minimum level; `host.json` independently controls host/runtime logs. Progress summaries are `Information`, object/precondition details are `Debug`, and per-version/request details are `Trace`.

## Local Secret Handling

Never put a real HMAC key, Application Insights connection string, storage key, token, or secret value in a tracked file. Use protected local environment configuration for a specifically approved mutation test and remove it after the lab run. The HMAC key is required only for standalone secret synchronization; it is not a runtime enable switch and does not gate eligible native seeds.
