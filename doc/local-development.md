# Local Development

## Prerequisites

- .NET 10 SDK
- Azure Functions Core Tools v4
- Azure CLI
- Azurite
- Bash plus `jq`, and/or PowerShell 7 for operator script tests

## Dev Container

The repository includes a feature-based [development container](../.devcontainer/devcontainer.json) with the .NET 10 SDK, the latest Azure CLI and Bicep, the stable Azure Developer CLI, Azure Functions Core Tools v4, PowerShell, and the VS Code extensions used by this project. Open the repository in VS Code and choose **Reopen in Container** when prompted.

Microsoft-maintained Dev Container features provide Azure CLI and Azure Developer CLI; the .NET image already includes PowerShell. Azure Functions Core Tools uses a community feature because Microsoft does not currently publish an equivalent feature. The Compose-based environment runs Microsoft's official Azurite image in the development container's network namespace, so `UseDevelopmentStorage=true` continues to resolve its services on `localhost`, and it exposes the Functions host and Azurite ports. Authenticate inside the container before using Azure-backed local settings:

```sh
azd config set auth.useAzCliAuth true
az login
```

The Dev Container runs the azd configuration command automatically after creation. Azure CLI owns the single interactive sign-in, and azd delegates authentication to that session.

The container does not include credentials, `local.settings.json`, an HMAC key, or Azure resource configuration. Copy `src/KeyVaultSync.Function/local.settings.example.json` to ignored `src/KeyVaultSync.Function/local.settings.json` and provide approved disposable values privately.

## Build and Test

```sh
dotnet restore
dotnet test tests/KeyVaultSync.Runner.Tests/KeyVaultSync.Runner.Tests.csproj --no-restore
dotnet build src/KeyVaultSync.Function/KeyVaultSync.Function.csproj --no-restore -p:GenerateDocumentationFile=true -warnaserror
bash tests/grant-keyvault-access.tests.sh
bash tests/prepare-deployment.tests.sh
bash tests/postdeploy-keyvault-access.tests.sh
pwsh -NoProfile -File tests/Grant-KeyVaultAccess.Tests.ps1
pwsh -NoProfile -File tests/Prepare-Deployment.Tests.ps1
pwsh -NoProfile -File tests/PostDeploy-KeyVaultAccess.Tests.ps1
az bicep build --file infra/main.bicep --outfile /tmp/keyvaultsync-main.json
```

Script tests use mocked Azure CLI behavior and must not make live Azure changes.

## Local Function Host

Authenticate with Azure CLI for a specifically approved tenant, then run the Function host from `src/KeyVaultSync.Function`. In the Dev Container, Azurite starts as a sidecar. In VS Code, **Run and Debug** → **.NET: Attach to KeyVaultSync Function** starts the local host through the pre-launch task, uses the Azure Functions process picker to select the isolated .NET worker, and attaches the debugger. Outside the container, start Azurite separately before launching the debugger.

The local identity must have the same least-privilege ARM, Blob, Key Vault, and RBAC permissions needed by the behavior being tested. A passing unit test or successful host startup does not prove live permissions or safe mutation.

## Terminal Runner

`src/KeyVaultSync.Cli` runs exactly one cycle with the same `RunnerApplication` as the timer Function and streams structured logs to the console. It does not call, require, or depend on a deployed Function App, Functions Core Tools, or Azurite: it runs as your signed-in Azure identity and talks directly to Azure Resource Manager, the Key Vaults, and the configured state storage account.

```sh
az login
# From the repository root after `azd provision`/`azd up`: reads the default azd environment.
dotnet run --project src/KeyVaultSync.Cli
# A named azd environment, a Functions settings file, or plain arguments:
dotnet run --project src/KeyVaultSync.Cli -- --azd-env <env-name>
dotnet run --project src/KeyVaultSync.Cli -- --settings src/KeyVaultSync.Function/local.settings.json
dotnet run --project src/KeyVaultSync.Cli -- --no-azd \
  --subscriptions "<subscription-guid>" \
  --storage-account-uri "https://<account>.blob.core.windows.net/" \
  --hmac-key-file ~/.keyvaultsync/hmac.key
```

Configuration precedence, highest first:

1. Arguments: `--subscriptions`, `--storage-account-uri`, `--hmac-key-file`, `--principal-id`, `--state-container`, `--runs-container`, and `--log-level`.
2. Environment variables already set in the shell.
3. `--settings`, which loads the `Values` object of the ignored Functions settings file.
4. The azd environment file `.azure/<name>/.env`, selected by `--azd-env` or, when neither `--settings` nor `--no-azd` is given, by `AZURE_ENV_NAME` or the azd default environment. Only an allowlist of runner settings is imported (`KEYVAULTSYNC_SUBSCRIPTIONS`, `KEYVAULTSYNC_STORAGE_ACCOUNT_URI`, `KEYVAULTSYNC_HMAC_KEY`, `KEYVAULTSYNC_HMAC_KEY_VERSION`, `KEYVAULTSYNC_PRINCIPAL_ID`, container names, and log level); other azd values are ignored.

Notes:

- The HMAC key is never accepted as a command-line argument, because arguments are visible in shell history and process listings. Use the azd environment, an environment variable, the settings file, or `--hmac-key-file`. Only setting names are logged, never values.
- When nothing configures subscriptions and state storage, the CLI prints `[KVS-CONFIG-MISSING]` with the three options above and exits `3` without contacting Azure.
- When `KEYVAULTSYNC_PRINCIPAL_ID` is not configured, the CLI uses the object ID of the signed-in identity, so target-only RBAC cleanup still protects the identity that is running. If a configured value (for example one copied from the Function app settings) differs from the signed-in identity, the CLI stops with exit code 3 before any Azure work, because cleanup would protect the wrong identity. Unset `KEYVAULTSYNC_PRINCIPAL_ID` or sign in as that principal.
- Use the deployment's state storage account and HMAC key. A separate state account or a different HMAC key makes the CLI and the Function treat each other's targets as unmanaged or baseline-incompatible.
- With the `private` network profile, the state storage account has public network access disabled. Run the CLI from a network that can reach the private endpoints; the CLI warns when the azd environment reports a private profile.
- Your identity needs the same Key Vault roles as the runtime identity plus **Storage Blob Data Contributor** on the state storage account. Grant them with `--include-signed-in-user --storage-account-uri <uri>` (Bash) or `-IncludeSignedInUser -StorageAccountUri <uri>` (PowerShell) on the grant scripts, or answer yes to the optional, default-No question in the interactive azd postdeploy hook. The scripts preview by default and change nothing without `--apply`/`-Apply` or the second confirmation.
- Set `KEYVAULTSYNC_LOG_LEVEL=Debug` or `Trace` for per-object and per-version detail. Azure Monitor export is enabled only when `APPLICATIONINSIGHTS_CONNECTION_STRING` is set; remove it from the environment for console-only output.
- Logging uses Serilog with structured message templates. The console shows a readable line with the structured properties appended as JSON; `--console-format json` prints one compact JSON (CLEF) event per line instead.
- Every run also writes the same events as compact JSON (CLEF) to `logs/keyvaultsync-<UTC time>-<pid>.clef` under the current directory. Each line has `@t`, `@m`, `@l`, `@x` (exceptions), and the named properties and scopes, such as `RunId`, `SourceVaultName`, `TargetResourceGroup`, and `DiagnosticCode`. Azure resources are logged as separate subscription ID, resource group, and name properties instead of full ARM resource IDs. Use `--log-file <path>` to choose the file or `--no-log-file` to disable it. The file is flushed per event. On macOS/Linux the directory is created owner-only (`0700`) and the file owner read/write only (`0600`). `logs/` is git-ignored. Log events never contain secret values or the HMAC key, but they do contain subscription, vault, and object identifiers, so treat the files as private. Query them with `jq`, or load them into Seq or another CLEF-aware viewer.
- `DefaultAzureCredential` uses your Azure CLI sign-in unless `AZURE_CLIENT_ID` or other credential variables select another identity.
- Press Ctrl+C once to request cooperative cancellation; a second Ctrl+C terminates immediately and can leave pending intent for the next run to resolve.
- Exit codes: `0` complete or no configured pairs, `1` failed, `2` needs attention (for example `Partial`), `3` usage or configuration error, `130` cancelled.

This is a live run, not a preview. It mutates every enabled, unpaused mapping exactly as the timer would. Pair Blob leases make an overlapping Function invocation skip a locked pair rather than write concurrently, but only point it at approved, preferably disposable, vaults during development.

## Sensitive Data

Never commit or print:

- HMAC keys;
- secret or certificate values;
- private keys;
- connection strings;
- tokens;
- tenant/subscription-specific inventories.

Protect ignored `.azure/`, `local.settings.json`, and local report files. Do not run synchronization against non-disposable vaults as a development check.
