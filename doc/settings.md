# KeyVaultSync Settings

The current console runner reads CLI arguments before environment variables. The Function timer reads these as Function App **Environment variables / Application settings**; do not compile values into the app. An enabled `sync-vault-id` or `sync-source-keyvault-id` mapping is the runtime opt-in for supported synchronization; there are no separate runtime apply, native-seed, or single-writer acknowledgment switches.

Bicep generates hosted selectors and infrastructure endpoints only. Operators do not maintain a vault list or repeat the identity ID in several settings. Ordinary defaults below remain in code rather than being emitted as extra app settings. For a new deployment, choose the azd environment and location; use name overrides only when needed for adoption, and retain protected settings on later provisioning.

| Setting | Required | Default | Purpose |
| --- | --- | --- | --- |
| `AZURE_SUBSCRIPTION_ID` | Yes | None | Subscription to inventory. CLI: `--subscription`. |
| `AZURE_CLIENT_ID` | Generated for the hosted Function; unnecessary locally | Identity module output | Standard Azure.Identity selector for the attached user-assigned identity. Both entry points keep `DefaultAzureCredential`; local runs can use Azure CLI sign-in. This is a non-secret client ID, not an RBAC principal ID. |
| `KEYVAULTSYNC_STORAGE_ACCOUNT_URI` | Yes | None | HTTPS Blob service endpoint. CLI: `--storage-account-uri`. |
| `KEYVAULTSYNC_RESOURCE_GROUP` | No | All subscription vaults | Optional discovery filter. CLI: `--resource-group`. |
| `KEYVAULTSYNC_PAIR_TAG` | No | `sync-vault-id` | Configurable source-side tag containing the target Key Vault ARM resource ID. CLI: `--pair-tag`. The runtime also accepts the fixed target-side tag `sync-source-keyvault-id=<source-vault-resource-ID>`, which supports multiple targets per source. The onboarding scripts support these two canonical tags; they do not infer other custom source-tag names. |
| `KEYVAULTSYNC_STATE_CONTAINER` | No | `keyvaultsync-state` | Private container for pair state/checkpoints. CLI: `--state-container`. |
| `KEYVAULTSYNC_RUNS_CONTAINER` | No | `keyvaultsync-runs` | Private container for durable run records. CLI: `--runs-container`. |
| `KEYVAULTSYNC_INTERVAL_MINUTES` | No | `10` | Console `--watch` cadence; the Function timer will use its declared schedule. |
| `KEYVAULTSYNC_TIMER_SCHEDULE` | Yes for Function | `0 */10 * * * *` | NCRONTAB schedule used by the isolated Timer Trigger. Do not enable `RunOnStartup`. |
| `AzureWebJobsStorage` | Connection name required; exact setting is local-only here | Deployment-specific | Locally, use Azurite with `UseDevelopmentStorage=true`. In Azure, omit the exact connection-string setting and use the managed-identity settings below for timer coordination/locks. |
| `AzureWebJobsStorage__accountName` / `AzureWebJobsStorage__credential` / `AzureWebJobsStorage__clientId` | Generated for deployed Function host | Account name / `managedidentity` / central identity client ID | Identity-based host storage configuration emitted by IaC. The Functions host needs its own client-ID selector; the worker's `AZURE_CLIENT_ID` alone is not enough. |
| `FUNCTIONS_EXTENSION_VERSION` / `FUNCTIONS_WORKER_RUNTIME` / `FUNCTIONS_WORKER_RUNTIME_VERSION` | Do not set manually on deployed Flex | Platform-managed host; worker selected by `functionAppConfig.runtime` | Deprecated on Flex. IaC selects `dotnet-isolated` / `10.0` in the resource configuration and removes these legacy selectors from preserved settings. Local Core Tools still uses `FUNCTIONS_WORKER_RUNTIME=dotnet-isolated`. |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | Required for Azure telemetry | None | Application Insights destination locator. Ingestion uses `DefaultAzureCredential`/managed identity and the `Monitoring Metrics Publisher` role; local authentication is disabled on the lab component. |
| `APPLICATIONINSIGHTS_AUTHENTICATION_STRING` | Generated for deployed Azure telemetry | `ClientId=<client-id>;Authorization=AAD` | Selects the same UAMI for Function host telemetry. Worker and console exporters use their shared `DefaultAzureCredential`; no duplicate export pipeline is added. |
| `KEYVAULTSYNC_LOG_LEVEL` | No | `Information` | Minimum application log level shared by the console runner and Function worker: `Trace`, `Debug`, `Information`, `Warning`, `Error`, or `Critical`. Invalid values and `None` fall back to `Information`. Function host/runtime filtering remains controlled separately by `src/KeyVaultSync.Function/host.json`. |
| `KEYVAULTSYNC_HMAC_KEY` | Required for standalone secret writes | None | Base64-encoded 32-byte HMAC key supplied through protected Function App/local configuration. If absent, standalone secret writes are blocked; eligible native seeds are evaluated separately. Do not pass the key on the command line or store it in source control, target secrets, logs, or IaC state. |
| `KEYVAULTSYNC_HMAC_KEY_VERSION` | No | `app-config-v1` | Non-secret version label for the configured HMAC key. Change it deliberately during key rotation and rebaseline existing fingerprints only through review. |

The runtime does not check a single-writer setting. Operators must ensure this runner is the sole writer to target objects being changed; Key Vault writes have no compare-and-set condition. An enabled mapping can cause writes on the next run, so review mappings, permissions, and persisted state before deployment. `KeyVaultSyncDisabled=true` on either vault pauses the pair.

## Hosted Runtime and Identity

Flex runtime selection is resource configuration, not an application setting: `properties.functionAppConfig.runtime.name=dotnet-isolated` and `.version=10.0`. Memory is 512, 2048, or 4096 MB (default 2048); the maximum on-demand instance count is 1-1000 (default 10). The Function uses the same user-assigned identity for deployment storage, host storage, and runner Azure calls. Bicep attaches it and wires each platform's selector automatically. Do not add a connection-string `AzureWebJobsStorage`, `AzureWebJobsStorage__managedIdentityResourceId`, or service-principal secret/certificate credentials alongside this configuration. The default credential chain is retained, so an earlier configured credential can still take precedence.

For later provisioning, `preserveExistingAppSettings=true` retains the out-of-band HMAC key and custom settings while filtering eight names case-insensitively: the three deprecated runtime selectors above, exact `AzureWebJobsStorage`, `AzureWebJobsStorage__managedIdentityResourceId`, and the three retired runtime gates (`KEYVAULTSYNC_APPLY_SECRETS`, `KEYVAULTSYNC_SEED_MISSING_KEYS_AND_CERTIFICATES`, and `KEYVAULTSYNC_SINGLE_WRITER_MODE`). An exact connection string would override prefixed host settings, and client-ID/resource-ID selectors are mutually exclusive. This merge does not remove arbitrary credentials; review those separately through the protected configuration path. The false/default branch is for initial provisioning and does not retain custom settings. See [deployment.md](deployment.md) and the [Microsoft Flex settings reference](https://learn.microsoft.com/azure/azure-functions/functions-app-settings#flex-consumption-plan-deprecations).

## Per-Vault Disable Control

Use the Azure Resource Manager tag `KeyVaultSyncDisabled=true` on either Key Vault to disable synchronization for its pair. The tag key is fixed and the value comparison is case-insensitive after trimming whitespace; only the value `true` activates the control.

- On a source vault, the tagged source is not paired.
- On a target vault, the source-to-target pair is not paired.
- Discovery records the intentional suppression in the run record and telemetry; it does not report a mapping error.
- The runner does not acquire the pair lease, read Key Vault data-plane objects, write secrets, advance the checkpoint, or delete existing state because of the tag.
- Remove the tag or change its value to anything other than `true` to allow the next scheduled run to admit the pair again. Existing pending-write or baseline safety checks still apply after re-enablement.

Apply the tag through Azure Resource Manager, Azure CLI, the portal, or another approved resource-management path. This is a resource-level control, not a Function App setting, and it does not require a Function restart.

## Configuration Ownership

- **IaC-owned Function settings:** `AZURE_CLIENT_ID`, three host-storage settings, two Application Insights settings, subscription, state/run Blob endpoint, and timer schedule. Flex runtime/scaling and deployment-storage identity belong to `functionAppConfig`.
- **Code defaults / optional overrides:** pair tag (`sync-vault-id`), resource-group filter, state/run container names, HMAC key-version label, and log level are not generated app settings. Existing overrides survive only with the preservation gate; nondefault containers require corresponding reviewed resources and grants. The onboarding scripts support `sync-vault-id` and `sync-source-keyvault-id`; a custom source-side mapping tag requires a corresponding reviewed access workflow.
- **Protected operator settings:** `KEYVAULTSYNC_HMAC_KEY` is supplied only through protected Function App or local environment configuration for standalone secret writes; if omitted, secret plan items remain blocked. Native key/certificate seeds do not use this secret-value HMAC. The key is never an IaC parameter.
- **Managed identity:** Azure access uses `DefaultAzureCredential`; Bicep provisions/attaches the UAMI and infrastructure roles. The separate onboarding script grants existing-vault access after preview and approval. `KEYVAULTSYNC_IDENTITY_RESOURCE_ID` is a non-secret deployment output for that script, not a runtime setting.
- **Resource-management control:** `KeyVaultSyncDisabled=true` is an ARM tag on an existing Key Vault, not a Function setting. It is evaluated during subscription discovery.
- **Deployment-only parameters:** environment/resource names (including optional `managedIdentityName`), location, retention, Flex limits, timer schedule, and `preserveExistingAppSettings`. There is no `existingKeyVaults` or `allowSecretValueRead` main-template parameter; vault onboarding uses discovery and a preview/apply operator workflow.

## CLI Flags

- `--watch`: repeat console scans at `KEYVAULTSYNC_INTERVAL_MINUTES`.
- `--help`: show local runner usage.

An enabled mapping automatically evaluates supported guarded secret writes and eligible one-time native seeds. A missing HMAC key blocks secret writes; target-safety checks and the pair-scoped backup/restore permissions still apply. Retired runtime switches and environment settings are rejected at startup and must be removed. The onboarding scripts' `--apply` / `-Apply` option is separate: it explicitly approves IAM changes, not runtime synchronization.

## Local Example

Set values in the shell session, not in source files. Retrieve the Application Insights connection string from the intended component without printing it, and provide subscription/storage settings explicitly. With an enabled mapping and effective write permissions, the runner can mutate eligible target objects; use `KeyVaultSyncDisabled=true` to pause a pair that is not ready. Omitting the HMAC key blocks standalone secret writes but does not disable eligible native seeds.

```sh
az login
export AZURE_SUBSCRIPTION_ID="<subscription-id>"
export KEYVAULTSYNC_STORAGE_ACCOUNT_URI="https://<storage-account>.blob.core.windows.net/"
export APPLICATIONINSIGHTS_CONNECTION_STRING="<application-insights-connection-string>"
dotnet run --project src/KeyVaultSync.Runner/KeyVaultSync.Runner.csproj
```

There is no need to copy the hosted `AZURE_CLIENT_ID` into the local environment. The signed-in developer needs their own resource permissions; UAMI grants do not grant the developer access. For standalone secret synchronization, provide `KEYVAULTSYNC_HMAC_KEY` and, when rotating, `KEYVAULTSYNC_HMAC_KEY_VERSION` through protected environment configuration; never pass the key on the command line. Native key/certificate seeds do not require this HMAC key. Hosted access uses the central user-assigned identity selected by Bicep. Assign only necessary roles at the specific resources/containers. Store no client secret or storage account key in application settings, and keep the HMAC key out of source control and IaC state.

## HMAC Rotation and Rebaseline

The HMAC key and its version label are an integrity boundary for committed secret baselines, not for native seed baselines. Keep the mapped pair paused with `KeyVaultSyncDisabled=true` while changing either value. During automatic secret synchronization, a changed `KEYVAULTSYNC_HMAC_KEY_VERSION` causes existing secret baselines to return `BLOCKED_HMAC_KEY_VERSION_CHANGED`; planning does not rebaseline anything. The current runner deliberately has no automatic rebaseline command, and the block must not be bypassed by editing Blob state by hand.

Before a future approved rotation, preserve the existing pair-state blobs and old protected configuration, generate a new random 32-byte key, and assign a new version label through protected Function App configuration. An explicit reviewed rebaseline workflow must then recompute and verify each source/target value and metadata baseline before the pair is resumed. Do not rotate the production key until that workflow has been implemented and tested; never place either key or a rebaseline value in Bicep, parameters, logs, or source control.
