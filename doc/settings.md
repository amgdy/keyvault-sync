# KeyVaultSync Settings

The Function reads runtime configuration from application settings. Command-line runtime configuration is not supported.

| Setting | Required | Default | Purpose |
|---|---|---|---|
| `KEYVAULTSYNC_SUBSCRIPTIONS` | Yes | None | Comma-, semicolon-, or whitespace-separated subscription GUIDs scanned as one graph. |
| `KEYVAULTSYNC_STORAGE_ACCOUNT_URI` | Yes | None | HTTPS Blob service endpoint for state, leases, and run reports. |
| `KEYVAULTSYNC_STATE_CONTAINER` | No | `keyvaultsync-state` | Private container for pair state. |
| `KEYVAULTSYNC_RUNS_CONTAINER` | No | `keyvaultsync-runs` | Private container for durable run reports. |
| `KEYVAULTSYNC_HMAC_KEY` | Yes for object writes | None | Base64-encoded 32-byte HMAC-SHA256 key. Missing or invalid material blocks guarded object writes. |
| `KEYVAULTSYNC_HMAC_KEY_VERSION` | No | `app-config-v1` | Non-secret label persisted with signatures to detect incompatible key changes. |
| `KEYVAULTSYNC_PRINCIPAL_ID` | Generated in Azure | None | Runtime managed identity object GUID used to prevent self-revocation during RBAC cleanup. |
| `KEYVAULTSYNC_TIMER_SCHEDULE` | Yes for Function | `0 */10 * * * *` | NCRONTAB timer schedule. |
| `AZURE_CLIENT_ID` | Generated in Azure | None | User-assigned managed identity client ID used by `DefaultAzureCredential`. |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | Yes for Azure telemetry | None | Application Insights destination. |
| `APPLICATIONINSIGHTS_AUTHENTICATION_STRING` | Generated in Azure | None | Managed-identity telemetry authentication selector. |
| `KEYVAULTSYNC_LOG_LEVEL` | No | `Information` | Worker application log minimum level. |

The deployed Functions host also uses identity-based `AzureWebJobsStorage__accountName`, `AzureWebJobsStorage__credential`, and `AzureWebJobsStorage__clientId` settings. Local development may use `AzureWebJobsStorage=UseDevelopmentStorage=true`.

## Mapping and Pause Control

Each target vault declares:

```text
sync-source-keyvault-id=<source-vault-resource-ID>
```

The source and target must be in `KEYVAULTSYNC_SUBSCRIPTIONS`, share a tenant, and use Azure RBAC. One source may map to multiple targets. `KeyVaultSyncDisabled=true` on either endpoint pauses the pair. Tag-key matching and the `true` value comparison are case-insensitive.

The retired source-side `sync-vault-id` tag does not enable discovery.

## HMAC Key Handling

The shared azd deployment-preparation hook runs before provisioning and before every package deployment. If the active environment has no key, an interactive run shows one hidden prompt: paste an existing Base64-encoded 256-bit key, or press Enter to generate one cryptographically. The key is saved once; the later predeploy invocation reuses it without prompting. Non-interactive runs must receive the key from protected pipeline configuration.

When a valid environment key already exists, the hook reuses it without displaying or rotating it. The ignored `.azure/<environment>/.env` contains the plaintext value; protect it and backups, do not enable shell tracing, and do not copy it to tickets, logs, or telemetry.

Changing the key or version label makes existing baselines incompatible. There is no runtime rebaseline bypass. Rebaseline must be an explicit reviewed administrative operation.

## Operational Contract

An enabled mapping opts into supported writes. There are no apply switches. Before enabling a mapping:

- review the source and target;
- apply only the required IAM grants;
- ensure KeyVaultSync is the sole writer for managed target objects;
- preserve state storage and the HMAC key;
- understand that eligible target-only managed objects may be soft-deleted.

The maximum Function instance count is not the correctness boundary. Pair Blob leases and ETags coordinate KeyVaultSync runs, but cannot fence unrelated writers.
