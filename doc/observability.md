# KeyVaultSync Observability

## Signals

The console runner uses the Azure Monitor OpenTelemetry exporter with a stable `KeyVaultSync.Runner` service identity. It exports:

- Serilog formats console-runner `ILogger` events as structured output, with `SourceContext`, named properties, and log scopes. The `ILogger` factory also registers the Azure Monitor OpenTelemetry provider; it exports the same events to `AppTraces` when an Application Insights connection string is configured. The exporter authenticates with `DefaultAzureCredential`.
- The isolated Function uses its OpenTelemetry worker provider directly for App Insights export. Logging scopes are enabled so run IDs, pair IDs/names, status, durations, inventory counts, and warning counts accompany the events. No Serilog Application Insights sink is configured, avoiding a second route that could bypass Entra authentication or duplicate telemetry.
- Stable-ID structured records for each discovered Key Vault (`EventId` 1100), each sync-pair decision (`EventId` 1101), and each Key Vault key name (`EventId` 2100). Pair records include `SyncEnabled`, `SyncId`, and `Decision` as structured properties.
- Progress event IDs cover ARM pagination (1200-1201), inventory stage start/completion/25-item progress (2000-2002), run and pair steps (3000-3003), Blob persistence and lease lifecycle (4000-4020), per-secret work steps/outcomes (5000-5001), and native seed outcomes (5100). Secret values, private key material, and HMAC fingerprints are not logged.
- Activities for a whole run, discovery, each discovered Key Vault (`arm.keyvault.discovered`), each pair evaluation (`arm.keyvault.sync-pair`), each vault inventory category, authorization reads, Blob writes/leases/checkpoints, native seed phases, and Azure SDK/HTTP dependencies to `AppDependencies` and related trace views.
- `keyvaultsync.runs.*`, `keyvaultsync.pairs.processed`, `keyvaultsync.failures`, `keyvaultsync.objects.inventoried`, and run/pair duration histograms, plus .NET runtime metrics, in `AppMetrics`.

The console runner has no inbound HTTP server, so an empty `AppRequests` table is expected. The timer Function also runs as a background operation; dependency spans and custom activities remain the primary troubleshooting path.

Trace sampling is configured to 100% because the lab runner is low volume. Re-evaluate sampling and ingestion limits before production rollout. The exporter flushes providers during shutdown and has offline storage enabled by its defaults. Connection strings identify the destination; Entra authentication is used for ingestion. The Function managed identity must have `Monitoring Metrics Publisher` scoped to its Application Insights component.

### Severity Levels

`KEYVAULTSYNC_LOG_LEVEL` is a minimum threshold shared by the console runner and Function worker. The supported values map to .NET/Serilog/OpenTelemetry as follows:

| Level | Use |
| --- | --- |
| `Trace` | Every ARM GET attempt and response, secret/key/certificate version metadata, and detailed inventory progress. High volume; use briefly for diagnosis. |
| `Debug` | Per-object inventory summaries, precondition checks, lease renewals, and internal phase details. |
| `Information` | Run/pair lifecycle, each Key Vault and key name, inventory stage summaries, durable intent/write/commit progress, and successful outcomes. |
| `Warning` | ARM retries, mapping issues, incomplete inventory, lock contention, blocked/conflicting plans, and partial runs. |
| `Error` | Pair/stage failures, persistence failures, failed apply steps, and unresolved write outcomes. |
| `Critical` | A terminal whole-run failure or Function timer run failure. |

The default is `Information`. Invalid values and `None` fall back to `Information`. `src/KeyVaultSync.Function/host.json` separately filters host/runtime logs; this setting controls application/worker logs. A threshold filters lower-severity events before console/App Insights export.

## Safety

Logs may include vault names, key names, secret names, version IDs, resource IDs, the source's configured pair-tag value, the target's `sync-source-keyvault-id` value, and exception stack traces. Treat these as potentially identifying operational metadata and restrict telemetry access accordingly. Secret values, private key material, HMAC keys/digests, bearer tokens, and connection strings must never be logged. Do not log all ARM tags; only the two supported pair-mapping values are emitted.

## KQL

Recent run and pair messages:

```kusto
AppTraces
| where TimeGenerated > ago(24h)
| where AppRoleName contains "KeyVaultSync"
| where Message has "Run " or Message has "Pair " or Message has "inventory"
| project TimeGenerated, SeverityLevel, Message, OperationId, Properties
| order by TimeGenerated desc
```

Severity distribution:

```kusto
AppTraces
| where TimeGenerated > ago(24h)
| where AppRoleName contains "KeyVaultSync"
| summarize Events=count() by Level=case(
    SeverityLevel == 0, "Trace",
    SeverityLevel == 1, "Information",
    SeverityLevel == 2, "Warning",
    SeverityLevel == 3, "Error",
    SeverityLevel == 4, "Critical",
    "Other")
| order by Events desc
```

End-to-end progress timeline:

```kusto
AppTraces
| where TimeGenerated > ago(24h)
| where AppRoleName contains "KeyVaultSync"
| where Message has_any (
    "discovery page completed",
    "inventory stage started",
    "inventory stage completed",
    "inventory is progressing",
    "Pair state lease",
    "Pair inventories complete",
    "Creating the synchronization plan",
    "Secret apply",
    "Secret sync step",
    "Secret sync outcome",
    "Pair state persisted",
    "Run progress record persisted")
| project TimeGenerated, SeverityLevel, Message, OperationId, Properties
| order by TimeGenerated asc
```

Failures and partial runs:

```kusto
AppTraces
| where TimeGenerated > ago(24h)
| where SeverityLevel >= 3
| project TimeGenerated, SeverityLevel, Message, OperationId, Properties
| order by TimeGenerated desc
```

Run outcomes that need operator attention:

```kusto
AppTraces
| where TimeGenerated > ago(24h)
| where AppRoleName contains "KeyVaultSync"
| where Message has_any ("completed with status Partial", "completed with status Failed", "finished with status Partial", "finished with status Failed", "SyncCompletedWithUnappliedWork", "PartialInventory", "NATIVE_SEED_OUTCOME_UNRESOLVED", "inventory incomplete", "could not persist")
| project TimeGenerated, SeverityLevel, Message, OperationId, Properties
| order by TimeGenerated desc
```

Intentional per-vault suppressions:

```kusto
AppTraces
| where TimeGenerated > ago(24h)
| where AppRoleName contains "KeyVaultSync"
| where Message has_any ("disabled pairs", "KeyVaultSyncDisabled=true")
| project TimeGenerated, SeverityLevel, Message, OperationId, Properties
| order by TimeGenerated desc
```

Discovered vaults, pair eligibility, and key names:

```kusto
AppTraces
| where TimeGenerated > ago(24h)
| where Message startswith "Discovered Key Vault "
    or Message startswith "Key Vault sync pair evaluated."
    or Message startswith "Discovered Key Vault key "
| project TimeGenerated, EventId=tostring(Properties["EventId"]), Message,
    KeyVaultName=tostring(Properties["KeyVaultName"]),
    SourceVaultName=tostring(Properties["SourceVaultName"]),
    TargetVaultName=tostring(Properties["TargetVaultName"]),
    KeyName=tostring(Properties["KeyName"]),
    HasSyncId=tobool(Properties["HasSyncId"]),
    SyncId=tostring(Properties["SyncId"]),
    SyncEnabled=tobool(Properties["SyncEnabled"]),
    Decision=tostring(Properties["Decision"]), OperationId
| order by TimeGenerated desc
```

Slow dependencies:

```kusto
AppDependencies
| where TimeGenerated > ago(24h)
| summarize Calls=count(), Failures=countif(Success == false), P95=percentile(DurationMs, 95) by Name, Target
| order by P95 desc
```

Slow custom run/pair activities appear as dependencies:

```kusto
AppDependencies
| where TimeGenerated > ago(24h)
| where Name in ("sync.run", "sync.scan-pair", "keyvault.inventory")
| project TimeGenerated, Name, DurationMs, Success, OperationId, Properties
| order by TimeGenerated desc
```

Slow vault inventory stages:

```kusto
AppDependencies
| where TimeGenerated > ago(24h)
| where Name startswith "keyvault.inventory"
| summarize Calls=count(), Failures=countif(Success == false), P95=percentile(DurationMs, 95) by Name, Target
| order by P95 desc
```

Lease, checkpoint, and write-intent failures:

```kusto
AppTraces
| where TimeGenerated > ago(24h)
| where AppRoleName contains "KeyVaultSync"
| where Message has_any ("lease", "checkpoint", "pending write", "write intent", "outcome unresolved")
| project TimeGenerated, SeverityLevel, Message, OperationId, Properties
| order by TimeGenerated desc
```

Inventory warnings and incomplete observations:

```kusto
AppTraces
| where TimeGenerated > ago(24h)
| where AppRoleName contains "KeyVaultSync"
| where Message has_any ("inventory", "warning", "soft-deleted", "unmapped", "partial")
| project TimeGenerated, SeverityLevel, Message, OperationId, Properties
| order by TimeGenerated desc
```

Runner counters and duration metrics:

```kusto
AppMetrics
| where TimeGenerated > ago(24h)
| where Name startswith "keyvaultsync."
| summarize Sum=sum(Sum), Samples=count() by Name
| order by Name asc
```

Lease, checkpoint, and inventory warnings can be filtered from `AppTraces` by message text (`lease`, `checkpoint`, `warning`, `partial`, `failed`) and joined to dependency spans by `OperationId`.
