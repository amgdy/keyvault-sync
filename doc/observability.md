# KeyVaultSync Observability

KeyVaultSync emits structured logs, W3C activities, Azure SDK dependencies, low-cardinality metrics, and durable private run reports.

## Implemented Signals

Structured logs cover run start/completion, discovery, pair lease and planning progress, inventory stages, plan persistence, object mutation intent and verification, RBAC execution, and pair completion. Logger scopes carry the run and pair correlation context through child services.

W3C activities cover the run, discovery, pair scanning/execution, ARM reads, Key Vault inventory, Blob state operations, and Azure SDK dependencies.

The `KeyVaultSync.Runner` meter emits:

- `keyvaultsync.runs.started` and `keyvaultsync.runs.completed`;
- `keyvaultsync.pairs.processed`;
- `keyvaultsync.failures`;
- `keyvaultsync.objects.inventoried`;
- `keyvaultsync.run.duration`;
- `keyvaultsync.pair.duration`.

Metric dimensions are bounded to values such as object type, vault role, mode, and status. Detailed item outcomes and reason codes remain in logs and durable reports instead of metric dimensions.

Durable private Blob reports are the authoritative record for the discovered graph, pair plans, terminal item outcomes, and unresolved mutation intent. Telemetry is an operational index, not a replacement for those records.

## Privacy

Never export:

- secret values;
- certificate PFX or private-key material;
- HMAC keys or signatures;
- credentials, tokens, or connection strings;
- JWK material;
- raw tags when their content is not controlled.

Persisted private Blob reports may contain operational identifiers needed for review. Exported telemetry must never include object values or cryptographic material. Keep metric dimensions low-cardinality and do not add names, ARM IDs, subscription IDs, or principal IDs to metrics.

Current application logs and activities can include raw operational identifiers for diagnosis. Restrict telemetry access and retention accordingly; a future keyed-correlation sanitization pass would be required before treating exported telemetry as identifier-free.

## Application Insights

IaC configures workspace-based Application Insights with managed-identity ingestion. The Function identity receives `Monitoring Metrics Publisher`; local authentication is disabled.

Recommended production controls that are not created by the current IaC:

- retention and daily-cap policy appropriate to the environment;
- alert on timer silence;
- alert on failed/ambiguous runs;
- alert on unresolved intents;
- alert on an open deletion circuit breaker;
- workbook views for run health, pair health, action outcomes, and latency.

Alerts and workbooks are not a substitute for durable private reports or explicit intent-resolution tooling.
