# KeyVaultSync Observability

KeyVaultSync emits structured logs, W3C activities, Azure SDK dependencies, low-cardinality metrics, and durable private run reports.

## Implemented Signals

Structured logs cover run start/completion, discovery, pair lease and planning progress, inventory stages, plan persistence, object mutation intent and verification, RBAC execution, and pair completion. Logger scopes carry the run and pair correlation context through child services.

Administrator-facing events use stable IDs and `KVS-*` diagnostic codes:

| Event ID | Event name | Purpose |
|---:|---|---|
| `5000` | `InventoryWarning` | One value-free category for each source or target inventory warning |
| `5001` | `PlanOutcomeSummary` | Counts of blocked, conflicting, failed, or unresolved plan items grouped by status, object type, and action |
| `5002` | `RbacOutcome` | RBAC readiness, success, self-protection, validation, mutation, and verification outcomes with bounded scope kind and role ID |
| `5003` | `PairDiagnosticSummary` | Pair status and aggregate source warnings, target warnings, attention items, and failed RBAC items |
| `5004` | `DiscoveryDecision` | Every enabled, disabled, or rejected source/target mapping decision |
| `5005` | `ObjectOutcome` | Every object safety, mutation, exact-verification, conflict, and ambiguous-intent outcome |
| `5006` | `RunDiagnosticSummary` | Complete, empty, partial, cancelled, failed, or unknown terminal run classification |
| `5007` | `SystemFailure` | Bounded configuration, storage, lease, scan, execution, or orchestration failure category |
| `5008` | `LifecycleTransition` | Run, discovery, inventory, planning, and execution stage transitions for timeline reconstruction |

Planning and execution emit all current statuses, including ready/in-sync/success states, not only failures. This allows the analyzer to distinguish missing evidence from an explicitly successful check. Diagnostic properties intentionally contain bounded categories and counts. They do not contain object values, HMAC material, principal IDs, or complete ARM scopes. The exact affected vaults, objects, and plan-item details remain in the protected durable run record.

Every administrator diagnostic uses the same bounded decision fields:

- `DiagnosticCode`, `DiagnosticStage`, and `DiagnosticOutcome`;
- `EvidenceType` (`Evidence` for runtime observations);
- `AdminPriority` (`Critical`, `High`, `Medium`, or `None`);
- `ActionDecision` (`AdminReviewRequired`, `NoActionRequired`, or a lifecycle action);
- `Confidence` (`High` for cataloged outcomes and `Low` for unknown fallbacks);
- `AdminAction` for the identifier-free inferred recommendation.

Logger scopes provide `RunId` and, during pair work, `PairId`. Object events add `ObjectType` and `ObjectAction`; authorization events add bounded `ScopeKind` and `ObjectAction`. Raw object names, principal IDs, and complete authorization scopes are intentionally excluded from these new correlation fields. Use the protected durable record when exact subject identity is required.

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

The [offline log analyzer](../tools/keyvaultsync-log-analyzer.html) redacts common ARM IDs, GUIDs, run IDs, service hosts, and labeled vault/object names by default. It visibly separates parsed evidence from inferred recommendations, derives a `Healthy`, `Needs review`, `Partial`, or `Blocked` assessment, and ranks actions from P1 through P4. `KVS-RBAC-403`, ambiguous object outcomes, unresolved intents, pair-state persistence failures, and lease-renewal failures are P1. Inventory warnings always produce at least a `Partial` assessment.

Sanitized summaries can be downloaded as JSON for automation or as a standalone HTML report. Both formats exclude the source filename and apply redaction to evidence text. This is a sharing aid, not a declassification guarantee. Review every downloaded sanitized summary before sharing it outside the authorized operational team.

The analyzer catalog covers:

- every current discovery eligibility decision;
- all inventory warning categories;
- every planner and object/RBAC executor status;
- every terminal pair and run status;
- HMAC configuration, Blob initialization/persistence, lease renewal/release, pair scan/execution, and orchestration failures;
- legacy message signatures from deployments that predate diagnostic codes.

Tests require every runtime diagnostic code to exist in the analyzer. An unknown status is elevated as `KVS-PLAN-UNKNOWN-STATUS`, `KVS-PAIR-UNKNOWN`, `KVS-RUN-UNKNOWN`, or the corresponding discovery/system fallback instead of being treated as success.

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

## Querying Diagnostic Codes

Use diagnostic codes rather than message text for alerts and workbooks created after this logging contract is deployed:

```kusto
AppTraces
| where TimeGenerated > ago(24h)
| extend DiagnosticCode = tostring(Properties["DiagnosticCode"])
| where DiagnosticCode startswith "KVS-"
| project TimeGenerated, SeverityLevel, DiagnosticCode,
    DiagnosticStage = tostring(Properties["DiagnosticStage"]),
    DiagnosticOutcome = tostring(Properties["DiagnosticOutcome"]),
    AdminPriority = tostring(Properties["AdminPriority"]),
    ActionDecision = tostring(Properties["ActionDecision"]),
    Confidence = tostring(Properties["Confidence"]),
    VaultRole = tostring(Properties["VaultRole"]),
    PlanStatus = tostring(Properties["PlanStatus"]),
    ScopeKind = tostring(Properties["ScopeKind"]),
    HttpStatus = toint(Properties["HttpStatus"]),
    ErrorCode = tostring(Properties["ErrorCode"]),
    AdminAction = tostring(Properties["AdminAction"])
| order by TimeGenerated desc
```

Do not add subscription IDs, vault names, object names, principal IDs, or full scopes as metric dimensions. Diagnostic codes and the fields above are intended for logs only; existing metrics remain deliberately low-cardinality.
