# KeyVaultSync Coding and Safety Guide

## Boundaries

- `Azure/ArmResourceClient.cs` owns subscription discovery and authorization inventory.
- `Azure/VaultInventoryScanner.cs` owns read-only data-plane inventory.
- `Sync/SyncPlanner.cs` is pure planning logic; it must not mutate Azure resources.
- `Sync/SecretSyncExecutor.cs` owns guarded secret synchronization.
- `Security/SecretHmacService.cs` owns HMAC computation and key zeroing.
- `State/BlobStateStore.cs` owns run records, pair state, leases, ETags, and checkpoint persistence.
- `Telemetry.cs` owns service identity, log/export providers, instruments, and custom activity sources.

## Change Rules

- For supported runtime operations, an enabled, unpaused pair mapping is the opt-in; do not add separate runtime apply or seed switches. Keep onboarding IAM writes separately gated. Every mutation still needs a plan item, preconditions, post-write verification, and a persisted intent/commit record.
- Do not infer ownership from equal names, equal secret values, equal access-policy counts, timestamps, or matching public certificate fingerprints alone.
- Re-read target state immediately before a write. When the service has no compare-and-set condition, preserve the operational single-writer requirement and never retry an ambiguous write.
- Do not advance complete-scan or deletion evidence after partial inventory, lease loss, or failed state persistence.
- HMAC values are integrity metadata, not plaintext. Never log secret values, HMAC key material, tokens, connection strings, PFX/PEM payloads, or private key material.
- Use bounded-cardinality telemetry dimensions. Vault role (`source`/`target`), operation type, and result status are suitable; secret values and arbitrary tags are not.
- Preserve backward-compatible deserialization when adding PairState fields. Missing fields must receive safe defaults.
- Keep cloud infrastructure changes in `infra/` and Azure service settings in explicit parameters. Never add source/target Key Vault resources to Bicep; they are pre-existing dependencies.

## Validation

Run the focused safety suite after changes to planner/state/HMAC logic:

```sh
dotnet test tests/KeyVaultSync.Runner.Tests/KeyVaultSync.Runner.Tests.csproj
```

Build the console runner:

```sh
dotnet build src/KeyVaultSync.Runner/KeyVaultSync.Runner.csproj
```

For a live inventory-only lab scan, ensure the pair is not enabled for automatic operations (for example, keep `KeyVaultSyncDisabled=true` on either vault), then provide `AZURE_SUBSCRIPTION_ID`, `KEYVAULTSYNC_STORAGE_ACCOUNT_URI`, and `APPLICATIONINSIGHTS_CONNECTION_STRING` through environment settings. Never place real credentials in a committed settings file.
