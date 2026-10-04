# KeyVaultSync Agent Guide

## Purpose

KeyVaultSync is a .NET 10 isolated Azure Functions timer for discovering mapped Azure Key Vault pairs across configured subscriptions, inventorying metadata, planning changes, and automatically executing supported synchronization for enabled pairs.

Use neutral product terminology. Runtime discovery uses target-side `sync-source-keyvault-id` to map each target back to its source and permit multiple targets per source. The retired source-side `sync-vault-id` tag is ignored by runtime discovery. `KeyVaultSyncDisabled=true` suppresses a pair during discovery. Disaster recovery is a use case, not the product or repository name.

## Current Boundaries

- `KeyVaultSync.Function` is a thin timer/host adapter; `RunnerApplication` owns run and pair orchestration.
- `ArmResourceClient` owns subscription discovery and declared-authorization inventory.
- `VaultInventoryScanner` performs value-free inventory; `ReplicationPlanner` is pure; `ObjectExecutor` owns guarded secret/certificate writes and soft deletes; `RbacExecutor` owns allowlisted direct Key Vault RBAC reconciliation.
- An enabled, unpaused mapping is the runtime opt-in for supported operations. Secrets and exportable PFX certificates are supported. Standalone private/symmetric keys and non-exportable certificate material remain blocked. Purge is never supported.
- Preserve HMAC baselines, pending-mutation intent, the zero-retry mutation boundary, exact-result verification, lease/ETag checks, and the operational single-writer requirement. A missing HMAC key blocks object writes but not independently safe planning and RBAC work.
- Never create, replace, delete, or purge source/target Key Vaults through the application's infrastructure.

## Deployment Scripts

- `prepare-deployment.sh` and `Prepare-Deployment.ps1` are the only azd preparation hooks. The `provision` phase validates subscriptions, obtains or preserves the HMAC key, and handles the optional deployment tag. The `deploy` phase revalidates the HMAC key and deployment-storage reachability before package upload.
- Never generate or rotate an HMAC key when an environment already has one. A replacement makes existing baselines incompatible. Non-interactive deployment must receive the key through protected pipeline configuration.
- `postdeploy-keyvault-access.*` discovers enabled mappings and delegates to `grant-keyvault-access.*`. Grant scripts preview by default and require explicit apply approval.
- Do not add backup/restore, vault replacement, purge, mapping-tag mutation, or live synchronization to deployment hooks.

## Privacy and Security

- Keep `.azure/`, `local.settings.json`, local environment files, build output, subscription-specific working notes, and private review material out of public commits.
- Never commit tenant/subscription IDs, resource inventories, customer names, access tokens, credentials, connection strings, HMAC keys, secret values, or private key material.
- Do not add organization-specific Azure Policy exceptions or claims of policy compliance to reusable infrastructure.
- DefaultAzureCredential is used in both hosts. Bicep supplies the hosted UAMI client ID; do not introduce competing hosted credentials.
- Live Azure reads may be used to diagnose. Before deployments, permission changes, resource deletion, or secret mutation, confirm the exact scope and authorization. Never clean an entire subscription based on a broad label.

## Development Checks

Run focused checks from the repository root:

```sh
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

PowerShell is supported on Windows and Azure Cloud Shell; Bash requires `jq`. The mocked script tests must not call live Azure. Do not run secret synchronization to validate docs, tags, credentials, or permissions.

## Documentation

Keep the README, `doc/`, examples, scripts, and Bicep aligned with actual behavior. Remove superseded architecture rather than documenting multiple active designs. Mark environment-specific behavior as an example, not a guarantee. The root `LICENSE` is MIT; do not add per-file license headers.

### Documentation and Readability Practices

- Use Mermaid diagrams in architecture and flow documentation when relationships, sequencing, decision gates, or state transitions are clearer visually than as prose. Keep adjacent prose as the accessibility and implementation-detail source of truth.
- Use stable product component names in diagrams and code documentation (`RunnerApplication`, `ReplicationPlanner`, `ObjectExecutor`, `RbacExecutor`, and `BlobStateStore`). Update diagrams whenever the represented behavior changes.
- Give domain objects and variables explicit names that reveal role and direction, such as `sourceInventory`, `targetVaultClient`, `objectStateKey`, and `roleAssignment`; avoid ambiguous names such as `data`, `item`, or `source` when more than one domain object is in scope.
- Add XML documentation to active C# types and externally meaningful members. Explain ownership, safety boundaries, side effects, persisted contracts, and exceptional outcomes; do not restate obvious syntax.
- Add concise comments to each operator script's purpose, phases, helper groups, read-only preflight, mutation boundary, and failure/partial-application behavior. Never let comments imply stronger safety or verification than the script implements.
- Prefer comments that explain why a guard or ordering constraint exists. Keep simple assignments and self-explanatory calls uncommented so important safety comments remain visible.
