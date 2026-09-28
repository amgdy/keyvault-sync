# KeyVaultSync Agent Guide

## Purpose

KeyVaultSync is a .NET 10 console runner and isolated Azure Functions timer for discovering mapped Azure Key Vault pairs, inventorying metadata, planning changes, and automatically executing supported synchronization for enabled pairs.

Use neutral product terminology. Source-side `sync-vault-id` maps a source vault to one target; target-side `sync-source-keyvault-id` maps a target back to its source and permits multiple targets per source. `KeyVaultSyncDisabled=true` suppresses a pair during discovery. Disaster recovery is a use case, not the product or repository name.

## Current Boundaries

- `KeyVaultSync.Function` is a thin timer/host adapter; `RunnerApplication` owns run and pair orchestration.
- `ArmResourceClient` owns subscription discovery and declared-authorization inventory.
- `VaultInventoryScanner` performs value-free inventory; the planner is pure; `SecretSyncExecutor` owns guarded secret synchronization; `NativeSeedExecutor` owns eligible one-time key and certificate-group seeds.
- An enabled, unpaused mapping is the runtime opt-in for supported operations. Native key/certificate seeds are one-time operations, not recurring synchronization or rotation. Delete/purge and authorization reconciliation remain plan-only. Do not broaden these boundaries without implementing and testing the owning operations.
- Preserve HMAC baselines, pending-write intent, the no-retry boundary, exact-version verification, lease/ETag checks, and the operational single-writer requirement. A missing HMAC key blocks standalone secret writes, not eligible native seeds.
- Never create, replace, delete, or purge source/target Key Vaults through the application's infrastructure.

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
bash tests/preprovision-resource-group-tag.tests.sh
bash tests/postdeploy-keyvault-access.tests.sh
pwsh -NoProfile -File tests/Grant-KeyVaultAccess.Tests.ps1
pwsh -NoProfile -File tests/PreProvision-ResourceGroupTag.Tests.ps1
pwsh -NoProfile -File tests/PostDeploy-KeyVaultAccess.Tests.ps1
az bicep build --file infra/main.bicep --outfile /tmp/keyvaultsync-main.json
```

PowerShell is supported on Windows and Azure Cloud Shell; Bash requires `jq`. The mocked script tests must not call live Azure. Do not run secret synchronization to validate docs, tags, credentials, or permissions.

## Documentation

 Keep the README, `doc/`, examples, scripts, and Bicep aligned with actual behavior. Separate implemented features from future design. Mark environment-specific behavior as an example, not a guarantee. The root `LICENSE` is MIT; do not add per-file license headers.
