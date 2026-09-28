# KeyVaultSync Copilot Instructions

Follow the repository-wide guidance in [AGENTS.md](../AGENTS.md). These instructions add editor-specific reminders; they do not override safety boundaries or user approval requirements.

## Before Changing Code

- Read the owning implementation, nearby tests, and relevant public documentation. Prefer a narrow, behavior-focused change.
- Keep terminology neutral: `KeyVaultSync` is the product; `sync-vault-id` maps a source to one target, and target-side `sync-source-keyvault-id` enables multiple targets per source. Disaster recovery is a possible use case, not the product name.
- Preserve architecture boundaries: the Function is a thin host, `RunnerApplication` orchestrates, ARM discovery is read-only, `SyncPlanner` is pure, `SecretSyncExecutor` owns guarded secret synchronization, and `NativeSeedExecutor` owns eligible one-time key/certificate-group seeds.
- Keep docs accurate to implemented behavior: an enabled, unpaused mapping opts into supported runtime operations; native key/certificate seeds are one-time operations, not rotation; delete/purge and authorization reconciliation remain plan-only.

## Safety and Privacy

- Preserve value-free inventory, HMAC baselines, pending-write intent, write verification, Blob lease/ETag checks, and the operational single-writer requirement. A missing HMAC key blocks standalone secret writes but not eligible native seeds. Never automatically retry an ambiguous Key Vault write.
- Do not put subscription/tenant IDs, customer/resource inventories, credentials, connection strings, HMAC material, secret values, or private keys in tracked files, examples, logs, or telemetry.
- `.azure/`, `local.settings.json`, and `untracked/` contain local-only data and must remain ignored. Do not move their contents into public docs.
- Infrastructure must not create, replace, delete, or purge source/target vaults. Do not add organization-specific policy exemptions to reusable Bicep.
- Before any live deployment, permission change, resource deletion, or secret mutation, confirm the exact scope and approval. Never treat a subscription-wide label as authorization to delete unrelated resources.

## Documentation and Verification

- Update the relevant `doc/` page and XML/API documentation when public behavior, settings, permissions, or failure handling changes.
- Run the narrowest relevant check first, then the required runner tests and Function build for shared runner changes.
- Useful local checks:

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

- Script tests must use mocked Azure CLI behavior. Do not run live onboarding `--apply` or synchronization as a test.
- Report what was actually validated. A successful build, Bicep compile, or mocked script test is not proof of live permissions, deployment, telemetry ingestion, or safe mutation.