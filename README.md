# KeyVaultSync

KeyVaultSync is a .NET 10 Azure Functions application and console runner for discovering mapped Azure Key Vault pairs, inventorying their contents, and automatically running supported synchronization for enabled pairs.

The project is intentionally narrower than a full vault replication product. It does not create source or target vaults. It inventories secrets, keys, certificates, and authorization declarations; standalone secrets can be synchronized with guarded writes, and eligible keys or certificate groups can be seeded once through native backup/restore. Native seeds do not rotate later versions. Delete/purge and authorization reconciliation remain plan-only.

## Use Cases

One use case is disaster recovery (DR): maintain selected secrets in a target vault so an application can use a separately configured endpoint during a regional incident. Other uses include controlled secret-version synchronization between existing environments. KeyVaultSync does not perform application failover or guarantee an RPO/RTO.

## How It Works

- A timer-triggered Function runs on a configurable schedule; a console runner supports local scans.
- The runner enumerates Key Vault resources in one subscription. A source can declare one target with `sync-vault-id=<target-vault-resource-ID>`, or each target can declare its source with `sync-source-keyvault-id=<source-vault-resource-ID>`. The reverse tag allows multiple targets per source. If both tags declare the same pair, discovery deduplicates it; conflicting target owners and chained/cyclic mappings are rejected.
- `KeyVaultSyncDisabled=true` on either member suppresses the pair for that scan.
- Source and target inventory is read without fetching secret values. A deterministic planner compares observations with persisted pair state.
- A timer inventory is authoritative for deletion detection: Key Vault Event Grid has no object-deletion event in its documented event catalog. Notifications could later trigger an early scan, but complete active/soft-deleted inventory remains required.
- An enabled mapping is the runtime opt-in for supported synchronization. Standalone secret writes run only when a valid protected HMAC key is configured and target safety checks pass; without the key, secret plan items are blocked while eligible native seeds are still evaluated.
- A secret write checks the target's current value HMAC and managed-metadata digest against the committed baseline before writing, stores a durable intent, performs one write without automatic retry, verifies the exact resulting target version, then commits the new baseline.
- Eligible key and certificate-group seeds are one-time native backup/restore operations into unused target names in the same subscription and region. They are not recurring key/certificate rotation.
- A Blob lease and ETag protect each pair's state. This coordinates KeyVaultSync runs; it does not fence unrelated writers to Key Vault.

## Safety Boundaries

An enabled mapping can cause writes on the next run, so review the pair, permissions, and persisted state before enabling it. Set `KeyVaultSyncDisabled=true` on either vault to pause that pair. For an enabled pair:

- Standalone secret writes require a protected Base64-encoded 256-bit HMAC key. Without it, the runner reports blocked secret work instead of writing.
- A target secret must be absent from active and soft-deleted inventory, or its current value HMAC and managed metadata must still match the committed baseline. Existing targets without a baseline are never adopted.
- The operator must ensure this runner is the sole writer to target objects being changed. The runtime has no single-writer acknowledgment switch, and Key Vault writes do not provide a compare-and-set condition.

Eligible native key/certificate seeds are automatically evaluated for an enabled pair and require the pair-scoped source backup/target restore permissions. A seed is allowed only for an eligible same-subscription, same-region item whose target namespaces are unused, including soft-deleted names. Certificate and backing objects are handled as a group. Ambiguous secret writes or native restores remain blocked for review and are never retried automatically. The scanner never fetches secret values during routine inventory.

## Requirements

- .NET 10 SDK.
- Azure Functions Core Tools v4 for local timer execution.
- Azure CLI sign-in for local Azure access through `DefaultAzureCredential`.
- Azurite for local Functions host storage.
- An existing source/target vault pair, Blob state storage, and the required scoped permissions.

## Local Development

Restore and build using your configured NuGet source, then run tests:

```sh
dotnet restore
dotnet build src/KeyVaultSync.Function/KeyVaultSync.Function.csproj
dotnet test tests/KeyVaultSync.Runner.Tests/KeyVaultSync.Runner.Tests.csproj
bash tests/grant-keyvault-access.tests.sh
bash tests/preprovision-resource-group-tag.tests.sh
bash tests/postdeploy-keyvault-access.tests.sh
pwsh -NoProfile -File tests/Grant-KeyVaultAccess.Tests.ps1
pwsh -NoProfile -File tests/PreProvision-ResourceGroupTag.Tests.ps1
pwsh -NoProfile -File tests/PostDeploy-KeyVaultAccess.Tests.ps1
```

Sign in and provide the required settings through the shell or ignored local settings. Do not put real credentials, HMAC keys, connection strings, tenant IDs, or subscription-specific configuration in committed files.

```sh
az login
export AZURE_SUBSCRIPTION_ID="<subscription-id>"
export KEYVAULTSYNC_STORAGE_ACCOUNT_URI="https://<state-account>.blob.core.windows.net/"
dotnet run --project src/KeyVaultSync.Runner/KeyVaultSync.Runner.csproj
```

The Function's local settings template is at [src/KeyVaultSync.Function/local.settings.example.json](src/KeyVaultSync.Function/local.settings.example.json). Copy it to `local.settings.json` for local use and replace placeholders privately; that file is git-ignored. See [local development](doc/local-development.md) and [settings](doc/settings.md) for details.

## Key Vault Access Setup

The operator tools take a UAMI resource ID and either a source vault resource ID or a target vault resource ID. The source form resolves the target from `sync-vault-id`; the target form resolves the source from `sync-source-keyvault-id`. They preview the complete supported pair profile: inventory and secret permissions, source key/certificate backup, and target restore. No grants are written without the explicit onboarding `--apply` or `-Apply` option. This approval applies only to IAM changes; once a mapping and grants are in place, supported runtime synchronization starts automatically.

macOS/Linux:

```sh
bash scripts/grant-keyvault-access.sh \
  --identity-id "<uami-resource-id>" \
  --source-vault-id "<source-vault-resource-id>"
```

Windows PowerShell 7:

```powershell
.\scripts\Grant-KeyVaultAccess.ps1 `
  -IdentityResourceId "<uami-resource-id>" `
  -SourceVaultResourceId "<source-vault-resource-id>"
```

For a reverse-declared pair, use `--target-vault-id` or `-TargetVaultResourceId` instead; the target must carry `sync-source-keyvault-id=<source-vault-resource-ID>`.

Both scripts also run in Azure Cloud Shell. Bash requires `jq`; PowerShell uses built-in JSON parsing. Review the preview and verify the selected source-side or target-side mapping before applying. The operator needs permission to write a legacy access policy or role assignments and, for RBAC vaults, create the narrowly scoped custom roles requested. The Function's UAMI is never granted permission to modify authorization.

After `azd deploy` (including the deploy phase of `azd up`), an interactive post-deploy hook explains both mapping tags, discovers pairs declared from either side, deduplicates pairs declared by both tags, and skips pairs whose source or target is marked `KeyVaultSyncDisabled=true`. It previews all pairs and asks again before applying any grant, including native backup/restore permissions. Declining either prompt makes no access change; non-interactive azd runs skip the optional workflow. Rerun it with `azd hooks run postdeploy`.

See [identity and RBAC](doc/identity-and-rbac.md) and [deployment](doc/deployment.md) for the full permission matrix and migration guidance.

## Infrastructure and Deployment

`azure.yaml` and `infra/main.bicep` define the Function, Flex Consumption plan, managed identity, one shared host/deployment/state storage account, telemetry, and infrastructure roles. They do not declare or create Key Vault resources. Review and preview infrastructure changes before deployment:

```sh
azd auth login
azd env new <environment> --subscription <subscription-id> --location <region>
azd provision --preview --no-prompt
```

The deployment resource group and managed-resource tag sets receive no optional tag by default. An interactive `preprovision` hook asks whether to add one optional deployment tag and, when accepted, requires its key and value. The selection is stored in the active azd environment. The template preserves other tags and applies the optional tag to the resource group and tagged resources it manages.

The current sample has public storage endpoints and no private endpoint/VNet configuration. Shared Key is disabled and data-plane access requires Entra authorization, but public endpoint reachability is still a network exposure. Do not treat these templates as production network isolation; adapt them to your organization's approved private-network design and policies. They intentionally contain no organization-specific policy exemptions.

## Project Status and Documentation

The tested implementation supports discovery, value-free inventory, planning, Blob-backed pair state, mapping-driven guarded secret synchronization when HMAC is configured, and eligible one-time native key/certificate-group seeds. Authorization reconciliation, delete/purge, automatic failover, and HMAC key rotation/rebaseline tooling are not implemented. Live Azure behavior must be validated in a disposable environment; unit and mocked CLI tests do not prove effective permissions or safe mutation.

- [Architecture](doc/architecture.md)
- [Code flow](doc/code-flow.md)
- [Configuration](doc/settings.md)
- [Deployment](doc/deployment.md)
- [Identity and RBAC](doc/identity-and-rbac.md)
- [Observability](doc/observability.md)
- [Troubleshooting](doc/troubleshooting.md)
- [Coding guide](doc/coding-guide.md)

## License

This project is licensed under the [MIT License](LICENSE).
