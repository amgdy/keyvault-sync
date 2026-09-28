# KeyVaultSync Deployment

## Deployment Boundary

The azd/Bicep scaffold provisions the Function App, Flex Consumption plan, one shared Function host/deployment/state storage account, workspace-based Application Insights and Log Analytics, one standalone user-assigned managed identity, and scoped infrastructure roles. Existing Key Vault access is onboarded separately through the operator-run script below; Bicep does not create, replace, delete, or purge vaults.

An enabled, unpaused mapping is the runtime opt-in for supported operations. Review every existing mapping and its effective permissions before deploying or starting the updated runtime: a mapped pair may begin writing on its next cycle. `KeyVaultSyncDisabled=true` on either vault pauses the pair. Standalone secret writes require a protected HMAC key; eligible one-time native key/certificate seeds are evaluated without that key.

- The HMAC key is not present in Bicep or parameter files.
- `preserveExistingAppSettings=false` is safe for first provisioning only. Set it to `true` before any later provisioning that must retain an out-of-band `KEYVAULTSYNC_HMAC_KEY`; the child app-settings resource merges existing settings and template-owned keys.
- No per-vault deployment list is required. A pair can be declared on the source with `sync-vault-id=<target-vault-resource-ID>` or on the target with `sync-source-keyvault-id=<source-vault-resource-ID>`; the latter allows multiple targets per source. The runner deduplicates pairs declared by both tags.
- A pair can be intentionally disabled by setting the existing source or target vault tag `KeyVaultSyncDisabled=true`; this does not modify the vault or its contents.
- The deployment resource group is not retagged by default. One generic optional tag can be enabled per azd environment; existing resource-group tags are preserved.

Do not deploy to production or perform live infrastructure, IAM, or secret changes without explicit approval and an operational recovery plan.

## Verified Modules and Ownership

[../infra/main.bicep](../infra/main.bicep) composes the official public Azure Verified Modules (AVM) recommended for azd Bicep infrastructure. The versions are pinned; adopting a newer version requires reviewing its defaults and generated template, not merely changing the version string.

| Resource | Public Bicep module | Pinned version |
| --- | --- | --- |
| Log Analytics workspace | `avm/res/operational-insights/workspace` | `0.16.1` |
| Application Insights | `avm/res/insights/component` | `0.8.0` |
| Shared host/deployment/state storage account | `avm/res/storage/storage-account` | `0.33.1` |
| Flex Consumption plan | `avm/res/web/serverfarm` | `0.7.0` |
| Function App and its diagnostic setting | `avm/res/web/site` | `0.24.0` |
| Central user-assigned identity | `avm/res/managed-identity/user-assigned-identity` | `0.6.0` |
| Resource-group Owner assignment | `avm/res/authorization/role-assignment/rg-scope` | `0.1.1` |
| Subscription Reader assignment | `avm/res/authorization/role-assignment/sub-scope` | `0.1.1` |

The registry prefix is `br/public:`. AVM module-usage telemetry is disabled with `enableTelemetry=false`; this does not disable application telemetry.

Small native declarations remain intentionally:

- The storage-account AVM owns the Blob service and all three private containers through its nested `blobServices.containers` input.
- The app-settings child resource owns the guarded merge. The site module receives no `configs` or inline app settings, so there is only one settings owner. Preservation excludes three deprecated Flex runtime selectors and two conflicting host-storage settings described in [settings.md](settings.md).
- Scoped assignments target the independent user-assigned identity and can precede Function creation. Scope-only `existing` aliases do not deploy duplicate resources. Assignment GUIDs now include the identity resource ID to avoid updating the immutable principal on an old Function-based assignment; old assignments are not automatically removed.
- The subscription-scoped role-assignment AVM grants ARM discovery access with the existing deterministic assignment GUID. Main Bicep does not invoke the existing-vault access module; the onboarding script owns reviewed vault grants. An AVM Key Vault creation module is deliberately not used.

Module defaults are overridden explicitly: `Standard_LRS`, `FC1`, Linux, HTTPS/TLS 1.2, private containers, Entra-only telemetry, App Insights IP masking, and 30-day default workspace retention. `requireInfrastructureEncryption=false` avoids requesting a creation-only encryption feature that the original storage accounts did not enable; normal service-side encryption remains. No key export, customer-managed-key vault, or second runtime identity is configured.

## CAF Naming

New defaults follow the Cloud Adoption Framework's resource-type, workload, environment, and uniqueness components. `keyvaultsync` is the workload; `kvs` is its storage-only abbreviation. The normalized environment contains only lowercase ASCII letters/digits, uses `env` if filtering leaves nothing, and is bounded to eight characters (`env8`) or four for storage (`env4`). The input accepts 1-64 characters, and tags retain the full value.

`hash13` is the deterministic 13-character `uniqueString(subscription().id, resourceGroup().id, environmentName)`. Truncating the display token does not truncate the hash input. Region is represented by the resource's location and deployment scope rather than another name component. A hash reduces collision risk but does not prove global name availability.

| Resource / override parameter | Default pattern | Uniqueness scope | Generated maximum / provider maximum |
| --- | --- | --- | --- |
| Function / `functionAppName` | `func-keyvaultsync-<env8>-<hash13>` | Global | 40 / 60 |
| Plan / `functionPlanName` | `asp-keyvaultsync-<env8>-<hash13>` | Resource group | 39 / 60 |
| Shared storage / `functionStorageAccountName` | `stkvsfn<env4><hash13>` | Global | 24 / 24 |
| Workspace / `logAnalyticsWorkspaceName` | `log-keyvaultsync-<env8>-<hash13>` | Resource group | 39 / 63 |
| App Insights / `applicationInsightsName` | `appi-keyvaultsync-<env8>-<hash13>` | Resource group | 40 / 260 |
| User-assigned identity / `managedIdentityName` | `id-keyvaultsync-<env8>-<hash13>` | Resource group | 38 / 128 |

The shared storage name retains the `fn` segment from the former Function-storage default so an existing environment adopts that account rather than creating another one. It cannot contain hyphens and must be 3-24 lowercase alphanumeric characters. Other generated names start/end in alphanumerics and use hyphen separators. Function names must be 2-60 characters, plans 1-60, workspaces 4-63, and components 1-260, subject to each provider's character rules. User-assigned identity names must be 3-128 alphanumerics, hyphens, or underscores and start with an alphanumeric character. Parameter decorators bound override lengths; operators must still validate override characters, minimum lengths, reserved names, and availability.

For environment `test` and illustrative hash `a123456789012`, examples are `func-keyvaultsync-test-a123456789012`, `asp-keyvaultsync-test-a123456789012`, `stkvsfntesta123456789012`, `log-keyvaultsync-test-a123456789012`, `appi-keyvaultsync-test-a123456789012`, and `id-keyvaultsync-test-a123456789012`. The example hash is not a computed deployment value.

Every main resource gets `workload=KeyVaultSync`, `environment=<full environmentName>`, and `azd-env-name=<full environmentName>`. The Function additionally gets `azd-service-name=keyvaultsync`, matching [../azure.yaml](../azure.yaml). Do not place secrets or personal information in names/tags. Existing vaults remain outside this template's ownership. The template can optionally merge one operator-selected tag into the deployment resource group but otherwise leaves its tags unchanged. For a new operator-created group, `rg-keyvaultsync-<environment>-<region>` is a suitable CAF convention.

Before each interactive provision, the root `preprovision` hook in [../azure.yaml](../azure.yaml) asks whether to add one optional deployment tag. If accepted, it requires a key and value and stores the confirmed values in the active azd environment. Existing configured values can be retained without re-entry. Non-interactive runs preserve complete existing values and do not prompt.

If both variables are empty, the template performs no optional tag write; the hook and Bicep both reject an incomplete pair. When configured, Bicep merges the tag into the resource group and every tagged resource managed by the main deployment. Existing tags are preserved. Removing the variables later removes the optional tag from template-owned resource tag sets on the next provision but does not remove a resource-group tag previously written by an incremental deployment.

Before package publication, the cross-platform root `predeploy` hook reads the provisioned shared storage account and verifies that its Blob endpoint is reachable by the configured deployment path. The hook reports incompatible network configuration early and does not change the account, tags, or roles.

**Adoption is not a rename or data-migration operation.** These defaults differ from the earlier `func-<environment>-<hash>`, `plan-*`, `law-*`, `stfn*`, `ststate*`, and `appi-<environment>-<hash>` defaults. Before provisioning over existing resources, add all applicable override parameters from the table to the `parameters` object in [../infra/main.parameters.json](../infra/main.parameters.json), using each deployed name as its `value`. Preserve the original resource group/location and review template-owned tags. Pin the existing Function-storage account, workspace, and component rather than creating empty replacements.

For an environment that already has separate Function and state accounts, the shared-account template adds `keyvaultsync-state` and `keyvaultsync-runs` to the Function account and changes `KEYVAULTSYNC_STORAGE_ACCOUNT_URI` to that account. It does not copy blobs from the old state account or delete that account. Before adopting this template, stop writers and either perform an explicitly reviewed state/run blob migration that preserves names and content or follow the approved rebaseline process. Do not resume secret writes against empty state. Keep the old account until the replacement state and recovery behavior are verified; cleanup is a separate approved action.

## Managed Identity First

One user-assigned managed identity is attached to the Function for host/deployment storage, runner Blob access, existing Key Vault access, ARM discovery, and telemetry. System-assigned identity is disabled. Both C# entry points retain `new DefaultAzureCredential()`; Bicep supplies the standard `AZURE_CLIENT_ID` selector. Local execution can use `az login` without changing code or exporting the hosted identity selector. The complete role/scope table is in [identity-and-rbac.md](identity-and-rbac.md).

- Host storage uses the account name, `AzureWebJobsStorage__credential=managedidentity`, and `AzureWebJobsStorage__clientId`. Deployment storage uses `UserAssignedIdentity` and the same identity's resource ID in `functionAppConfig`. All selectors are generated from one module, not separate operator inputs.
- The shared account sets `allowSharedKeyAccess=false` and `defaultToOAuthAuthentication=true`. Review other consumers of an adopted account before provisioning: key-based requests and account/service SAS will stop working. This is an authentication change, not a data migration.
- App Insights and Log Analytics disable local authentication. `APPLICATIONINSIGHTS_AUTHENTICATION_STRING=ClientId=<client-id>;Authorization=AAD` selects this identity for host telemetry; the worker exporter reuses its `DefaultAzureCredential`. The connection string is a destination locator, not a replacement credential.
- The guarded settings merge removes an exact legacy `AzureWebJobsStorage` connection string and `AzureWebJobsStorage__managedIdentityResourceId`, which would override or conflict with the new client-ID settings. It does not scrub arbitrary credentials. Do not configure client-secret/certificate environment credentials in the hosted app: `DefaultAzureCredential` retains its normal chain and could select an earlier credential. Preserve the protected HMAC setting during any cleanup.
- The identity survives Function replacement, but not deletion/recreation of the identity itself. Pin an existing identity's name with `managedIdentityName` in the same resource group. Do not delete/recreate it under the same name: a new principal behind the old resource ID requires a separately reviewed assignment migration.
- Restrict who can attach this identity to another resource. Each attached host can use all its grants; central identity simplifies lifecycle management but increases the impact of a compromised host. Use a separate identity per trusted environment/boundary.

For an existing system-assigned Function, plan an approved cutover window: pause mapped pairs with `KeyVaultSyncDisabled=true` and stop invocations before changing identities, preserve existing state/telemetry names and protected settings, provision the UAMI, onboard vault access, and validate startup before resuming. Old system-assigned grants can remain as orphaned assignments; their removal is a separate reviewed operation, never automatic cleanup.

Only 11 app settings are generated. Container names, pair tag, HMAC version label, and log level use code defaults; optional existing overrides can still be preserved. The default parameter file supplies environment/location and the preservation flag, with name overrides only when needed. Remove obsolete `existingKeyVaults`, `allowSecretValueRead`, `resourceGroupFilter`, `pairTag`, and `hmacKeyVersion` entries from adopted parameter files. Their optional runtime equivalents remain supported where applicable.

The azd provisioning/deployment principal is separate from the runtime identity. It needs resource deployment rights, identity assignment rights, app-settings read/write for guarded preservation, and role-assignment creation at the specified infrastructure scopes. Vault onboarding has its own operator permissions, described below. Prefer an approved federated CI or managed-identity deployment principal over stored client secrets. The pinned storage AVM exposes **secure** key outputs and uses `listKeys` internally even though this template never consumes or re-exports them. Account-management permissions required by that module belong to the deployer, not the Function identity. Keep deployment diagnostics protected and never print app settings or secure module outputs.

This reference scaffold currently uses public storage endpoints (`publicNetworkAccess=Enabled`, storage firewall `defaultAction=Allow`) because it does not provision private endpoints or Function VNet integration. Shared Key remains disabled, anonymous Blob access is disabled, containers are private, and Entra data roles are required. This is not a production network-isolation design. Adapt the network, DNS, and deployment path to the target environment before provisioning. The Well-Architected tradeoffs are recorded in [architecture.md](architecture.md).

## Validation and Lab Deployment

Compile using a current Bicep toolchain with access to the public module registry. The latest local Azure CLI build used Bicep `0.42.1.51946`:

```sh
az bicep build --file infra/main.bicep --outfile /tmp/keyvaultsync-main.json
```

Compilation validates syntax/module types, not Azure policies, name availability, role propagation, or Function startup. Static checks covered the generated module inputs, central identity, scoped roles, acyclic dependencies, 11 settings, guarded settings merge, mutation defaults, output contracts, and 49 generated-name boundary cases with a synthetic hash. The pair onboarding scripts have offline mocked-CLI scenarios covering no-write previews, scoped/idempotent grants, legacy-policy preservation, and partial-apply recovery. Separate mocked hook suites cover non-interactive skips, disabled-pair filtering, two-stage confirmation, and preflight failure:

```sh
bash tests/grant-keyvault-access.tests.sh
bash tests/preprovision-resource-group-tag.tests.sh
bash tests/bicep-tag-wiring.tests.sh
bash tests/verify-deployment-storage.tests.sh
bash tests/postdeploy-keyvault-access.tests.sh
pwsh -NoProfile -File tests/Grant-KeyVaultAccess.Tests.ps1
pwsh -NoProfile -File tests/PreProvision-ResourceGroupTag.Tests.ps1
pwsh -NoProfile -File tests/Verify-DeploymentStorage.Tests.ps1
pwsh -NoProfile -File tests/PostDeploy-KeyVaultAccess.Tests.ps1
```

No deployment is implied by local validation. A successful Bicep build and unit tests do not prove network reachability, RBAC propagation, package publication, Function startup, timer execution, or telemetry ingestion in a target environment.

For a separately reviewed preview, use an azd environment from the repository root:

```sh
azd version
azd env new keyvaultsync-validation --subscription <subscription-id> --location <region>
azd provision --preview --no-prompt --environment keyvaultsync-validation
```

Preview must report the intended non-Key-Vault resources without applying them. If the preview stalls while updating Bicep, stop it and retain the gate as inconclusive; do not remove the preview flag to make progress. Do not run `azd up` or non-preview `azd provision` without approval.

## Provisioning Sequence

1. Confirm the destination resource group, region, subscription, existing-name overrides, retention, and explicit `Standard_LRS` storage choice. Flex memory supports 512/2048/4096 MB (default 2048); `maximumInstanceCount` is 1-1000 (default 10), not a reservation or single-writer lock. Confirm regional .NET 10 isolated/Flex support and quota. Runtime selection belongs in `functionAppConfig`, not deprecated runtime app settings; FTPS/Always On are not configured.
2. Confirm the source/target Key Vaults already exist, review either the source's `sync-vault-id` target mapping or the target's `sync-source-keyvault-id` source mapping, and select the central identity name. For cutover from an older deployment, keep pairs paused with `KeyVaultSyncDisabled=true` until the new Function, grants, state, and intended automatic operations are reviewed. Do not maintain a duplicate vault list in deployment parameters.
3. Preview the deployment and inspect the generated changes. Verify that no `Microsoft.KeyVault/vaults` resource is being created.
4. With approval, provision the non-Key-Vault resources and then deploy the Function code through the approved azd pipeline. The initiating deployment principal receives `Owner` on the deployment resource group and `Storage Blob Data Owner` on shared storage; it must already be authorized to create those role assignments, because the template cannot bootstrap missing authorization. Let role assignments propagate before startup validation; an ARM dependency alone does not guarantee data-plane readiness. Provisioning is not package deployment, and manually uploading a zip is not a substitute for the supported Flex deployment path.
5. Preview the vault-onboarding script and, only with separate approval, apply its grants. Verify the central identity, scoped assignments, and Function app settings. Provisioning does not onboard vaults or approve IAM changes.
6. Add `KEYVAULTSYNC_HMAC_KEY` out of band through the protected Function App configuration path when standalone secret synchronization is intended. A missing key blocks secret actions but not eligible native seeds. Before any subsequent `azd provision`, set `preserveExistingAppSettings=true` in the deployment parameters. Use a deployment secret mechanism or portal configuration that does not place the key in source, Bicep, parameter files, azd environment state, command history, logs, or telemetry.
7. Before resuming a mapped pair, review its permissions, pair state, HMAC availability for secret synchronization, and the single-writer operating condition. Then run the timer and verify state, run history, traces, dependencies, and metrics.

## Existing Vault Access

The pair-scoped onboarding tools accept the UAMI resource ID and either a source vault resource ID or a target vault resource ID. The source form resolves the target from `sync-vault-id`; the target form resolves the source from `sync-source-keyvault-id`. Both vaults must be in the UAMI subscription and tenant. Sign in with an approved onboarding operator (an authorized subscription Owner can perform role-definition/assignment and legacy-policy writes), not the runtime identity. The tools read vault metadata but never secret values.

Both scripts can run in Azure Cloud Shell. Cloud Shell provides Azure CLI and pre-authenticates the signed-in operator. Bash additionally requires `jq` (`jq --version` verifies availability); the PowerShell 7 script uses Azure CLI plus built-in JSON parsing and does not require `jq`. Upload or clone the scripts into the Cloud Shell home directory; attach Cloud Shell storage if the files need to persist between sessions. The signed-in operator still needs the permissions listed in [identity-and-rbac.md](identity-and-rbac.md).

macOS (Bash 3.2+, Azure CLI, and `jq`):

```sh
identity_id="$(azd env get-value KEYVAULTSYNC_IDENTITY_RESOURCE_ID)"
source_vault_id="$(az keyvault show --name <source-vault> --query id --output tsv)"
bash scripts/grant-keyvault-access.sh --identity-id "$identity_id" --source-vault-id "$source_vault_id"
```

Windows PowerShell 7 or Azure Cloud Shell PowerShell (Azure CLI required):

```powershell
$identityId = azd env get-value KEYVAULTSYNC_IDENTITY_RESOURCE_ID
$sourceVaultId = az keyvault show --name <source-vault> --query id --output tsv
.\scripts\Grant-KeyVaultAccess.ps1 -IdentityResourceId $identityId -SourceVaultResourceId $sourceVaultId
```

An interactive root `postdeploy` hook in [../azure.yaml](../azure.yaml) automates the multi-pair version of this workflow after `azd deploy` and the deploy phase of `azd up`:

1. It explains both supported declarations: `sync-vault-id=<full-target-vault-ARM-ID>` on a source or `sync-source-keyvault-id=<full-source-vault-ARM-ID>` on a target. If both declare the same pair, the hook deduplicates it. Chained/cyclic mappings are unsupported, and `KeyVaultSyncDisabled=true` disables a pair.
2. The operator confirms that tagging is complete.
3. The hook discovers pairs declared from either tag in `AZURE_SUBSCRIPTION_ID`, deduplicates duplicate declarations, excludes pairs whose source or target is marked `KeyVaultSyncDisabled=true`, and runs the pair script in preview mode for all of them. Any failed preview stops the hook before writes.
4. A second explicit confirmation is required before the hook reruns each validated pair with its apply switch.

Declining either prompt exits successfully without changing vault access. Runs with `AZD_NON_INTERACTIVE=true` skip this optional workflow. An unavailable interactive response is also treated as a decline. Applying multiple pairs is convergent but not transactional: a later failure can leave earlier pairs applied. Review the output and rerun to converge. The hook can be invoked again without redeploying:

```sh
azd hooks run postdeploy
```

The default mode previews the complete supported pair profile: metadata access on both vaults, source secret-value reads, target secret set/verification, source key/certificate backup, and target restore for eligible one-time seeds. Review the preview before applying; Bash uses `--apply`, PowerShell uses `-Apply` (and supports `-WhatIf`). This is approval for IAM changes only. Both forms reread authorization state before writes. The identity resource ID can also be passed literally; `AZURE_CLIENT_ID` is not needed by these scripts.

For RBAC vaults, the tools assign `Key Vault Reader` on both, `Key Vault Secrets User` on source, and a narrowly defined `KeyVaultSync Secret Writer` custom role on target. The custom role is assignable at the target subscription but the assignment is only at the target vault. They also assign a source-only `KeyVaultSync Native Backup` role (`keys/backup/action`, `certificates/backup/action`) and a target-only `KeyVaultSync Native Restore` role (`keys/restore/action`, `certificates/restore/action`). For legacy access-policy vaults, the tools merge source secrets `get,list` and target secrets `get,list,set`, plus keys/certificates `get,list,backup` on source and `get,list,restore` on target. No vault list is processed beyond the selected pair.

The default secret-writer role excludes delete/purge/backup/restore and authorization operations. These are vault-wide secret permissions, including certificate-backed secrets at the IAM layer; application-level exclusions do not narrow the IAM grant. Native seeding uses only the separately scoped backup/restore actions described above and runs only for eligible one-time seeds; it does not rotate keys or certificates. A pair must be in one subscription, unambiguous, unpaused, and non-chained; native seeds additionally require the same region and an unused target namespace. A pause/remap does not revoke previously granted permissions. The UAMI receives no access-policy or RBAC-management permission. With an enabled mapping and effective grants, supported operations run automatically; secret actions are blocked without a valid protected HMAC key. Operators must ensure the runner is the sole writer to target objects being changed.

All preflight reads must succeed before writes begin. Existing conditional assignments, application-specific/duplicate identity policies, or a mismatched named custom role cause a stop for manual review. Direct unconditional assignments and already-sufficient policies are skipped on reruns. Existing inherited/group permissions are not calculated or removed. A failure during apply can leave earlier assignments or the custom role in place: review, rerun preview, and retry only after correcting the cause. RBAC propagation can take several minutes. Serialize IAM/tag changes; the per-vault recheck is not a transaction or an ETag fence.

Rerun onboarding when vaults or mappings change. The Function never elevates its own access, changes vault authorization models, or removes grants. Prefer this explicit workflow over subscription-wide data roles unless the entire subscription is intentionally one trust boundary. Azure Policy automation for future vaults is a later governance decision, not required configuration here. The older [standalone access module](../infra/modules/keyvault-access.bicep) remains for reviewed manual callers; main Bicep no longer invokes it, and it does not provide the script's existing-permission merge checks.

Operator prerequisites and the role matrix are in [identity-and-rbac.md](identity-and-rbac.md).

## Post-Deployment Checks

- Function App is on the intended Flex Consumption plan, has the central user-assigned identity attached, and has no system-assigned identity enabled.
- `AzureWebJobsStorage` uses managed identity in Azure; no storage account key is configured.
- The shared storage account rejects Shared Key authentication; no other approved consumers were left dependent on it.
- `AZURE_CLIENT_ID`, `AzureWebJobsStorage__clientId`, and the client ID in `APPLICATIONINSIGHTS_AUTHENTICATION_STRING` match the attached identity; the identity has `Monitoring Metrics Publisher` on the component.
- `KEYVAULTSYNC_STORAGE_ACCOUNT_URI`, state/run containers, subscription, pair tag, and timer schedule are correct.
- Any intentionally disabled pair has `KeyVaultSyncDisabled=true` on the source or target ARM resource, appears in the run record's disabled-vault list, and has no pair lease or Key Vault data-plane inventory for that run.
- When standalone secret synchronization is intended, `KEYVAULTSYNC_HMAC_KEY` is present only in protected application configuration; if absent, secret actions are blocked. Eligible native seeds do not use the key.
- Old telemetry and state resources remain untouched until replacement behavior is verified and cleanup is separately approved.

## Microsoft References

- [azd Bicep authoring guidance](https://learn.microsoft.com/azure/developer/azure-developer-cli/make-azd-compatible) and the [AVM Bicep resource catalog](https://azure.github.io/Azure-Verified-Modules/indexes/bicep/bicep-resource-modules/).
- [CAF naming strategy](https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-best-practices/resource-naming), [resource abbreviations](https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations), and [provider naming rules](https://learn.microsoft.com/azure/azure-resource-manager/management/resource-name-rules).
- [Functions infrastructure as code](https://learn.microsoft.com/azure/azure-functions/functions-infrastructure-as-code?pivots=flex-consumption-plan), [Flex limits and supported runtimes](https://learn.microsoft.com/azure/azure-functions/flex-consumption-plan), and [deprecated settings](https://learn.microsoft.com/azure/azure-functions/functions-app-settings#flex-consumption-plan-deprecations).
- [Identity-based Functions host storage](https://learn.microsoft.com/azure/azure-functions/functions-reference#connecting-to-host-storage-with-an-identity) and [managed-identity deployment storage](https://learn.microsoft.com/azure/azure-functions/flex-consumption-how-to#configure-deployment-settings).
- [DefaultAzureCredential user-assigned client-ID selection](https://learn.microsoft.com/dotnet/api/azure.identity.defaultazurecredentialoptions.managedidentityclientid), [Entra-authenticated telemetry](https://learn.microsoft.com/azure/azure-monitor/app/azure-ad-authentication), and [Key Vault RBAC guidance](https://learn.microsoft.com/azure/key-vault/general/rbac-guide).
