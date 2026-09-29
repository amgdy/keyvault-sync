# KeyVaultSync Identity and RBAC

## Runtime Identity

The Function App uses one standalone user-assigned managed identity, created or adopted by name in its resource group. Both C# entry points retain `new DefaultAzureCredential()`: the SDK reads the Bicep-generated `AZURE_CLIENT_ID` to select that identity in Azure and can use the signed-in Azure CLI user locally. No credential factory, hosted-mode flag, client secret, or storage key is required. A local user's permissions are separate from the managed identity's grants.

The same identity is used for Flex deployment-package access (`UserAssignedIdentity`), host storage (`AzureWebJobsStorage__credential=managedidentity` plus `__clientId`), Blob state/history, ARM, vaults, and telemetry. The Function has no system-assigned identity. Storage Shared Key and telemetry local authentication remain disabled. `DefaultAzureCredential` retains its normal chain, not an exclusive managed-identity guarantee; do not add environment client-secret/certificate credentials that could take precedence.

Preserve the identity across Function replacements. Deleting/recreating it, even with the same name, changes its principal and requires an assignment migration. Restrict `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action`: any host that can attach this central identity can use its grants. Centralize within a trusted application/environment boundary, not across unrelated workloads.

Provisioning and onboarding use separate operator/CI identities with deployment or scoped IAM-management permissions. The storage AVM's internal secure key outputs require account-management permissions even though the app never consumes them; do not grant those management rights to the Function to make provisioning succeed. Main Bicep grants the initiating ARM deployment principal `Owner` on the deployment resource group and `Storage Blob Data Owner` on shared storage. That principal must already be authorized to create role assignments; these grants cannot bootstrap an underprivileged deployment. See [deployment.md](deployment.md) for adoption and deployment-identity requirements.

The infrastructure template assigns the following access:

| Scope | Role or permission | Purpose |
| --- | --- |
| Subscription | `Reader` | Discover Key Vault resources and validate ARM metadata. |
| Shared host/deployment/state storage account | `Storage Blob Data Owner` | Functions deployment and host coordination plus pair state, leases, ETags, checkpoints, and durable run history. |
| Application Insights component | `Monitoring Metrics Publisher` | Entra-authenticated telemetry ingestion, not just custom metrics. |

The initiating deployment principal receives these persistent infrastructure grants:

| Scope | Role | Purpose |
| --- | --- | --- |
| Deployment resource group | `Owner` | Full administration of resources deployed into that group, including role assignments. |
| Shared storage account | `Storage Blob Data Owner` | Full Blob data access for deployment and diagnostics. |

These are intentionally broad operator grants, not runtime grants. `deployer().objectId` supports an interactive user or an automation service principal/managed identity without hard-coding a principal type. Review continued need and assignment policy for each environment.

Subscription Reader supports ARM discovery, not Key Vault data-plane access. Review whether a custom discovery role can replace it before production rollout. Infrastructure Bicep does not grant vault access or authorization-management permissions to the runtime.

## Existing Key Vaults

Source and target vaults remain external resources. The pair-scoped [Bash](../scripts/grant-keyvault-access.sh) and [PowerShell](../scripts/Grant-KeyVaultAccess.ps1) onboarding tools take the UAMI and either a source or target vault resource ID. The source form resolves the target from `sync-vault-id`; the target form resolves the source from `sync-source-keyvault-id`. They inspect only that pair and can run in Azure Cloud Shell with its signed-in Azure CLI; Bash also needs `jq`, while PowerShell parses JSON natively. The default preview shows the complete supported pair profile, including secret synchronization and native seed permissions. `--apply` or `-Apply` is the explicit IAM-write approval gate; it does not enable or disable runtime operations. An enabled, unpaused mapping is the runtime opt-in.

| Authorization model and side | Default mapping-driven profile |
| --- | --- | --- |
| RBAC source | `Key Vault Reader` (`21090545-7ca7-4776-b22c-e363652d74d2`), `Key Vault Secrets User` (`4633458b-17de-408a-b874-0445c86b69e6`), and source-only `KeyVaultSync Native Backup`. |
| RBAC target | `Key Vault Reader`, target-only `KeyVaultSync Secret Writer (<subscription-id>)`, and target-only `KeyVaultSync Native Restore`; custom roles are assigned at this vault only. |
| Legacy source | Secrets `get,list`; keys/certificates `get,list,backup`. |
| Legacy target | Secrets `get,list,set`; keys/certificates `get,list,restore`. Existing permissions and unrelated policy entries are retained. |

The default profile creates or validates separate subscription-assignable RBAC roles, then assigns them only at the selected vault scopes: `KeyVaultSync Native Backup` on the source with only `Microsoft.KeyVault/vaults/keys/backup/action` and `Microsoft.KeyVault/vaults/certificates/backup/action`, and `KeyVaultSync Native Restore` on the target with only `Microsoft.KeyVault/vaults/keys/restore/action` and `Microsoft.KeyVault/vaults/certificates/restore/action`. For legacy access-policy vaults, it merges `backup` into source key/certificate permissions and `restore` into target key/certificate permissions. These permissions support eligible one-time seeds; the runtime does not use them to rotate later key or certificate versions.

For an RBAC target, the custom writer role has no management-plane actions and exactly four data actions:

- `Microsoft.KeyVault/vaults/secrets/readMetadata/action`
- `Microsoft.KeyVault/vaults/secrets/getSecret/action`
- `Microsoft.KeyVault/vaults/secrets/setSecret/action`
- `Microsoft.KeyVault/vaults/secrets/update/action`

Its subscription-level **assignable scope** allows vault assignments; it is not a subscription-level grant. `Key Vault Secrets Officer` is intentionally not used because it also permits delete, purge, backup, and restore. The native backup/restore roles do not grant secret deletion, purge, or authorization management. Vault-wide secret permissions can expose certificate-backed secret payloads too; the executor's certificate-backing exclusions are not an IAM restriction. Existing broader permissions are preserved, not revoked, so independently audit effective access and ensure the runner is the sole writer to target objects being changed.

The runtime accepts source-side `sync-vault-id=<target-vault-resource-ID>` and target-side `sync-source-keyvault-id=<source-vault-resource-ID>`. The reverse tag allows multiple targets per source; duplicate declarations of the same pair are collapsed. A target declared by distinct sources, a self-map, missing or cross-subscription resources, chained/cyclic mappings, and `KeyVaultSyncDisabled=true` are rejected before grants. The onboarding scripts support these two canonical tags. A custom source tag selected through `KEYVAULTSYNC_PAIR_TAG` is not inferred by the scripts; use the fixed reverse tag or a separately reviewed access workflow. Pause/remap/removal does not revoke previously granted permissions. Rerun onboarding after a mapping change.

Preflight checks the selected pair before making any changes. Direct/inherited unconditional role assignments and sufficient legacy policies are skipped on reruns. Conditional assignments, compound/duplicate legacy policies, or an existing custom role with different permissions require manual review. If a custom role becomes visible after preflight, the tool reuses it only after verifying that its assignable scope and permissions exactly match the required definition; otherwise it stops. The tools do not evaluate group, PIM, or deny-based effective permissions. Vault authorization/tag rechecks reduce stale updates but provide no ETag fence or transaction. Coordinate other administrators; an apply failure can leave earlier successful changes in place. Review and rerun the preview before retrying.

The script never switches an existing vault from access policies to RBAC, since that invalidates policies and can cause an outage. The Function's planner now reports a mode-first exact mirror proposal for the source's active authorization model: it compares legacy access-policy declarations or direct vault-scoped RBAC assignments, including target-only removals. Parent-scope RBAC remains inventory context; conditional assignment semantics and effective access are not resolved. These entries are guidance only—the runtime does not change authorization. Onboarding must not be run as a Function startup task or with the runtime identity.

## Operator Permissions

Preview requires ARM read access to the identity, the selected source/target, their subscription's vault inventory for mapping-conflict checks, role assignments, and (for RBAC vaults) role definitions. Applying requires `Microsoft.Authorization/roleAssignments/write` at the affected vault scopes or an ancestor. Legacy vaults instead require `Microsoft.KeyVault/vaults/accessPolicies/write`. Creating the RBAC custom roles (secret writer, native backup, and native restore) also requires `Microsoft.Authorization/roleDefinitions/write` at the relevant subscription; use an approved IAM administrator such as Owner or User Access Administrator for that step. `Key Vault Data Access Administrator` alone cannot assign the custom secret writer role because its built-in delegation is restricted to specified built-in roles.

These permissions belong to a reviewed operator or federated provisioning pipeline, never the central runtime identity. Do not grant subscription-wide secret write or Key Vault Administrator merely to avoid onboarding. Subscription-wide data-role inheritance can be considered only when every vault, including future ones, is deliberately in the same access boundary. It also does not configure legacy access policies. A recurring approved onboarding job is simpler than adding Azure Policy automation until automatic new-vault onboarding is a real governance requirement.

Command examples, failure recovery, and tag migration precautions are in [deployment.md](deployment.md). The scripts grant authorization only. For an enabled pair, secret synchronization runs automatically when a valid HMAC key is configured and safe plan items are present; without the key, secret items are blocked. Eligible one-time native seeds are also evaluated automatically and do not require the secret HMAC key. The runtime has no apply or single-writer acknowledgment switch; operators must ensure effective permissions and external writers satisfy the single-writer requirement. Use `KeyVaultSyncDisabled=true` to pause a mapped pair.

## HMAC Key Boundary

`KEYVAULTSYNC_HMAC_KEY` is not an Azure RBAC permission and is not a Bicep parameter. Provision it separately as a protected Function App application setting when standalone secret synchronization is intended. Set `preserveExistingAppSettings=true` before later IaC provisioning so the child app-settings resource retains it. The non-secret `KEYVAULTSYNC_HMAC_KEY_VERSION` uses the code default `app-config-v1` unless deliberately overridden during a reviewed rotation. Never store the key in [the parameter file](../infra/main.parameters.json), azd environment state, source control, logs, or target secrets.

## Verification Checklist

- Confirm the attached user-assigned identity and its distinct principal/client/resource IDs after provisioning.
- Confirm state and run containers have private access and only the intended container-scoped data roles.
- Confirm onboarding is scoped to the intended identity and vaults, with no authorization-mode changes or unintended loss of legacy permissions.
- Before deploying or enabling an active mapping, confirm whether automatic writes are intended; set `KeyVaultSyncDisabled=true` on any pair that is not ready.
- Confirm retired runtime-gate settings have been removed and are not reintroduced through preserved Function App settings.
- Audit existing and inherited access for delete, purge, and authorization-management permissions. Verify backup is limited to the source and restore to the target. The onboarding script does not remove pre-existing broad grants or prove the single-writer contract.

## Microsoft References

- [DefaultAzureCredential client-ID defaults](https://learn.microsoft.com/dotnet/api/azure.identity.defaultazurecredentialoptions.managedidentityclientid) and [.NET credential-chain tradeoffs](https://learn.microsoft.com/dotnet/azure/sdk/authentication/best-practices).
- [Key Vault RBAC guidance and built-in roles](https://learn.microsoft.com/azure/key-vault/general/rbac-guide), [Key Vault data actions](https://learn.microsoft.com/azure/role-based-access-control/permissions/security), and [custom role creation/response shapes](https://learn.microsoft.com/azure/role-based-access-control/custom-roles-cli).
- [Object-ID role assignments](https://learn.microsoft.com/cli/azure/role/assignment#az-role-assignment-create), [legacy policy updates](https://learn.microsoft.com/cli/azure/keyvault#az-keyvault-set-policy), and [identity-based Functions connections](https://learn.microsoft.com/azure/azure-functions/functions-reference#connecting-to-host-storage-with-an-identity).
