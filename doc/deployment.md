# KeyVaultSync Deployment

## Ownership Boundary

`azure.yaml` and `infra/main.bicep` deploy:

- .NET 10 isolated Function App on Flex Consumption;
- user-assigned managed identity;
- shared host/deployment/state storage;
- private state and run containers;
- Log Analytics and Application Insights;
- infrastructure role assignments.

They do not create, replace, delete, purge, retag, or change authorization mode on participating Key Vaults.

```mermaid
flowchart TB
    Operator["Operator or CI"]
    Azd["Azure Developer CLI"]
    Prepare["prepare-deployment<br/>preprovision and predeploy guard"]
    Bicep["infra/main.bicep"]
    Package["Function package deployment"]
    Function["Flex Consumption Function App"]
    Identity["User-assigned managed identity"]
    Storage["Shared deployment, host,<br/>state, and report storage"]
    Monitor["Log Analytics and<br/>Application Insights"]
    Vaults["Existing participating Key Vaults<br/>not owned by this deployment"]

    Operator --> Azd
    Azd --> Prepare
    Prepare --> Bicep
    Prepare --> Package
    Bicep --> Function
    Bicep --> Identity
    Bicep --> Storage
    Bicep --> Monitor
    Package --> Function
    Function -. runtime access only .-> Vaults
```

## Configuration

The azd environment must supply:

- deployment subscription and location;
- either an existing `AZURE_RESOURCE_GROUP` or a three-letter `KEYVAULTSYNC_REGION_CODE` for generated resource-group naming;
- `KEYVAULTSYNC_SUBSCRIPTIONS`;
- the HMAC key;
- one networking profile (`public`, `private-managed`, or `private-existing`);
- profile-specific private-network inputs when required;
- optional adopted resource-name overrides;
- optional deployment tags.

Every subscription in `KEYVAULTSYNC_SUBSCRIPTIONS` is scanned as part of one mapping graph. Main Bicep grants the runtime identity Reader in each one. The provisioning identity therefore needs role-assignment permission at every listed subscription.

Each target vault declares its source with `sync-source-keyvault-id`. Cross-subscription pairs are supported when both endpoints are configured, use Azure RBAC, and share a tenant.

## Provision

```sh
azd auth login
azd env new <environment> --subscription <deployment-subscription-id> --location <region>
azd provision --preview
azd up
```

Review the preview before applying. One deployment-preparation script serves both azd phases:

- before provisioning, it validates and persists multi-subscription configuration, establishes the deployment resource-group name, collects missing private-network details, obtains or preserves the HMAC key, and optionally configures one deployment tag;
- before package deployment, it revalidates the HMAC key and confirms that Flex deployment storage is reachable through the expected public or private Blob path.

`azd` defers subscription-list and HMAC initialization to the preprovision hook, so it does not collect those Bicep parameters before the preparation logic runs. If no key exists, an interactive run shows one hidden prompt: paste an existing Base64-encoded 32-byte key, or press Enter to generate one cryptographically. The key is saved once in the active azd environment; the later predeploy hook reuses it without asking again. Valid existing keys are never displayed or rotated. An invalid saved value can be interactively replaced after warning the operator, but the replacement is persisted only after it validates as Base64 for exactly 32 bytes. Non-interactive pipelines must provide valid protected HMAC material.

When `AZURE_RESOURCE_GROUP` is absent, an interactive run asks for exactly three ASCII letters representing the Azure region abbreviation, normalizes them to lowercase, and persists:

```text
KEYVAULTSYNC_REGION_CODE=swc
AZURE_RESOURCE_GROUP=rg-keyvaultsync-swc-<environment>
```

Use a consistent internal abbreviation such as `eun` for North Europe or `swc` for Sweden Central. The environment component is normalized to lowercase letters, numbers, and hyphens. Existing `AZURE_RESOURCE_GROUP` values are reused without requesting a region abbreviation or renaming the group. Non-interactive creation must provide `KEYVAULTSYNC_REGION_CODE` when it does not provide `AZURE_RESOURCE_GROUP`.

Generated resource names use one reusable Bicep variable: `environmentUniqueToken`.
It is the deterministic `uniqueString` value seeded with the deployment
subscription ID, normalized environment name, and location.

Changing any seed changes every generated solution-resource name. Resource-name override parameters remain the adoption mechanism when an existing name must be retained.

For a new interactive environment, the same hook asks for one networking
profile. Public endpoints are the default; the other choices create a dedicated
KeyVaultSync private network or attach to existing enterprise networking.
Selections are numbered and Enter accepts option 1. The managed-private profile
shows the complete recommended topology and offers one default choice. Individual
VNet and subnet values are requested only when customization is selected.
The existing-private profile prompts for every missing subnet, private DNS zone,
and Azure Monitor Private Link Scope resource ID. Resolved values are written
with `azd env set` before Bicep provisioning begins and reused on later runs.
When an older environment has no profile but still has the retired mode/source
pair, the hook translates that pair once and persists the equivalent profile.

The ignored `.azure/<environment>/.env` stores sensitive plaintext configuration. Protect it and backups.

```mermaid
sequenceDiagram
    participant Operator
    participant azd
    participant Prepare as prepare-deployment
    participant Azure

    Operator->>azd: azd up or azd provision
    azd->>Prepare: provision phase
    Prepare->>Prepare: Validate subscriptions and stable HMAC key
    Prepare-->>azd: Prepared environment
    azd->>Azure: Preview or apply Bicep
    azd->>Prepare: deploy phase
    Prepare->>Azure: Verify deployment-storage reachability
    Prepare-->>azd: Deployment guard passed
    azd->>Azure: Upload Function package
```

## Script Surface

The operator-facing automation is three responsibilities, each implemented for Bash and PowerShell:

- `prepare-deployment.*` runs only as the azd preprovision/predeploy guard;
- `postdeploy-keyvault-access.*` discovers enabled mappings, lists each pair's source and target subscription, resource group, and vault name in a table, then coordinates optional onboarding;
- `grant-keyvault-access.*` previews or applies the three required per-pair grants.

There are no separate HMAC, storage-validation, backup/restore, or vault-mutation deployment scripts.

## Vault Onboarding

After deployment, use the target-based onboarding scripts:

```sh
bash scripts/grant-keyvault-access.sh \
  --identity-id "<uami-resource-id>" \
  --target-vault-id "<target-vault-resource-id>"
```

```powershell
.\scripts\Grant-KeyVaultAccess.ps1 `
  -IdentityResourceId "<uami-resource-id>" `
  -TargetVaultResourceId "<target-vault-resource-id>"
```

Preview is the default. `--apply`/`-Apply` is required for IAM changes. The scripts resolve the source from the target tag, support cross-subscription pairs, and require Azure RBAC on both vaults.

Interactive azd deployments can run the optional post-deploy hook. It discovers target-declared mappings in all configured subscriptions, previews every grant, and asks separately before applying. Non-interactive runs skip it.

## State Preservation

The storage account is not disposable. It contains:

- Functions host/deployment artifacts;
- pair leases and ETag-guarded state;
- object baselines and unresolved intents;
- deletion approvals;
- durable plans and run reports.

Blob versioning and 14-day soft-delete retention are enabled. Preserve the storage account, managed identity, HMAC key, and key-version label across host replacement.

Adopting an existing deployment requires compatible state and exact resource names. Incompatible non-empty state fails closed and requires explicit administrative handling.

## Networking

The `public` profile uses public service endpoints with Entra authorization and Shared Key disabled.

The `private-managed` and `private-existing` profiles configure Flex Consumption VNet integration, disable public access on the Function, storage, and Application Insights, and create private endpoints for Blob, Queue, Table, and Azure Monitor. They do not create private endpoints or network resources for participating source and target vaults; customer infrastructure must make those vaults reachable from the Function. The managed profile creates a minimal dedicated VNet, private DNS zones, and an Azure Monitor Private Link Scope. The existing profile reuses supplied enterprise subnets, zones, and scope. See [networking](networking.md) for inputs, ownership boundaries, package-deployment constraints, and validation.

## Validation

Local validation:

```sh
dotnet test tests/KeyVaultSync.Runner.Tests/KeyVaultSync.Runner.Tests.csproj --no-restore
dotnet build src/KeyVaultSync.Function/KeyVaultSync.Function.csproj --no-restore -p:GenerateDocumentationFile=true -warnaserror
az bicep build --file infra/main.bicep --outfile /tmp/keyvaultsync-main.json
```

Before live validation, confirm the exact tenant, subscriptions, resource group, regions, vault names, IAM scope, mutation approval, retention period, and cleanup boundary. Create disposable test vaults separately from application Bicep. Never purge them as part of automated validation.

A successful deployment or build is not proof of effective permissions, telemetry ingestion, or safe mutation.
