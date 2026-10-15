#!/usr/bin/env bash
# Preview or grant the runtime identity the built-in Key Vault roles required for
# full supported object replication for one target-declared mapping. The source
# administrator role is intentionally broad because backup/restore of all Key Vault
# object types is not covered by the reader/user roles. This script never changes vaults, tags,
# authorization mode, objects, role definitions, or existing assignments.
# --include-signed-in-user also plans the same vault roles plus Storage Blob Data Contributor on the
# state storage account for the signed-in operator, so the terminal runner can run as that identity.
set -euo pipefail

# Print the operator contract; preview is intentionally the default.
usage() {
    printf '%s\n' \
        "Usage: bash $0 --target-vault-id <target-vault-resource-id> [--identity-id <uami-resource-id>] [--include-signed-in-user [--storage-account-uri <blob-uri>]] [--apply]" \
        'When --identity-id is omitted, the script uses KEYVAULTSYNC_IDENTITY_RESOURCE_ID or the current azd environment output.' \
        '--include-signed-in-user also grants the signed-in operator the same vault roles and Storage Blob Data Contributor on the' \
        'state storage account (KEYVAULTSYNC_STORAGE_ACCOUNT_URI or the azd output) so the terminal runner can run as that identity.' \
        'The target must declare sync-source-keyvault-id. Source and target may be in different subscriptions in the same tenant.' \
        'Preview is the default. --apply creates only missing direct built-in role assignments.'
}

# Print one terminal error and stop before later phases can mutate IAM.
fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

# Parse and validate all input before resolving Azure resources.
identity_id=''
target_id=''
storage_uri=''
include_signed_in_user=false
apply=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --identity-id|--target-vault-id|--storage-account-uri)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || fail "Missing value for $1."
            case "$1" in
                --identity-id) identity_id="$2" ;;
                --target-vault-id) target_id="$2" ;;
                *) storage_uri="$2" ;;
            esac
            shift 2
            ;;
        --include-signed-in-user) include_signed_in_user=true; shift ;;
        --apply) apply=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; fail "Unknown argument: $1" ;;
    esac
done

for dependency in az jq; do
    command -v "$dependency" >/dev/null 2>&1 || fail "$dependency is required."
done

# Normalize a scalar emitted by azd, including values wrapped in matching quotes.
normalize_scalar() {
    jq -rn --arg value "$1" '
        $value | gsub("^\\s+|\\s+$"; "")
        | if length >= 2 and
            (((.[0:1] == "\"") and (.[-1:] == "\"")) or
             ((.[0:1] == "\u0027") and (.[-1:] == "\u0027")))
          then .[1:-1]
          else .
          end'
}

# Prefer an explicit argument, then the hook environment, then the selected azd environment.
# Arguments: setting name, explicit argument value, hook environment value, argument flag name.
resolve_azd_setting() {
    local name="$1"
    local resolved="$2"
    if [[ -z "$resolved" ]]; then
        resolved="$3"
    fi
    if [[ -z "$resolved" ]]; then
        command -v azd >/dev/null 2>&1 \
            || fail "azd is required when $4 and $name are not supplied."
        local azd_arguments=(env get-value "$name")
        if [[ -n "${AZURE_ENV_NAME:-}" ]]; then
            azd_arguments+=(--environment "$AZURE_ENV_NAME")
        fi
        resolved=$(azd "${azd_arguments[@]}" 2>/dev/null) \
            || fail "Could not read $name from the current azd environment."
    fi
    normalize_scalar "$resolved"
}

identity_id=$(resolve_azd_setting KEYVAULTSYNC_IDENTITY_RESOURCE_ID "$identity_id" "${KEYVAULTSYNC_IDENTITY_RESOURCE_ID:-}" --identity-id)
[[ -n "$identity_id" ]] \
    || fail 'No managed identity was resolved. Supply --identity-id or set KEYVAULTSYNC_IDENTITY_RESOURCE_ID in the current azd environment.'
if [[ "$include_signed_in_user" == true ]]; then
    storage_uri=$(resolve_azd_setting KEYVAULTSYNC_STORAGE_ACCOUNT_URI "$storage_uri" "${KEYVAULTSYNC_STORAGE_ACCOUNT_URI:-}" --storage-account-uri)
    [[ -n "$storage_uri" ]] \
        || fail 'No state storage account was resolved. Supply --storage-account-uri or set KEYVAULTSYNC_STORAGE_ACCOUNT_URI in the current azd environment.'
fi

guid_pattern='[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
identity_pattern="^/subscriptions/$guid_pattern/resourceGroups/[^/]+/providers/Microsoft.ManagedIdentity/userAssignedIdentities/[^/]+$"
vault_pattern="^/subscriptions/$guid_pattern/resourceGroups/[^/]+/providers/Microsoft.KeyVault/vaults/[^/]+$"
jq -en --arg id "$identity_id" --arg pattern "$identity_pattern" '$id | test($pattern; "i")' >/dev/null \
    || fail '--identity-id must be a user-assigned managed identity ARM resource ID.'
jq -en --arg id "$target_id" --arg pattern "$vault_pattern" '$id | test($pattern; "i")' >/dev/null \
    || fail '--target-vault-id must be a Key Vault ARM resource ID.'
storage_account_name=''
if [[ "$include_signed_in_user" == true ]]; then
    storage_account_name=$(jq -rn --arg uri "$storage_uri" '
        $uri | ascii_downcase | capture("^https://(?<name>[a-z0-9]{3,24})\\.blob\\.[^/]+/?$").name // ""')
    [[ -n "$storage_account_name" ]] \
        || fail '--storage-account-uri must be an HTTPS Blob service URI such as https://<account>.blob.core.windows.net/.'
fi

if ! az account show --only-show-errors --output none >/dev/null 2>&1; then
    fail 'Azure CLI is not authenticated. Run az login once; azd must be configured with auth.useAzCliAuth=true so both tools share that session.'
fi

printf '[KeyVaultSync][vault-access] Starting %s for one target-declared mapping.\n' \
    "$([[ "$apply" == true ]] && printf 'apply' || printf 'read-only preview')"

# Extract the subscription segment from a validated ARM resource ID.
subscription_from_id() {
    jq -rn --arg id "$1" '$id | split("/")[2] | ascii_downcase'
}

# Normalize ARM IDs for case-insensitive equality checks.
normalized_id() {
    jq -rn --arg id "$1" '$id | gsub("/+$"; "") | ascii_downcase'
}

# Read one case-insensitive string tag from Azure resource JSON.
tag_value() {
    jq -r --arg name "$2" '
        [((.tags // {}) | to_entries[])
         | select((.key | ascii_downcase) == ($name | ascii_downcase))
         | select(.value | type == "string")
         | (.value | gsub("^\\s+|\\s+$"; ""))][0] // ""' <<<"$1"
}

# Read a vault by ID, with a generic ARM fallback for compatible Azure CLI versions.
show_vault() {
    local id="$1"
    local subscription
    subscription=$(subscription_from_id "$id")
    if az keyvault show --ids "$id" --subscription "$subscription" --only-show-errors --output json 2>/dev/null; then
        return 0
    fi
    az resource show --ids "$id" --subscription "$subscription" --only-show-errors --output json
}

# Resolve the managed identity principal and prove that the signed-in context uses its tenant.
identity_subscription=$(subscription_from_id "$identity_id")
if ! identity=$(az identity show --ids "$identity_id" --subscription "$identity_subscription" --only-show-errors --output json 2>/dev/null); then
    identity=$(az resource show --ids "$identity_id" --subscription "$identity_subscription" --api-version 2023-01-31 --only-show-errors --output json)
    identity=$(jq '{principalId: .properties.principalId, tenantId: .properties.tenantId}' <<<"$identity")
fi
principal_id=$(jq -er --arg pattern "$guid_pattern" '.principalId | select(test("^" + $pattern + "$"; "i")) | ascii_downcase' <<<"$identity")
identity_tenant_id=$(jq -er '.tenantId | select(type == "string" and length > 0) | ascii_downcase' <<<"$identity")
account=$(az account show --subscription "$identity_subscription" --only-show-errors --output json)
account_tenant_id=$(jq -er '.tenantId | ascii_downcase' <<<"$account")
[[ "$account_tenant_id" == "$identity_tenant_id" ]] \
    || fail 'The signed-in operator and runtime identity must belong to the same tenant.'
tenant_id="$identity_tenant_id"

# Print "<object-id> <principal-type>" for the signed-in operator; the type selects the
# --assignee-principal-type used for any optional signed-in grant.
current_principal_id() {
    local principal=''
    if principal=$(az ad signed-in-user show --query id -o tsv 2>/dev/null); then
        printf '%s User' "$principal"
        return 0
    fi

    local app_id=''
    app_id=$(az account show --query user.name -o tsv 2>/dev/null || true)
    if [[ -n "$app_id" ]]; then
        principal=$(az ad sp show --id "$app_id" --query id -o tsv 2>/dev/null || true)
        if [[ -n "$principal" ]]; then
            printf '%s ServicePrincipal' "$principal"
            return 0
        fi
    fi

    return 1
}

assert_principal_can_manage_keyvault_rbac() {
    local scope="$1"
    local subscription_id="$2"
    local current_principal="$3"
    local resource_label="$4"
    local assignments
    # --include-inherited returns the vault scope and every parent scope, so --all
    # (which the CLI rejects when combined with --scope) is not needed.
    if ! assignments=$(az role assignment list \
            --scope "$scope" \
            --assignee-object-id "$current_principal" \
            --subscription "$subscription_id" \
            --include-inherited \
            --include-groups \
            --fill-principal-name false \
            --only-show-errors \
            --output json 2>&1); then
        fail "Azure CLI could not read effective RBAC assignments on the $resource_label. Verify the Azure CLI session and roleAssignments/read access. Azure CLI output: $assignments"
    fi
    if ! jq -e '
        any(.[];
            ((.roleDefinitionName // "") | ascii_downcase) as $role
            | $role == "owner"
                or $role == "user access administrator"
                or $role == "role based access control administrator")' <<<"$assignments" >/dev/null; then
        fail "The current signed-in principal does not have Owner, User Access Administrator, or Role Based Access Control Administrator effective on the $resource_label. Sign in with a principal that can assign these RBAC roles before onboarding."
    fi
    printf 'Verified the current Azure principal can manage role assignments on the %s.\n' "$resource_label"
}

# Resolve the target-declared mapping and reject paused, cross-tenant, or access-policy vaults.
target=$(show_vault "$target_id")
jq -e --arg id "$(normalized_id "$target_id")" --arg tenant "$tenant_id" '
    (.id | ascii_downcase | gsub("/+$"; "")) == $id
    and (.properties.tenantId | ascii_downcase) == $tenant
    and .properties.enableRbacAuthorization == true' <<<"$target" >/dev/null \
    || fail 'The target vault must match the requested ID, use the runtime tenant, and have Azure RBAC enabled.'
[[ "$(tag_value "$target" 'KeyVaultSyncDisabled')" != 'true' ]] \
    || fail 'The target mapping is disabled; no permissions were changed.'

source_id=$(tag_value "$target" 'sync-source-keyvault-id')
[[ -n "$source_id" ]] || fail 'The target vault is missing sync-source-keyvault-id.'
jq -en --arg id "$source_id" --arg pattern "$vault_pattern" '$id | test($pattern; "i")' >/dev/null \
    || fail 'sync-source-keyvault-id is not a valid Key Vault ARM resource ID.'
source=$(show_vault "$source_id")
jq -e --arg id "$(normalized_id "$source_id")" --arg tenant "$tenant_id" '
    (.id | ascii_downcase | gsub("/+$"; "")) == $id
    and (.properties.tenantId | ascii_downcase) == $tenant
    and .properties.enableRbacAuthorization == true' <<<"$source" >/dev/null \
    || fail 'The source vault must match the target declaration, use the runtime tenant, and have Azure RBAC enabled.'
[[ "$(tag_value "$source" 'KeyVaultSyncDisabled')" != 'true' ]] \
    || fail 'The source mapping is disabled; no permissions were changed.'

source_id=$(jq -r '.id' <<<"$source")
target_id=$(jq -r '.id' <<<"$target")
source_subscription=$(subscription_from_id "$source_id")
target_subscription=$(subscription_from_id "$target_id")

# Preflight the operator's effective inherited/group RBAC assignments before the
# plan is approved. This remains read-only and prevents a later pair from failing
# after earlier pairs have already been onboarded.
printf 'Checking whether the current Azure principal can assign Key Vault RBAC permissions on both vaults.\n'
current_principal_info=$(current_principal_id || true)
if [[ -z "$current_principal_info" ]]; then
    fail 'Could not resolve the current Azure user or service principal. Sign in with an account that can assign Key Vault RBAC roles before onboarding.'
fi
read -r current_principal current_principal_type <<<"$current_principal_info"
current_principal=$(tr '[:upper:]' '[:lower:]' <<<"$current_principal")
assert_principal_can_manage_keyvault_rbac "$target_id" "$target_subscription" "$current_principal" 'target vault'
assert_principal_can_manage_keyvault_rbac "$source_id" "$source_subscription" "$current_principal" 'source vault'

# Resolve the state account in the deployment subscription and require its Blob endpoint to match
# the configured URI so the grant cannot land on a same-named account elsewhere.
storage_id=''
storage_subscription=''
if [[ "$include_signed_in_user" == true ]]; then
    storage=$(az storage account show --name "$storage_account_name" --subscription "$identity_subscription" \
        --only-show-errors --output json 2>/dev/null) \
        || fail "State storage account $storage_account_name was not found in the runtime identity's subscription."
    jq -e --arg uri "$storage_uri" '
        ((.primaryEndpoints.blob // "") | ascii_downcase | rtrimstr("/")) == ($uri | ascii_downcase | rtrimstr("/"))' \
        <<<"$storage" >/dev/null \
        || fail 'The resolved storage account Blob endpoint does not match the configured state storage URI.'
    storage_id=$(jq -r '.id' <<<"$storage")
    storage_subscription=$(subscription_from_id "$storage_id")
    assert_principal_can_manage_keyvault_rbac "$storage_id" "$storage_subscription" "$current_principal" 'state storage account'
fi

# Build the full supported object-replication onboarding plan. The source
# administrator role is intentionally broad because backup/restore of all Key Vault
# object types is not covered by the reader/user roles. The source Data Access
# Administrator grant is requested for operator-directed source role-assignment
# management; the runtime itself never writes role assignments at source scope.
key_vault_administrator='00482a5a-887f-4fb3-b363-3b7fe8e74483'                # Key Vault Administrator
key_vault_data_access_administrator='8b54135c-b56d-4d72-a534-26097cfdc8d8'    # Key Vault Data Access Administrator
storage_blob_data_contributor='ba92f5b4-2d11-453d-a403-e96b0029c9fe'          # Storage Blob Data Contributor

vault_plans() {
    jq -cn \
        --arg principal "$1" --arg principalType "$2" --arg label "$3" \
        --arg source "$source_id" --arg sourceSub "$source_subscription" \
        --arg target "$target_id" --arg targetSub "$target_subscription" \
        --arg admin "$key_vault_administrator" --arg rbacAdmin "$key_vault_data_access_administrator" '
        [
          {scope:$source, subscription:$sourceSub, roleId:$admin, roleName:"Key Vault Administrator"},
          {scope:$source, subscription:$sourceSub, roleId:$rbacAdmin, roleName:"Key Vault Data Access Administrator"},
          {scope:$target, subscription:$targetSub, roleId:$admin, roleName:"Key Vault Administrator"},
          {scope:$target, subscription:$targetSub, roleId:$rbacAdmin, roleName:"Key Vault Data Access Administrator"}
        ] | map(. + {principalId:$principal, principalType:$principalType, principalLabel:$label})'
}

plans=$(vault_plans "$principal_id" ServicePrincipal 'runtime identity')
if [[ "$include_signed_in_user" == true ]]; then
    signed_in_label="signed-in $(tr '[:upper:]' '[:lower:]' <<<"${current_principal_type/ServicePrincipal/service principal}")"
    if [[ "$current_principal" == "$principal_id" ]]; then
        printf 'The signed-in principal is the runtime identity; no separate signed-in grants are planned.\n'
    else
        signed_in_plans=$(vault_plans "$current_principal" "$current_principal_type" "$signed_in_label")
        signed_in_plans=$(jq -c \
            --arg scope "$storage_id" --arg subscription "$storage_subscription" --arg role "$storage_blob_data_contributor" \
            --arg principal "$current_principal" --arg principalType "$current_principal_type" --arg label "$signed_in_label" '
            . + [{scope:$scope, subscription:$subscription, roleId:$role, roleName:"Storage Blob Data Contributor",
                  principalId:$principal, principalType:$principalType, principalLabel:$label}]' <<<"$signed_in_plans")
        plans=$(jq -c --argjson more "$signed_in_plans" '. + $more' <<<"$plans")
    fi
fi

# Preflight existing direct assignments without changing IAM.
missing='[]'
while IFS= read -r plan; do
    scope=$(jq -r '.scope' <<<"$plan")
    subscription=$(jq -r '.subscription' <<<"$plan")
    role_id=$(jq -r '.roleId' <<<"$plan")
    assignee=$(jq -r '.principalId' <<<"$plan")
    assignments=$(az role assignment list --scope "$scope" --assignee-object-id "$assignee" \
        --subscription "$subscription" --fill-principal-name false \
        --only-show-errors --output json)
    exists=$(jq -r --arg role "$role_id" '
        any(.[]; ((.roleDefinitionId // "") | split("/")[-1] | ascii_downcase) == ($role | ascii_downcase)
            and ((.scope // "") | ascii_downcase | gsub("/+$"; "")) == ($scope | ascii_downcase | gsub("/+$"; "")))' \
        --arg scope "$scope" <<<"$assignments")
    if [[ "$exists" != 'true' ]]; then
        missing=$(jq -c --argjson plan "$plan" '. + [$plan]' <<<"$missing")
    fi
done < <(jq -c '.[]' <<<"$plans")

printf 'KeyVaultSync vault access plan\n'
printf '  Source subscription: %s\n' "$source_subscription"
printf '  Target subscription: %s\n' "$target_subscription"
jq -r --argjson missing "$missing" '
    .[] as $plan | "  - " + $plan.roleName + " at " + $plan.scope + " for " + $plan.principalLabel
    + (if any($missing[]; .scope == $plan.scope and .roleId == $plan.roleId and .principalId == $plan.principalId)
       then " [create]" else " [existing]" end)' <<<"$plans"

if [[ "$apply" != true ]]; then
    printf 'Preview only; no role assignments were changed.\n'
    exit 0
fi

# Re-read both endpoints immediately before the first mutation. A changed mapping,
# tenant, RBAC mode, or disable tag invalidates the reviewed plan.
current_target=$(show_vault "$target_id")
current_source=$(show_vault "$source_id")
[[ "$(tag_value "$current_target" 'sync-source-keyvault-id' | tr '[:upper:]' '[:lower:]')" == "$(normalized_id "$source_id")" ]] \
    || fail 'The target mapping changed after preflight; no permissions were changed.'
for current in "$current_source" "$current_target"; do
    jq -e --arg tenant "$tenant_id" '
        (.properties.tenantId | ascii_downcase) == $tenant
        and .properties.enableRbacAuthorization == true
        and ([((.tags // {}) | to_entries[])
            | select((.key | ascii_downcase) == "keyvaultsyncdisabled")
            | (.value | tostring | ascii_downcase)][0] // "false") != "true"' <<<"$current" >/dev/null \
        || fail 'Vault eligibility changed after preflight; no permissions were changed.'
done

# The mutation phase creates only assignments proven missing during the reviewed preflight.
while IFS= read -r plan; do
    az role assignment create \
        --assignee-object-id "$(jq -r '.principalId' <<<"$plan")" \
        --assignee-principal-type "$(jq -r '.principalType' <<<"$plan")" \
        --role "$(jq -r '.roleId' <<<"$plan")" \
        --scope "$(jq -r '.scope' <<<"$plan")" \
        --subscription "$(jq -r '.subscription' <<<"$plan")" \
        --only-show-errors --output none
done < <(jq -c '.[]' <<<"$missing")

printf 'Vault access onboarding completed; %s role assignment(s) were created.\n' "$(jq 'length' <<<"$missing")"
