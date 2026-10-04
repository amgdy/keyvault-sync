#!/usr/bin/env bash
# Preview or grant the runtime identity the built-in Key Vault roles required for
# full supported object replication for one target-declared mapping. The source
# administrator role is intentionally broad because backup/restore of all Key Vault
# object types is not covered by the reader/user roles. This script never changes vaults, tags,
# authorization mode, objects, role definitions, or existing assignments.
set -euo pipefail

# Print the operator contract; preview is intentionally the default.
usage() {
    printf '%s\n' \
        "Usage: bash $0 --identity-id <uami-resource-id> --target-vault-id <target-vault-resource-id> [--apply]" \
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
apply=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --identity-id|--target-vault-id)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || fail "Missing value for $1."
            if [[ "$1" == '--identity-id' ]]; then identity_id="$2"; else target_id="$2"; fi
            shift 2
            ;;
        --apply) apply=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; fail "Unknown argument: $1" ;;
    esac
done

for dependency in az jq; do
    command -v "$dependency" >/dev/null 2>&1 || fail "$dependency is required."
done

guid_pattern='[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
identity_pattern="^/subscriptions/$guid_pattern/resourceGroups/[^/]+/providers/Microsoft.ManagedIdentity/userAssignedIdentities/[^/]+$"
vault_pattern="^/subscriptions/$guid_pattern/resourceGroups/[^/]+/providers/Microsoft.KeyVault/vaults/[^/]+$"
jq -en --arg id "$identity_id" --arg pattern "$identity_pattern" '$id | test($pattern; "i")' >/dev/null \
    || fail '--identity-id must be a user-assigned managed identity ARM resource ID.'
jq -en --arg id "$target_id" --arg pattern "$vault_pattern" '$id | test($pattern; "i")' >/dev/null \
    || fail '--target-vault-id must be a Key Vault ARM resource ID.'

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
    identity=$(jq '{principalId: .properties.principalId}' <<<"$identity")
fi
principal_id=$(jq -er --arg pattern "$guid_pattern" '.principalId | select(test("^" + $pattern + "$"; "i")) | ascii_downcase' <<<"$identity")
account=$(az account show --subscription "$identity_subscription" --only-show-errors --output json)
tenant_id=$(jq -er '.tenantId | ascii_downcase' <<<"$account")

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

# Build the full supported object-replication onboarding plan. The source
# administrator role is intentionally broad because backup/restore of all Key Vault
# object types is not covered by the reader/user roles. The source Data Access
# Administrator grant is requested for operator-directed source role-assignment
# management; the runtime itself never writes role assignments at source scope.
key_vault_administrator='00482a5a-887f-4fb3-b363-3b7fe8e74483'                # Key Vault Administrator
key_vault_data_access_administrator='8b54135c-b56d-4d72-a534-26097cfdc8d8'    # Key Vault Data Access Administrator

plans=$(jq -cn \
    --arg source "$source_id" --arg sourceSub "$source_subscription" \
    --arg target "$target_id" --arg targetSub "$target_subscription" \
    --arg admin "$key_vault_administrator" --arg rbacAdmin "$key_vault_data_access_administrator" '
    [
      {scope:$source, subscription:$sourceSub, roleId:$admin, roleName:"Key Vault Administrator"},
      {scope:$source, subscription:$sourceSub, roleId:$rbacAdmin, roleName:"Key Vault Data Access Administrator"},
      {scope:$target, subscription:$targetSub, roleId:$admin, roleName:"Key Vault Administrator"},
      {scope:$target, subscription:$targetSub, roleId:$rbacAdmin, roleName:"Key Vault Data Access Administrator"}
    ]')

# Preflight existing direct assignments without changing IAM.
missing='[]'
while IFS= read -r plan; do
    scope=$(jq -r '.scope' <<<"$plan")
    subscription=$(jq -r '.subscription' <<<"$plan")
    role_id=$(jq -r '.roleId' <<<"$plan")
    assignments=$(az role assignment list --scope "$scope" --assignee-object-id "$principal_id" \
        --subscription "$subscription" --fill-principal-name false \
        --only-show-errors --output json)
    exists=$(jq -r --arg role "$role_id" '
        any(.[]; ((.roleDefinitionId // "") | split("/")[-1] | ascii_downcase) == ($role | ascii_downcase)
            and ((.scope // "") | ascii_downcase | gsub("/+$"; "")) == ($ARGS.named.scope | ascii_downcase | gsub("/+$"; "")))' \
        --arg scope "$scope" <<<"$assignments")
    if [[ "$exists" != 'true' ]]; then
        missing=$(jq -c --argjson plan "$plan" '. + [$plan]' <<<"$missing")
    fi
done < <(jq -c '.[]' <<<"$plans")

printf 'KeyVaultSync vault access plan\n'
printf '  Source subscription: %s\n' "$source_subscription"
printf '  Target subscription: %s\n' "$target_subscription"
jq -r --argjson missing "$missing" '
    .[] as $plan | "  - " + $plan.roleName + " at " + $plan.scope
    + (if any($missing[]; .scope == $plan.scope and .roleId == $plan.roleId) then " [create]" else " [existing]" end)' <<<"$plans"

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
        --assignee-object-id "$principal_id" \
        --assignee-principal-type ServicePrincipal \
        --role "$(jq -r '.roleId' <<<"$plan")" \
        --scope "$(jq -r '.scope' <<<"$plan")" \
        --subscription "$(jq -r '.subscription' <<<"$plan")" \
        --only-show-errors --output none
done < <(jq -c '.[]' <<<"$missing")

printf 'Vault access onboarding completed; %s role assignment(s) were created.\n' "$(jq 'length' <<<"$missing")"
