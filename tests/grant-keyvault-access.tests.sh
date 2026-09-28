#!/usr/bin/env bash
# Offline contract checks for the onboarding script. The exported az function rejects unknown
# calls and never invokes Azure CLI. All mutable fixtures live in an isolated temporary directory.
set -euo pipefail
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture_directory=$(mktemp -d)
trap 'rm -rf "$fixture_directory"' EXIT
export fixture_directory
export fixture_subscription='11111111-1111-1111-1111-111111111111'
export fixture_tenant='22222222-2222-2222-2222-222222222222'
export fixture_principal='33333333-3333-3333-3333-333333333333'
export fixture_writer='44444444-4444-4444-4444-444444444444'
export fixture_backup='55555555-5555-5555-5555-555555555555'
export fixture_restore='66666666-6666-6666-6666-666666666666'
export fixture_scope="/subscriptions/$fixture_subscription"
identity_id="$fixture_scope/resourceGroups/identity/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-keyvaultsync"
export fixture_source="$fixture_scope/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/source-vault"
export fixture_target="$fixture_scope/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/target-vault"
export fixture_other="$fixture_scope/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/other-vault"

argument() {
    local name="$1"
    shift
    while [[ $# -gt 0 ]]; do
        if [[ "$1" == "$name" ]]; then printf '%s\n' "$2"; return; fi
        shift
    done
    return 1
}

permission_values() {
    local name="$1"
    shift
    while [[ $# -gt 0 && "$1" != "$name" ]]; do shift; done
    if [[ $# == 0 ]]; then printf '[]'; return; fi
    shift
    local values=()
    while [[ $# -gt 0 && "$1" != --* ]]; do values+=("$1"); shift; done
    jq -cn --args '$ARGS.positional' -- "${values[@]}"
}

az() {
    jq -cn --args '$ARGS.positional' -- "$@" >>"$fixture_directory/calls.jsonl"
    local response resource_id role_id scope policy_name permissions definition definition_name
    case "$1 $2 ${3:-}" in
        'identity show --ids') jq -n --arg principal "$fixture_principal" --arg tenant "$fixture_tenant" '{principalId: $principal, tenantId: $tenant}' ;;
        'account show --subscription') jq -n --arg tenant "${fixture_operator_tenant:-$fixture_tenant}" '{tenantId: $tenant}' ;;
        'keyvault list --resource-type')
            [[ ${mock_fail_read:-false} != true ]] || return 71
            jq '.' "$fixture_directory/vaults.json"
            ;;
        'keyvault show --name')
            local vault_name resource_group
            vault_name=$(argument --name "$@")
            resource_group=$(argument --resource-group "$@")
            response=$(jq -c --arg name "$vault_name" --arg resourceGroup "$resource_group" \
                '.[] | select(.name == $name and .resourceGroup == $resourceGroup)' "$fixture_directory/vaults.json")
            resource_id=$(jq -r '.id' <<<"$response")
            if [[ ${mock_drift:-false} == true && $(jq -s '[.[] | select(.[0:2] == ["keyvault", "show"])] | length' "$fixture_directory/calls.jsonl") -gt 2 && "$resource_id" == "$fixture_source" ]]; then
                response=$(jq --arg other "$fixture_other" '.tags["sync-vault-id"] = $other' <<<"$response")
            fi
            printf '%s\n' "$response"
            ;;
        'role assignment list')
            [[ ${mock_fail_read:-false} != true ]] || return 71
            scope=$(argument --scope "$@")
            jq --arg scope "$scope" '[.[] | select(.scope == $scope)]' "$fixture_directory/assignments.json"
            ;;
        'role assignment create')
            scope=$(argument --scope "$@")
            [[ ${mock_fail_target:-false} != true || "$scope" != "$fixture_target" ]] || return 72
            role_id=$(argument --role "$@")
            response=$(jq -cn --arg scope "$scope" --arg role "$fixture_scope/providers/Microsoft.Authorization/roleDefinitions/$role_id" \
                --arg principal "$fixture_principal" '{scope: $scope, roleDefinitionId: $role, principalId: $principal}')
            jq --argjson assignment "$response" '. + [$assignment]' "$fixture_directory/assignments.json" >"$fixture_directory/next.json"
            mv "$fixture_directory/next.json" "$fixture_directory/assignments.json"
            printf '%s\n' "$response"
            ;;
        'role definition list')
            definition_name=$(argument --name "$@")
            jq --arg name "$definition_name" '[.[] | select(.roleName == $name)]' "$fixture_directory/definitions.json"
            ;;
        'role definition create')
            definition=$(argument --role-definition "$@")
            case "$(jq -r '.Name' <<<"$definition")" in
                *'Native Backup'*) role_id="$fixture_backup" ;;
                *'Native Restore'*) role_id="$fixture_restore" ;;
                *) role_id="$fixture_writer" ;;
            esac
            response=$(jq -c --arg id "$role_id" '{name: $id, roleName: .Name, roleType: "CustomRole", assignableScopes: .AssignableScopes,
                permissions: [{actions: .Actions, notActions: .NotActions, dataActions: .DataActions, notDataActions: .NotDataActions}]}' <<<"$definition")
            jq --argjson definition "$response" '. + [$definition]' "$fixture_directory/definitions.json" >"$fixture_directory/next.json"
            mv "$fixture_directory/next.json" "$fixture_directory/definitions.json"
            printf '%s\n' "$response"
            ;;
        'keyvault set-policy --name')
            policy_name=$(argument --name "$@")
            permissions=$(jq -cn --argjson keys "$(permission_values --key-permissions "$@")" \
                --argjson secrets "$(permission_values --secret-permissions "$@")" \
                --argjson certificates "$(permission_values --certificate-permissions "$@")" \
                --argjson storage "$(permission_values --storage-permissions "$@")" \
                '{keys: $keys, secrets: $secrets, certificates: $certificates, storage: $storage}')
            jq --arg name "$policy_name" --arg principal "$fixture_principal" --arg tenant "$fixture_tenant" --argjson permissions "$permissions" '
                map(if .name == $name then .properties.accessPolicies |=
                    (if any(.[]; .objectId == $principal) then map(if .objectId == $principal then .permissions = $permissions else . end)
                     else . + [{objectId: $principal, tenantId: $tenant, permissions: $permissions}] end) else . end)' \
                "$fixture_directory/vaults.json" >"$fixture_directory/next.json"
            mv "$fixture_directory/next.json" "$fixture_directory/vaults.json"
            printf '{}\n'
            ;;
        *) printf 'Unexpected mocked Azure call: %s\n' "$*" >&2; return 99 ;;
    esac
}
export -f az argument permission_values

reset_fixture() {
    export mock_drift=false mock_fail_read=false mock_fail_target=false
    printf '' >"$fixture_directory/calls.jsonl"
    printf '[]\n' >"$fixture_directory/assignments.json"
    printf '[]\n' >"$fixture_directory/definitions.json"
    jq -n --arg source "$fixture_source" --arg target "$fixture_target" --arg other "$fixture_other" --arg tenant "$fixture_tenant" '
        [$source, $target, $other] | map({id: ., name: (split("/")[-1]), resourceGroup: "vaults", tags: {},
            properties: {tenantId: $tenant, enableRbacAuthorization: true, accessPolicies: []}})
        | .[0].tags["sync-vault-id"] = $target' >"$fixture_directory/vaults.json"
}

edit_fixture() {
    jq "$@" "$fixture_directory/vaults.json" >"$fixture_directory/next.json"
    mv "$fixture_directory/next.json" "$fixture_directory/vaults.json"
}

run_script() {
    if bash "$repository_root/scripts/grant-keyvault-access.sh" --identity-id "$identity_id" --source-vault-id "$fixture_source" "$@" >"$fixture_directory/output.txt" 2>&1; then
        return 0
    else
        local exit_code=$?
        if [[ ${MOCK_TRACE:-false} == true ]]; then cat "$fixture_directory/output.txt" >&2; fi
        return "$exit_code"
    fi
}

run_target_script() {
    if bash "$repository_root/scripts/grant-keyvault-access.sh" --identity-id "$identity_id" --target-vault-id "$fixture_target" "$@" >"$fixture_directory/output.txt" 2>&1; then
        return 0
    else
        local exit_code=$?
        if [[ ${MOCK_TRACE:-false} == true ]]; then cat "$fixture_directory/output.txt" >&2; fi
        return "$exit_code"
    fi
}

assert_json() {
    jq -e "$1" "$2" >/dev/null || { printf 'Assertion failed: %s\n' "$1" >&2; exit 1; }
}

assert_no_writes() {
    jq -se 'all(.[]; (.[0:3] != ["role", "assignment", "create"]) and (.[0:3] != ["role", "definition", "create"]) and (.[0:2] != ["keyvault", "set-policy"]))' \
        "$fixture_directory/calls.jsonl" >/dev/null
}

expect_failure() {
    if run_script "$@"; then printf 'Expected failure: %s\n' "$*" >&2; exit 1; fi
}

expect_target_failure() {
    if run_target_script "$@"; then printf 'Expected target-path failure: %s\n' "$*" >&2; exit 1; fi
}

reset_fixture
run_script
assert_no_writes
grep -q 'Mode: mapping-driven-sync' "$fixture_directory/output.txt"
grep -q 'Native key/certificate seed permissions: enabled' "$fixture_directory/output.txt"
printf 'PASS default mapping-driven preview includes supported sync grants and performs no writes\n'
run_script --apply
assert_json 'length == 6
    and ([.[] | select(.scope == env.fixture_source)] | length) == 3
    and ([.[] | select(.scope == env.fixture_target)] | length) == 3' "$fixture_directory/assignments.json"
assert_json 'length == 3
    and any(.[]; (.roleName | contains("Secret Writer"))
        and .permissions[0].actions == []
        and (.permissions[0].dataActions | length) == 4
        and all(.permissions[0].dataActions[]; test("delete|purge|backup|restore|\\*"; "i") | not))
    and any(.[]; (.roleName | contains("Native Backup"))
        and .permissions[0].actions == []
        and (.permissions[0].dataActions | sort) == ["Microsoft.KeyVault/vaults/certificates/backup/action","Microsoft.KeyVault/vaults/keys/backup/action"])
    and any(.[]; (.roleName | contains("Native Restore"))
        and .permissions[0].actions == []
        and (.permissions[0].dataActions | sort) == ["Microsoft.KeyVault/vaults/certificates/restore/action","Microsoft.KeyVault/vaults/keys/restore/action"])' \
    "$fixture_directory/definitions.json"
printf '' >"$fixture_directory/calls.jsonl"
run_script --apply
assert_no_writes
printf 'PASS default RBAC grants are pair-scoped, narrow, and idempotent\n'
jq '.[0].permissions[0].actions = ["*"]' "$fixture_directory/definitions.json" >"$fixture_directory/next.json"
mv "$fixture_directory/next.json" "$fixture_directory/definitions.json"
expect_failure --apply
assert_no_writes
printf 'PASS an existing broader custom role is rejected without overwriting it\n'

reset_fixture
edit_fixture '.[0].tags = {} | .[1].tags["sync-source-keyvault-id"] = .[0].id'
run_target_script
assert_no_writes
grep -q 'Mapping: sync-source-keyvault-id' "$fixture_directory/output.txt"
run_target_script --apply
assert_json 'length == 6
    and all(.[]; (.scope == env.fixture_source or .scope == env.fixture_target))
    and all(.[]; .scope != env.fixture_other)' "$fixture_directory/assignments.json"
printf 'PASS target-side source mapping supports preview and pair-scoped grants\n'

reset_fixture
edit_fixture '.[0].tags["sync-vault-id"] = .[2].id | .[1].tags["sync-source-keyvault-id"] = .[0].id'
run_target_script --apply
assert_json 'length == 6
    and all(.[]; (.scope == env.fixture_source or .scope == env.fixture_target))
    and all(.[]; .scope != env.fixture_other)' "$fixture_directory/assignments.json"
printf 'PASS reverse-tag onboarding supports a second target when the source has another mapping\n'

reset_fixture
edit_fixture '.[1].tags["sync-source-keyvault-id"] = .[2].id'
expect_target_failure --apply
assert_no_writes
printf 'PASS a reverse mapping conflicting with a forward owner is rejected before grants\n'

reset_fixture
run_script --apply
jq 'map(if .roleName | contains("Native Backup") then .permissions[0].dataActions += ["*"] else . end)' \
    "$fixture_directory/definitions.json" >"$fixture_directory/next.json"
mv "$fixture_directory/next.json" "$fixture_directory/definitions.json"
printf '' >"$fixture_directory/calls.jsonl"
expect_failure --apply
assert_no_writes
printf 'PASS an existing broader native backup role is rejected without overwriting it\n'

reset_fixture
edit_fixture '.[1].properties.enableRbacAuthorization = false'
run_script --apply
assert_json '[.[] | select(.scope == env.fixture_source)] | length == 3
    and all(.[]; .scope == env.fixture_source)' "$fixture_directory/assignments.json"
assert_json '[.[] | select(.id == env.fixture_target)][0].properties.accessPolicies[0].permissions
    | .keys == ["get","list","restore"] and .certificates == ["get","list","restore"]
    and .secrets == ["get","list","set"]' "$fixture_directory/vaults.json"
assert_json 'length == 1 and (.[0].roleName | contains("Native Backup"))' "$fixture_directory/definitions.json"
printf 'PASS default sync grants support mixed RBAC and legacy authorization\n'

reset_fixture
edit_fixture 'map(.properties.enableRbacAuthorization = false)'
run_script --apply
assert_json 'length == 0' "$fixture_directory/assignments.json"
assert_json 'length == 0' "$fixture_directory/definitions.json"
assert_json '[.[] | select(.id == env.fixture_source)][0].properties.accessPolicies[0].permissions
    | .keys == ["backup","get","list"] and .certificates == ["backup","get","list"]
    and .secrets == ["get","list"]' "$fixture_directory/vaults.json"
assert_json '[.[] | select(.id == env.fixture_target)][0].properties.accessPolicies[0].permissions
    | .keys == ["get","list","restore"] and .certificates == ["get","list","restore"]
    and .secrets == ["get","list","set"]' "$fixture_directory/vaults.json"
printf 'PASS default sync grants merge into legacy access policies\n'

reset_fixture
edit_fixture '.[2].tags["sync-vault-id"] = .[1].id'
expect_failure --apply
assert_no_writes
printf 'PASS ambiguous targets fail before any grant\n'
reset_fixture
edit_fixture '.[0].tags["sync-vault-id"] = (.[1].id | sub("11111111-1111-1111-1111-111111111111"; "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))'
expect_failure --apply
assert_no_writes
printf 'PASS out-of-scope targets fail before any grant\n'
reset_fixture
edit_fixture '.[1].tags["sync-vault-id"] = .[2].id'
expect_failure --apply
assert_no_writes
printf 'PASS chained pairs fail before any grant\n'
reset_fixture
edit_fixture '.[2].tags["sync-vault-id"] = .[0].id'
expect_failure --apply
assert_no_writes
printf 'PASS a source already targeted by a forward mapping cannot become a chained source\n'
reset_fixture
edit_fixture '.[0].tags["sync-source-keyvault-id"] = .[2].id'
expect_failure --apply
assert_no_writes
printf 'PASS a source already targeted by a reverse mapping cannot become a chained source\n'
reset_fixture
edit_fixture '.[1].tags.KeyVaultSyncDisabled = "TRUE"'
expect_failure --apply
assert_no_writes
printf 'PASS paused-only pairs receive no new secret grants\n'

reset_fixture
edit_fixture --arg principal "$fixture_principal" --arg tenant "$fixture_tenant" '
    .[1].properties.enableRbacAuthorization = false
    | .[1].properties.accessPolicies = [{objectId: $principal, tenantId: $tenant,
        permissions: {keys: ["backup"], secrets: ["list"], certificates: ["get"], storage: ["get"]}},
        {objectId: "other-principal", tenantId: $tenant, permissions: {secrets: ["get"]}}]'
run_script --apply
assert_json '.[1].properties.accessPolicies | length == 2 and .[0].permissions.keys == ["backup", "get", "list", "restore"]
    and .[0].permissions.certificates == ["get", "list", "restore"]
    and .[0].permissions.secrets == ["get", "list", "set"] and .[0].permissions.storage == ["get"]
    and .[1].permissions == {secrets: ["get"]}' "$fixture_directory/vaults.json"
assert_json 'length == 1 and (.[0].roleName | contains("Native Backup"))' "$fixture_directory/definitions.json"
printf '' >"$fixture_directory/calls.jsonl"
run_script --apply
assert_no_writes
printf 'PASS legacy merging preserves existing permissions and other principals\n'

reset_fixture
edit_fixture --arg principal "$fixture_principal" --arg tenant "$fixture_tenant" '
    .[0].properties.enableRbacAuthorization = false
    | .[0].properties.accessPolicies = [{objectId: $principal, tenantId: $tenant, applicationId: "application", permissions: {secrets: ["get"]}}]'
expect_failure --apply
assert_no_writes
printf 'PASS application-specific legacy policies require manual review\n'
reset_fixture
jq -n --arg principal "$fixture_principal" --arg scope "$fixture_source" '
    [{principalId: $principal, scope: $scope, roleDefinitionId: "/providers/Microsoft.Authorization/roleDefinitions/21090545-7ca7-4776-b22c-e363652d74d2",
      condition: "restricted"}]' >"$fixture_directory/assignments.json"
expect_failure --apply
assert_no_writes
printf 'PASS conditional assignments require manual review\n'
reset_fixture
edit_fixture 'map(.properties.accessPolicies = null)'
run_script --apply
assert_json 'length == 6' "$fixture_directory/assignments.json"
printf 'PASS RBAC vaults can omit unused access policies\n'
reset_fixture
export mock_fail_read=true
expect_failure --apply
assert_no_writes
printf 'PASS preflight failure prevents all writes\n'
reset_fixture
export mock_drift=true
expect_failure --apply
assert_no_writes
printf 'PASS authorization drift stops the affected grant\n'
reset_fixture
export mock_fail_target=true
expect_failure --apply
assert_json 'length == 3' "$fixture_directory/assignments.json"
export mock_fail_target=false
run_script --apply
assert_json 'length == 6' "$fixture_directory/assignments.json"
printf 'PASS partial apply stops and a rerun converges without duplicates\n'

reset_fixture
expect_failure --source-vault-id not-a-resource-id --apply
assert_no_writes
printf 'PASS malformed source vault ID is rejected\n'
reset_fixture
expect_failure --source-vault-id "$fixture_source" --target-vault-id "$fixture_target" --apply
assert_no_writes
printf 'PASS both mapping-direction arguments cannot be selected together\n'
printf 'All onboarding checks passed without live Azure calls.\n'