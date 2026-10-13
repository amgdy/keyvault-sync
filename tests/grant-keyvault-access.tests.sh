#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture_directory=$(mktemp -d)
trap 'rm -rf "$fixture_directory"' EXIT
export fixture_directory

export source_subscription='11111111-1111-1111-1111-111111111111'
export target_subscription='22222222-2222-2222-2222-222222222222'
export tenant_id='33333333-3333-3333-3333-333333333333'
export principal_id='44444444-4444-4444-4444-444444444444'
export identity_id="/subscriptions/$source_subscription/resourceGroups/identity/providers/Microsoft.ManagedIdentity/userAssignedIdentities/keyvaultsync"
export source_id="/subscriptions/$source_subscription/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/source-vault"
export target_id="/subscriptions/$target_subscription/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/target-vault"

argument() {
    local name="$1"
    shift
    while [[ $# -gt 1 ]]; do
        if [[ "$1" == "$name" ]]; then printf '%s\n' "$2"; return; fi
        shift
    done
    return 1
}

az() {
    jq -cn --args '$ARGS.positional' -- "$@" >>"$fixture_directory/calls.jsonl"
    local id scope role
    case "$1 $2" in
        'identity show')
            jq -n --arg principal "$principal_id" --arg tenant "${MOCK_IDENTITY_TENANT_ID:-$tenant_id}" \
                '{principalId:$principal,tenantId:$tenant}'
            ;;
        'account show')
            if [[ "$*" == *'--output none'* && "${MOCK_AZ_LOGIN_MISSING:-false}" == true ]]; then
                printf 'Please run az login.\n' >&2
                return 1
            fi
            if [[ "$*" == *'--query user.name'* ]]; then
                printf '%s\n' "$principal_id"
                return 0
            fi
            jq -n --arg tenant "$tenant_id" --arg user "$principal_id" '{tenantId:$tenant,user:{name:$user}}'
            ;;
        'ad signed-in-user')
            printf '%s\n' "$principal_id"
            ;;
        'ad sp')
            printf '%s\n' "$principal_id"
            ;;
        'keyvault show')
            id=$(argument --ids "$@")
            if [[ "$id" == "$target_id" ]]; then
                local target_reads
                target_reads=$(jq -s --arg id "$target_id" '
                    [.[] | select(.[0:2] == ["keyvault","show"])
                    | select(.[(index("--ids") + 1)] == $id)] | length' "$fixture_directory/calls.jsonl")
                if [[ ${mock_drift:-false} == true && "$target_reads" -gt 1 ]]; then
                    jq --arg source "$source_id/changed" '.tags["sync-source-keyvault-id"]=$source' "$fixture_directory/target.json"
                else
                    cat "$fixture_directory/target.json"
                fi
            elif [[ "$id" == "$source_id" ]]; then
                cat "$fixture_directory/source.json"
            else
                return 44
            fi
            ;;
        'role assignment')
            case "$3" in
                list)
                    scope=$(argument --scope "$@")
                    if [[ "$*" == *'--include-inherited'* ]]; then
                        if [[ "${MOCK_OPERATOR_RBAC_READ_FAILURE_SCOPE:-}" == "$scope" ]]; then
                            printf 'mock role assignment read failure\n' >&2
                            return 55
                        fi
                        if [[ "${MOCK_OPERATOR_RBAC_DENIED_SCOPE:-}" == "$scope" ]]; then
                            printf '[]\n'
                        else
                            jq -n --arg scope "$scope" --arg principal "$principal_id" \
                                --arg role "${MOCK_OPERATOR_ROLE_NAME:-Owner}" \
                                '[{scope:$scope,principalId:$principal,roleDefinitionName:$role}]'
                        fi
                        return 0
                    fi
                    jq --arg scope "$scope" --arg principal "$principal_id" '
                        map(select(.scope == $scope and .principalId == $principal))' \
                        "$fixture_directory/assignments.json"
                    ;;
                create)
                    scope=$(argument --scope "$@")
                    role=$(argument --role "$@")
                    jq -n --arg scope "$scope" --arg principal "$principal_id" --arg role "$role" \
                        '{scope:$scope,principalId:$principal,roleDefinitionId:("/providers/Microsoft.Authorization/roleDefinitions/"+$role)}' \
                        >"$fixture_directory/new.json"
                    jq --slurpfile item "$fixture_directory/new.json" '. + $item' \
                        "$fixture_directory/assignments.json" >"$fixture_directory/next.json"
                    mv "$fixture_directory/next.json" "$fixture_directory/assignments.json"
                    cat "$fixture_directory/new.json"
                    ;;
                *) return 99 ;;
            esac
            ;;
        *) printf 'Unexpected mocked Azure call: %s\n' "$*" >&2; return 99 ;;
    esac
}
azd() {
    printf '%s\n' "$*" >>"$fixture_directory/azd-calls.txt"
    [[ "${MOCK_AZD_FAILURE:-false}" != true ]] || return 42
    printf '%s\n' "${MOCK_AZD_IDENTITY_VALUE:-}"
}
export -f az azd argument

reset_fixture() {
    export mock_drift=false
    : >"$fixture_directory/calls.jsonl"
    : >"$fixture_directory/azd-calls.txt"
    unset KEYVAULTSYNC_IDENTITY_RESOURCE_ID AZURE_ENV_NAME MOCK_AZD_IDENTITY_VALUE MOCK_AZD_FAILURE \
        MOCK_AZ_LOGIN_MISSING MOCK_IDENTITY_TENANT_ID MOCK_OPERATOR_RBAC_DENIED_SCOPE \
        MOCK_OPERATOR_RBAC_READ_FAILURE_SCOPE
    printf '[]\n' >"$fixture_directory/assignments.json"
    jq -n --arg id "$source_id" --arg tenant "$tenant_id" \
        '{id:$id,tags:{},properties:{tenantId:$tenant,enableRbacAuthorization:true}}' \
        >"$fixture_directory/source.json"
    jq -n --arg id "$target_id" --arg tenant "$tenant_id" --arg source "$source_id" \
        '{id:$id,tags:{"sync-source-keyvault-id":$source},properties:{tenantId:$tenant,enableRbacAuthorization:true}}' \
        >"$fixture_directory/target.json"
}

run_script() {
    bash "$repository_root/scripts/grant-keyvault-access.sh" \
        --identity-id "$identity_id" \
        --target-vault-id "$target_id" \
        "$@"
}

run_script_without_identity() {
    bash "$repository_root/scripts/grant-keyvault-access.sh" \
        --target-vault-id "$target_id" \
        "$@"
}

write_count() {
    jq -s '[.[] | select(.[0:3] == ["role","assignment","create"])] | length' "$fixture_directory/calls.jsonl"
}

# Report every created assignment as a sorted "<scope> <roleId>" line so the test
# pins the onboarding plan itself rather than only its size.
created_grants() {
    jq -rs '[.[] | select(.[0:3] == ["role","assignment","create"])
        | (.[index("--scope") + 1]) + " " + (.[index("--role") + 1])]
        | sort | .[]' "$fixture_directory/calls.jsonl"
}

key_vault_administrator='00482a5a-887f-4fb3-b363-3b7fe8e74483'
key_vault_data_access_administrator='8b54135c-b56d-4d72-a534-26097cfdc8d8'
expected_grants=$(printf '%s\n' \
    "$source_id $key_vault_administrator" \
    "$source_id $key_vault_data_access_administrator" \
    "$target_id $key_vault_administrator" \
    "$target_id $key_vault_data_access_administrator" | sort)


reset_fixture
export KEYVAULTSYNC_IDENTITY_RESOURCE_ID="'$identity_id'"
run_script_without_identity >/dev/null
[[ ! -s "$fixture_directory/azd-calls.txt" ]]

reset_fixture
export MOCK_AZD_IDENTITY_VALUE="  \"$identity_id\"  "
export AZURE_ENV_NAME='test-environment'
run_script_without_identity >/dev/null
grep -q '^env get-value KEYVAULTSYNC_IDENTITY_RESOURCE_ID --environment test-environment$' "$fixture_directory/azd-calls.txt"

reset_fixture
export MOCK_AZD_IDENTITY_VALUE='/invalid/identity'
run_script >/dev/null
[[ ! -s "$fixture_directory/azd-calls.txt" ]]

reset_fixture
export MOCK_AZD_IDENTITY_VALUE='/invalid/identity'
if run_script_without_identity >"$fixture_directory/invalid-identity.out" 2>&1; then
    echo 'Expected malformed azd identity to fail.' >&2
    exit 1
fi
grep -q -- '--identity-id must be a user-assigned managed identity ARM resource ID' "$fixture_directory/invalid-identity.out"
[[ ! -s "$fixture_directory/calls.jsonl" ]]

reset_fixture
export MOCK_AZD_IDENTITY_VALUE=''
if run_script_without_identity >"$fixture_directory/missing-identity.out" 2>&1; then
    echo 'Expected unresolved azd identity to fail.' >&2
    exit 1
fi
grep -q 'No managed identity was resolved' "$fixture_directory/missing-identity.out"
[[ ! -s "$fixture_directory/calls.jsonl" ]]

reset_fixture
export MOCK_AZ_LOGIN_MISSING=true
if run_script >"$fixture_directory/azure-login-missing.out" 2>&1; then
    echo 'Expected missing Azure CLI authentication to fail.' >&2
    exit 1
fi
grep -q 'Run az login once' "$fixture_directory/azure-login-missing.out"
[[ "$(write_count)" == 0 ]]

reset_fixture
export MOCK_IDENTITY_TENANT_ID='55555555-5555-5555-5555-555555555555'
if run_script >"$fixture_directory/identity-tenant-mismatch.out" 2>&1; then
    echo 'Expected identity tenant mismatch to fail.' >&2
    exit 1
fi
grep -q 'runtime identity must belong to the same tenant' "$fixture_directory/identity-tenant-mismatch.out"
[[ "$(write_count)" == 0 ]]

reset_fixture
preview=$(run_script)
grep -q 'Preview only' <<<"$preview"
grep -q 'Verified the current Azure principal can manage role assignments on the source vault' <<<"$preview"
grep -q 'Verified the current Azure principal can manage role assignments on the target vault' <<<"$preview"
jq -se '
  [.[] | select(.[0:3] == ["role","assignment","list"])
    | select(index("--include-inherited") != null and index("--include-groups") != null)]
  | length == 2' "$fixture_directory/calls.jsonl" >/dev/null
[[ "$(write_count)" == 0 ]]

reset_fixture
export MOCK_OPERATOR_ROLE_NAME='Role Based Access Control Administrator'
run_script >/dev/null
unset MOCK_OPERATOR_ROLE_NAME

reset_fixture
export MOCK_OPERATOR_RBAC_READ_FAILURE_SCOPE="$target_id"
if run_script >"$fixture_directory/operator-rbac-read-failure.out" 2>&1; then
    echo 'Expected operator RBAC read failure to stop preview.' >&2
    exit 1
fi
grep -q 'could not read effective RBAC assignments on the target vault' \
    "$fixture_directory/operator-rbac-read-failure.out"
grep -q 'mock role assignment read failure' "$fixture_directory/operator-rbac-read-failure.out"
[[ "$(write_count)" == 0 ]]

reset_fixture
apply_output=$(run_script --apply)
grep -q '4 role assignment(s) were created' <<<"$apply_output"
[[ "$(write_count)" == 4 ]]
[[ "$(created_grants)" == "$expected_grants" ]]
[[ "$(jq 'length' "$fixture_directory/assignments.json")" == 4 ]]

: >"$fixture_directory/calls.jsonl"
second_apply=$(run_script --apply)
grep -q '0 role assignment(s) were created' <<<"$second_apply"
[[ "$(write_count)" == 0 ]]

reset_fixture
jq '.tags={}' "$fixture_directory/target.json" >"$fixture_directory/next.json"
mv "$fixture_directory/next.json" "$fixture_directory/target.json"
if run_script >/dev/null 2>&1; then
    echo 'Expected missing target mapping to fail.' >&2
    exit 1
fi
[[ "$(write_count)" == 0 ]]

reset_fixture
jq '.properties.enableRbacAuthorization=false' "$fixture_directory/source.json" >"$fixture_directory/next.json"
mv "$fixture_directory/next.json" "$fixture_directory/source.json"
if run_script >/dev/null 2>&1; then
    echo 'Expected non-RBAC source to fail.' >&2
    exit 1
fi
[[ "$(write_count)" == 0 ]]

reset_fixture
jq '.tags.KeyVaultSyncDisabled="true"' "$fixture_directory/target.json" >"$fixture_directory/next.json"
mv "$fixture_directory/next.json" "$fixture_directory/target.json"
if run_script --apply >/dev/null 2>&1; then
    echo 'Expected disabled target to fail.' >&2
    exit 1
fi
[[ "$(write_count)" == 0 ]]

reset_fixture
export mock_drift=true
if run_script --apply >/dev/null 2>&1; then
    echo 'Expected mapping drift to fail before writes.' >&2
    exit 1
fi
[[ "$(write_count)" == 0 ]]

reset_fixture
export MOCK_OPERATOR_RBAC_DENIED_SCOPE="$target_id"
if run_script >"$fixture_directory/operator-denied.out" 2>&1; then
    echo 'Expected missing target operator RBAC authority to fail during preview.' >&2
    exit 1
fi
grep -q 'does not have Owner, User Access Administrator, or Role Based Access Control Administrator' \
    "$fixture_directory/operator-denied.out"
[[ "$(write_count)" == 0 ]]

printf 'grant-keyvault-access.sh offline tests passed.\n'
