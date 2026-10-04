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
identity_id="/subscriptions/$source_subscription/resourceGroups/identity/providers/Microsoft.ManagedIdentity/userAssignedIdentities/keyvaultsync"
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
            jq -n --arg principal "$principal_id" --arg tenant "$tenant_id" \
                '{principalId:$principal,tenantId:$tenant}'
            ;;
        'account show')
            jq -n --arg tenant "$tenant_id" '{tenantId:$tenant}'
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
                    jq --arg scope "$scope" --arg principal "$principal_id" \
                        '[.[] | select(.scope == $scope and .principalId == $principal)]' \
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
export -f az argument

reset_fixture() {
    export mock_drift=false
    : >"$fixture_directory/calls.jsonl"
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
preview=$(run_script)
grep -q 'Preview only' <<<"$preview"
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

printf 'grant-keyvault-access.sh offline tests passed.\n'
