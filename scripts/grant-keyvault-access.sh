#!/usr/bin/env bash
# Onboard one user-assigned identity to an existing vault pair in one subscription. Requires Bash 3.2+,
# Azure CLI sign-in, jq, ARM read access, and (only with --apply) role-assignment write permission
# or vault access-policy write permission. The default pair-scoped grants cover supported secret
# synchronization and eligible one-time key/certificate seeds. No vault, authorization mode, secret,
# or existing grant is removed.
# Preview is the default. All discovery/preflight reads finish before any grant; an apply failure
# can leave earlier grants in place. Coordinate other IAM/tag edits, review, and rerun to converge.
set -euo pipefail

usage() {
    printf '%s\n' \
        "Usage: bash $0 --identity-id <uami-resource-id> (--source-vault-id <source-vault-resource-id> | --target-vault-id <target-vault-resource-id>) [--apply]" \
        'The source path resolves its target from sync-vault-id; the target path resolves its source from sync-source-keyvault-id.' \
        'Both vaults must be in the identity subscription and tenant. Either tag may declare the same pair, but conflicting mappings are rejected.' \
        'Default: pair-scoped inventory and secret permissions, source key/certificate backup, and target restore permissions.' \
        'An enabled mapping automatically opts the pair into supported synchronization; the runner enforces HMAC and one-time seed checks.' \
        '--apply: perform the displayed grants. Preview is the default; existing permissions are merged, never revoked.'
}

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

identity_id=''
subscription_id=''
source_id=''
target_id=''
apply=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --identity-id|--identity|--source-vault-id|--source-vault|--target-vault-id|--target-vault)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || fail "Missing value for $1."
            case "$1" in
                --identity-id|--identity) identity_id="$2" ;;
                --source-vault-id|--source-vault) source_id="$2" ;;
                --target-vault-id|--target-vault) target_id="$2" ;;
            esac
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
if [[ -n "$source_id" && -n "$target_id" ]] || [[ -z "$source_id" && -z "$target_id" ]]; then
    fail 'Specify exactly one of --source-vault-id or --target-vault-id.'
fi
mapping_mode=source
requested_vault_id="$source_id"
if [[ -n "$target_id" ]]; then
    mapping_mode=target
    requested_vault_id="$target_id"
fi
jq -en --arg id "$requested_vault_id" --arg pattern "$vault_pattern" '$id | test($pattern; "i")' >/dev/null \
    || fail 'The selected source or target must be a Key Vault ARM resource ID.'
identity_subscription=$(jq -rn --arg identity "$identity_id" '$identity | split("/")[2] | ascii_downcase')
requested_subscription=$(jq -rn --arg resourceId "$requested_vault_id" '$resourceId | split("/")[2] | ascii_downcase')
[[ "$requested_subscription" == "$identity_subscription" ]] \
    || fail 'The selected vault and UAMI must be in the same subscription for this onboarding script.'
subscription_id="$identity_subscription"
subscription_id=$(jq -rn --arg subscription "$subscription_id" '$subscription | ascii_downcase')
subscription_scope="/subscriptions/$subscription_id"

# Explicit scopes avoid changing the operator's default Azure CLI subscription. Object IDs bypass
# Microsoft Graph lookups; the client ID used by DefaultAzureCredential is not an RBAC principal ID.
azure() {
    az "$@" --subscription "$subscription_id" --only-show-errors --output json
}
subscription_from_id() {
    jq -rn --arg resourceId "$1" '$resourceId | split("/")[2] | ascii_downcase'
}
normalized_id() {
    jq -rn --arg resourceId "$1" '$resourceId | gsub("/+$"; "") | ascii_downcase'
}
tag_value() {
    jq -r --arg tagName "$2" '
        [((.tags // {}) | to_entries[])
         | select((.key | ascii_downcase) == ($tagName | ascii_downcase))
         | (if (.value | type) == "string" then (.value | gsub("^\\s+|\\s+$"; "")) else "" end)][0] // ""' <<<"$1"
}
identity=$(az identity show --ids "$identity_id" --only-show-errors --output json)
principal_id=$(jq -er --arg pattern "$guid_pattern" '.principalId | select(test("^" + $pattern + "$"; "i")) | ascii_downcase' <<<"$identity")
tenant_id=$(jq -er '.tenantId | ascii_downcase' <<<"$identity")
account=$(azure account show)
jq -e --arg tenant "$tenant_id" '(.tenantId | ascii_downcase) == $tenant' <<<"$account" >/dev/null \
    || fail 'The signed-in operator and UAMI must belong to the same tenant.'

# Missing authorization metadata is not treated as permission to modify a legacy vault.
load_vault() {
    local resource_id="$1"
    local resource_group vault_name
    resource_group=$(jq -rn --arg resourceId "$resource_id" '$resourceId | split("/")[4]')
    vault_name=$(jq -rn --arg resourceId "$resource_id" '$resourceId | split("/")[8]')
    azure keyvault show --name "$vault_name" --resource-group "$resource_group" \
        | jq -ce --arg id "$resource_id" --arg tenant "$tenant_id" '
        if (.id | ascii_downcase) == ($id | ascii_downcase)
            and (.properties.tenantId | ascii_downcase) == $tenant
            and ((.properties.enableRbacAuthorization | type) == "boolean" or .properties.enableRbacAuthorization == null)
            and ((.properties.accessPolicies | type) == "array"
                or (.properties.enableRbacAuthorization == true and .properties.accessPolicies == null))
        then .properties.accessPolicies //= []
        else error("Vault authorization metadata is incomplete or belongs to a different tenant.") end'
}

# Legacy compound/application-specific policies cannot safely be updated through an object-ID-only
# command. Preserve existing permission families and reject ambiguous matches rather than narrowing them.
authorization_snapshot() {
    jq -ce --arg principal "$principal_id" --arg tenant "$tenant_id" '
        {rbac: (.properties.enableRbacAuthorization // false), tags: (.tags // {}),
         policies: [.properties.accessPolicies[] | select((.objectId | ascii_downcase) == $principal)]}
        | if .rbac then .policies = []
          elif (.policies | length) > 1 or any(.policies[]; (.applicationId // "") != "" or (.tenantId | ascii_downcase) != $tenant)
          then error("Existing identity policy needs manual review (duplicate, tenant, or application-specific entry).")
          else . end'
}

jq -en --arg sourceSub "$subscription_id" --arg identitySub "$identity_subscription" '($sourceSub|ascii_downcase) == ($identitySub|ascii_downcase)' >/dev/null \
    || fail 'The source vault and UAMI must be in the same subscription for this onboarding script.'
vault_list=$(azure keyvault list --resource-type vault)
jq -e --arg scope "$subscription_scope" '
    type == "array" and all(.[]; (.id | ascii_downcase) | test("^" + $scope + "/resourcegroups/[^/]+/providers/microsoft.keyvault/vaults/[^/]+$"))
    and ([.[].id | ascii_downcase] | length == (unique | length))' <<<"$vault_list" >/dev/null \
    || fail 'Subscription vault discovery returned an invalid or out-of-scope inventory.'

pair_tag='sync-vault-id'
source_tag='sync-source-keyvault-id'
mapping_tag="$pair_tag on source"
if [[ "$mapping_mode" == source ]]; then
    source=$(load_vault "$source_id")
    target_id=$(tag_value "$source" "$pair_tag")
    [[ -n "$target_id" ]] || fail "Source vault is missing the $pair_tag target tag."
else
    target=$(load_vault "$target_id")
    source_id=$(tag_value "$target" "$source_tag")
    mapping_tag="$source_tag on target"
    [[ -n "$source_id" ]] || fail "Target vault is missing the $source_tag source tag."
fi

jq -en --arg id "$source_id" --arg pattern "$vault_pattern" '$id | test($pattern; "i")' >/dev/null \
    || fail "The source mapping is not a Key Vault ARM resource ID."
jq -en --arg id "$target_id" --arg pattern "$vault_pattern" '$id | test($pattern; "i")' >/dev/null \
    || fail "The target mapping is not a Key Vault ARM resource ID."
source_subscription=$(subscription_from_id "$source_id")
target_subscription=$(subscription_from_id "$target_id")
[[ "$source_subscription" == "$subscription_id" && "$target_subscription" == "$subscription_id" ]] \
    || fail 'Source and target vaults must be in the UAMI subscription for this onboarding script.'
[[ "$(normalized_id "$target_id")" != "$(normalized_id "$source_id")" ]] || fail 'Source maps to itself.'
if [[ "$mapping_mode" == source ]]; then
    target=$(load_vault "$target_id")
else
    source=$(load_vault "$source_id")
fi
[[ "$(normalized_id "$(jq -r '.id' <<<"$source")")" == "$(normalized_id "$source_id")" ]] \
    || fail 'The resolved source vault does not match its declared ARM resource ID.'
[[ "$(normalized_id "$(jq -r '.id' <<<"$target")")" == "$(normalized_id "$target_id")" ]] \
    || fail 'The resolved target vault does not match its declared ARM resource ID.'
jq -e --arg source "$(normalized_id "$source_id")" --arg target "$(normalized_id "$target_id")" '
    any(.[]; ((.id | gsub("/+$"; "") | ascii_downcase) == $source))
    and any(.[]; ((.id | gsub("/+$"; "") | ascii_downcase) == $target))' <<<"$vault_list" >/dev/null \
    || fail 'Both selected vaults must be present in the UAMI subscription discovery inventory.'
[[ "$(subscription_from_id "$target_id")" == "$subscription_id" ]] \
    || fail 'Source and target vaults must be in the UAMI subscription for this onboarding script.'

for side in source target; do
    if [[ "$side" == source ]]; then vault="$source"; else vault="$target"; fi
    disabled=$(jq -r '[((.tags // {}) | to_entries[])
        | select((.key | ascii_downcase) == "keyvaultsyncdisabled") | .value][0] // ""' <<<"$vault" | tr '[:upper:]' '[:lower:]')
    [[ "$disabled" != 'true' ]] || fail "Sync is disabled on the $side vault; no permissions were changed."
done

target_pair_tag=$(tag_value "$target" "$pair_tag")
[[ -z "$target_pair_tag" ]] || fail 'Target vault is also tagged as a sync source; chained mappings need manual review.'
target_source_tag=$(tag_value "$target" "$source_tag")
if [[ -n "$target_source_tag" && "$(normalized_id "$target_source_tag")" != "$(normalized_id "$source_id")" ]]; then
    fail "Target $source_tag conflicts with the selected source vault."
fi
if [[ "$mapping_mode" == target && -z "$target_source_tag" ]]; then
    fail "Target vault is missing the $source_tag source tag."
fi

source_parent_id=$(tag_value "$source" "$source_tag")
if [[ -n "$source_parent_id" ]]; then
    source_parent_exists=$(jq -e --arg parent "$(normalized_id "$source_parent_id")" '
        any(.[]; ((.id | gsub("/+$"; "") | ascii_downcase) == $parent))' <<<"$vault_list" >/dev/null && printf true || printf false)
    [[ "$source_parent_exists" != true ]] || fail 'The source vault is already a mapped target; chained mappings need manual review.'
fi
upstream_sources=$(jq -c --arg source "$(normalized_id "$source_id")" --arg pairTag "$pair_tag" '
    [.[] as $vault
     | [($vault.tags // {} | to_entries[])
        | select((.key | ascii_downcase) == ($pairTag | ascii_downcase))
        | (if (.value | type) == "string" then (.value | gsub("^\\s+|\\s+$"; "") | gsub("/+$"; "") | ascii_downcase) else "" end)][0] as $mapped
     | select($mapped == $source)
     | $vault.id]' <<<"$vault_list")
[[ "$(jq 'length' <<<"$upstream_sources")" == 0 ]] \
    || fail 'The selected source vault is already a target of another source; chained mappings need manual review.'

matching_sources=$(jq -c --arg target "$(normalized_id "$target_id")" --arg pairTag "$pair_tag" '
    [.[] as $vault
     | [($vault.tags // {} | to_entries[])
        | select((.key | ascii_downcase) == ($pairTag | ascii_downcase))
        | (if (.value | type) == "string" then (.value | gsub("^\\s+|\\s+$"; "") | gsub("/+$"; "") | ascii_downcase) else "" end)][0] as $mapped
     | select($mapped == $target)
     | $vault.id]' <<<"$vault_list")
matching_source_count=$(jq 'length' <<<"$matching_sources")
if [[ "$matching_source_count" -gt 1 ]] \
    || [[ "$matching_source_count" == 1 && "$(normalized_id "$(jq -r '.[0]' <<<"$matching_sources")")" != "$(normalized_id "$source_id")" ]] \
    || [[ "$mapping_mode" == source && "$matching_source_count" != 1 ]]; then
    fail 'Target is missing, duplicated, or mapped by another source in the discovery subscription.'
fi

reader_role='21090545-7ca7-4776-b22c-e363652d74d2'
secret_reader_role='4633458b-17de-408a-b874-0445c86b69e6'
writer_role_id='pending-writer-role'
native_backup_role_id='pending-native-backup-role'
native_restore_role_id='pending-native-restore-role'
custom_role_id_map='{}'
custom_role_creates='[]'

resolve_custom_role() {
    local output_variable="$1"
    local placeholder="$2"
    local name="$3"
    local description="$4"
    local data_actions="$5"
    local definition definitions role_id
    definition=$(jq -cn --arg name "$name" --arg description "$description" --arg scope "$subscription_scope" \
        --argjson dataActions "$data_actions" '{
            Name: $name, IsCustom: true, Description: $description,
            Actions: [], NotActions: [], NotDataActions: [], AssignableScopes: [$scope],
            DataActions: $dataActions
        }')
    definitions=$(azure role definition list --name "$name" --scope "$subscription_scope")
    if [[ $(jq 'length' <<<"$definitions") == 0 ]]; then
        printf -v "$output_variable" '%s' "$placeholder"
        custom_role_creates=$(jq -cn --argjson roles "$custom_role_creates" --arg placeholder "$placeholder" \
            --argjson definition "$definition" '$roles + [{placeholder:$placeholder,definition:$definition}]')
        custom_role_id_map=$(jq -cn --argjson map "$custom_role_id_map" --arg placeholder "$placeholder" \
            '$map + {($placeholder):$placeholder}')
        return
    fi

    jq -e --argjson expected "$definition" '
        length == 1 and .[0].roleType == "CustomRole" and (.[0].permissions | length) == 1
        and (.[0].assignableScopes | map(ascii_downcase) | sort) == ($expected.AssignableScopes | map(ascii_downcase) | sort)
        and (.[0].permissions[0].actions // []) == [] and (.[0].permissions[0].notActions // []) == []
        and (.[0].permissions[0].notDataActions // []) == []
        and ((.[0].permissions[0].dataActions // []) | sort) == ($expected.DataActions | sort)' <<<"$definitions" >/dev/null \
        || fail "The existing custom role '$name' differs from the required narrow role; it will not be overwritten."
    role_id=$(jq -er --arg pattern "$guid_pattern" '.[0].name | select(test("^" + $pattern + "$"; "i"))' <<<"$definitions")
    printf -v "$output_variable" '%s' "$role_id"
    custom_role_id_map=$(jq -cn --argjson map "$custom_role_id_map" --arg placeholder "$placeholder" --arg roleId "$role_id" \
        '$map + {($placeholder):$roleId}')
}

if [[ $(jq -r '.properties.enableRbacAuthorization' <<<"$target") == true ]]; then
    writer_name="KeyVaultSync Secret Writer ($subscription_id)"
    writer_actions='["Microsoft.KeyVault/vaults/secrets/readMetadata/action","Microsoft.KeyVault/vaults/secrets/getSecret/action","Microsoft.KeyVault/vaults/secrets/setSecret/action","Microsoft.KeyVault/vaults/secrets/update/action"]'
    resolve_custom_role writer_role_id pending-writer-role "$writer_name" \
        'KeyVaultSync target secret read/set/update only; no delete, purge, backup, restore, or authorization management.' "$writer_actions"
fi

if [[ $(jq -r '.properties.enableRbacAuthorization' <<<"$source") == true ]]; then
    backup_name="KeyVaultSync Native Backup ($subscription_id)"
    backup_actions='["Microsoft.KeyVault/vaults/keys/backup/action","Microsoft.KeyVault/vaults/certificates/backup/action"]'
    resolve_custom_role native_backup_role_id pending-native-backup-role "$backup_name" \
        'KeyVaultSync source backup for keys and certificates; assign only at the source vault.' "$backup_actions"
fi

if [[ $(jq -r '.properties.enableRbacAuthorization' <<<"$target") == true ]]; then
    restore_name="KeyVaultSync Native Restore ($subscription_id)"
    restore_actions='["Microsoft.KeyVault/vaults/keys/restore/action","Microsoft.KeyVault/vaults/certificates/restore/action"]'
    resolve_custom_role native_restore_role_id pending-native-restore-role "$restore_name" \
        'KeyVaultSync target restore for keys and certificates; assign only at the target vault.' "$restore_actions"
fi

role_assignment_snapshot() {
    local assignment_list="$1"
    local vault_id="$2"
    local desired_roles="$3"
    jq -cn --arg principal "$principal_id" --argjson roles "$desired_roles" --argjson assignments "$assignment_list" '
        [$assignments[] | . as $assignment
         | select(($assignment.principalId | ascii_downcase) == $principal
             and any($roles[]; ((.id | ascii_downcase) == ($assignment.roleDefinitionId | split("/")[-1] | ascii_downcase))))
         | {roleId:($assignment.roleDefinitionId | split("/")[-1] | ascii_downcase),
            condition:($assignment.condition // ""),scope:($assignment.scope | ascii_downcase)}]
        | sort_by(.roleId,.scope)'
}

build_vault_plan() {
    local side="$1"
    local vault="$2"
    local vault_id vault_subscription_id access snapshot roles assignments assignments_snapshot roles_to_add permissions needs_policy
    vault_id=$(jq -r '.id' <<<"$vault")
    vault_subscription_id=$(subscription_from_id "$vault_id")
    if [[ "$side" == source ]]; then access=read; else access=write; fi
    snapshot=$(authorization_snapshot <<<"$vault") \
        || fail "Authorization state on $side vault needs manual review; no permissions were changed."
    roles='[]'
    assignments='[]'
    assignments_snapshot='[]'
    roles_to_add='[]'
    permissions='null'
    needs_policy=false

    if [[ $(jq -r '.rbac' <<<"$snapshot") == true ]]; then
        roles=$(jq -cn --arg access "$access" --arg side "$side" --arg reader "$reader_role" --arg secretReader "$secret_reader_role" \
            --arg writer "$writer_role_id" --arg backup "$native_backup_role_id" --arg restore "$native_restore_role_id" '
            [{id:$reader,label:"Key Vault Reader"}] +
            (if $access == "read" then [{id:$secretReader,label:"Key Vault Secrets User"}]
             elif $access == "write" then [{id:$writer,label:"KeyVaultSync Secret Writer"}] else [] end) +
            (if $side == "source" then [{id:$backup,label:"KeyVaultSync Native Backup"}] else [] end) +
            (if $side == "target" then [{id:$restore,label:"KeyVaultSync Native Restore"}] else [] end)')
        assignments=$(azure role assignment list --assignee-object-id "$principal_id" --scope "$vault_id" \
            --include-inherited --fill-principal-name false --fill-role-definition-name false)
        assignments_snapshot=$(role_assignment_snapshot "$assignments" "$vault_id" "$roles")
        roles_to_add=$(jq -ce --argjson roles "$roles" --argjson existing "$assignments_snapshot" '
            [$roles[] as $role
             | [$existing[] | select(.roleId == ($role.id | ascii_downcase))] as $matches
             | if any($matches[]; .condition != "") then error("Conditional role assignment requires manual review.")
               elif ($matches | length) == 0 then $role else empty end]' <<< '{}') \
            || fail "A conditional UAMI role assignment exists on the $side vault; no permissions were changed."
    else
        permissions=$(jq -c --arg access "$access" --arg side "$side" '
            (.policies[0].permissions // {}) as $current
            | (if $side == "source" then ["backup"] else ["restore"] end) as $nativePermissions
            | {keys:(($current.keys // []) + ["get","list"] + $nativePermissions | unique | sort),
               certificates:(($current.certificates // []) + ["get","list"] + $nativePermissions | unique | sort),
               secrets:(($current.secrets // []) + ["list"] +
                 (if $access == "read" then ["get"] elif $access == "write" then ["get","set"] else [] end) | unique | sort),
               storage:($current.storage // [] | unique | sort)}' <<<"$snapshot")
        needs_policy=$(jq -c --argjson desired "$permissions" '
            (.policies[0].permissions // {} | {keys:(.keys // [] | unique | sort),certificates:(.certificates // [] | unique | sort),
                secrets:(.secrets // [] | unique | sort),storage:(.storage // [] | unique | sort)}) != $desired' <<<"$snapshot")
    fi

    jq -cn --arg side "$side" --argjson vault "$vault" --argjson snapshot "$snapshot" \
        --argjson roles "$roles" --argjson assignmentsSnapshot "$assignments_snapshot" --argjson rolesToAdd "$roles_to_add" \
        --argjson permissions "$permissions" --argjson needsPolicy "$needs_policy" '
        {side:$side,id:$vault.id,name:$vault.name,resourceGroup:($vault.id|split("/")[4]),subscriptionId:($vault.id|split("/")[2]|ascii_downcase),
         snapshot:$snapshot,roles:$roles,assignmentsSnapshot:$assignmentsSnapshot,rolesToAdd:$rolesToAdd,
         permissions:$permissions,needsPolicy:$needsPolicy}'
}

source_plan=$(build_vault_plan source "$source")
target_plan=$(build_vault_plan target "$target")
plan=$(jq -cn --argjson source "$source_plan" --argjson target "$target_plan" '[$source,$target]')

printf 'Identity principal: %s\nSource: %s\nTarget: %s\nMapping: %s\nMode: %s\nApply: %s\n' \
        "$principal_id" "$source_id" "$target_id" "$mapping_tag" mapping-driven-sync "$apply"
jq -r '.[] | "CREATE custom role: \(.definition.Name) (subscription assignable scope)"' <<<"$custom_role_creates"
printf 'Native key/certificate seed permissions: enabled (vault-scoped grants)\n'
jq -r '.[] as $vault | if $vault.snapshot.rbac then
        (if ($vault.rolesToAdd | length) == 0 then "UNCHANGED\t\($vault.side)\t\($vault.id)" else $vault.rolesToAdd[] | "ADD \(.label)\t\($vault.side)\t\($vault.id)" end)
    elif $vault.needsPolicy then "MERGE legacy access policy\t\($vault.side)\t\($vault.id)\t\($vault.permissions|tojson)"
    else "UNCHANGED\t\($vault.side)\t\($vault.id)" end' <<<"$plan"
if [[ "$apply" != true ]]; then
    printf 'Preview only. Review these grants, then rerun with --apply; that run rediscovers current state.\n'
    exit 0
fi

# Role-definition creation and grants are separate ARM operations, not an atomic transaction.
# Stop on the first failure, without rollback or blind retries; rerunning skips completed grants.
trap 'printf "Apply stopped; earlier grants may remain. Review the error and rerun the preview before retrying.\n" >&2' ERR
plan_rows=$(jq -c '.[]' <<<"$plan")
while IFS= read -r grant; do
    [[ -n "$grant" ]] || continue
    vault_id=$(jq -r '.id' <<<"$grant")
    current_vault=$(load_vault "$vault_id")
    current_snapshot=$(authorization_snapshot <<<"$current_vault") \
        || fail "Authorization state changed or needs manual review on $vault_id."
    jq -en --argjson current "$current_snapshot" --argjson grant "$grant" '$current == $grant.snapshot' >/dev/null \
        || fail "Vault tags or access policy changed after preflight: $vault_id. Rerun preview."
    if [[ $(jq -r '.snapshot.rbac' <<<"$grant") == true ]]; then
        current_assignments=$(azure role assignment list --assignee-object-id "$principal_id" --scope "$vault_id" \
            --include-inherited --fill-principal-name false --fill-role-definition-name false)
        current_assignment_snapshot=$(role_assignment_snapshot "$current_assignments" "$vault_id" "$(jq -c '.roles' <<<"$grant")")
        jq -en --argjson current "$current_assignment_snapshot" --argjson expected "$(jq -c '.assignmentsSnapshot' <<<"$grant")" \
            '$current == $expected' >/dev/null || fail "UAMI role assignments changed after preflight on $vault_id. Rerun preview."
    fi
done <<<"$plan_rows"

while IFS= read -r role_plan; do
    [[ -n "$role_plan" ]] || continue
    placeholder=$(jq -r '.placeholder' <<<"$role_plan")
    definition=$(jq -c '.definition' <<<"$role_plan")
    role_name=$(jq -r '.definition.Name' <<<"$role_plan")
    definitions=$(azure role definition list --name "$role_name" --scope "$subscription_scope")
    [[ $(jq 'length' <<<"$definitions") == 0 ]] || fail "The custom role '$role_name' appeared after preflight; rerun the preview before applying."
    created_role=$(azure role definition create --role-definition "$definition")
    created_role_id=$(jq -er --arg pattern "$guid_pattern" '.name | select(test("^" + $pattern + "$"; "i"))' <<<"$created_role")
    custom_role_id_map=$(jq -cn --argjson map "$custom_role_id_map" --arg placeholder "$placeholder" --arg roleId "$created_role_id" \
        '$map + {($placeholder):$roleId}')
done < <(jq -c '.[]' <<<"$custom_role_creates")

while IFS= read -r grant; do
    [[ -n "$grant" ]] || continue
    vault_id=$(jq -r '.id' <<<"$grant")
    if [[ $(jq -r '.snapshot.rbac' <<<"$grant") == true ]]; then
        role_ids=$(jq -r --argjson resolved "$custom_role_id_map" '.rolesToAdd[].id as $roleId | $resolved[$roleId] // $roleId' <<<"$grant")
        while IFS= read -r role_id; do
            [[ -n "$role_id" ]] || continue
            azure role assignment create --assignee-object-id "$principal_id" --assignee-principal-type ServicePrincipal \
                --role "$role_id" --scope "$vault_id" >/dev/null
        done <<<"$role_ids"
    elif [[ $(jq -r '.needsPolicy' <<<"$grant") == true ]]; then
        # set-policy updates this object-ID entry; unioned permissions retain previous grants in
        # every family. This has no ETag fence, so operators must serialize concurrent IAM edits.
        key_permissions=()
        certificate_permissions=()
        secret_permissions=()
        storage_permissions=()
        while IFS= read -r permission; do [[ -n "$permission" ]] && key_permissions+=("$permission"); done < <(jq -r '.permissions.keys[]' <<<"$grant")
        while IFS= read -r permission; do [[ -n "$permission" ]] && certificate_permissions+=("$permission"); done < <(jq -r '.permissions.certificates[]' <<<"$grant")
        while IFS= read -r permission; do [[ -n "$permission" ]] && secret_permissions+=("$permission"); done < <(jq -r '.permissions.secrets[]' <<<"$grant")
        policy_arguments=(keyvault set-policy --name "$(jq -r '.name' <<<"$grant")" --resource-group "$(jq -r '.resourceGroup' <<<"$grant")"
            --object-id "$principal_id" --key-permissions "${key_permissions[@]}"
            --certificate-permissions "${certificate_permissions[@]}" --secret-permissions "${secret_permissions[@]}")
        if [[ $(jq '.permissions.storage | length' <<<"$grant") -gt 0 ]]; then
            while IFS= read -r permission; do [[ -n "$permission" ]] && storage_permissions+=("$permission"); done < <(jq -r '.permissions.storage[]' <<<"$grant")
            policy_arguments+=(--storage-permissions "${storage_permissions[@]}")
        fi
        azure "${policy_arguments[@]}" >/dev/null
    fi
done <<<"$plan_rows"
printf 'Grant operations completed. Allow RBAC propagation, then run a read-only scan. Sync and mutation settings are unchanged.\n'