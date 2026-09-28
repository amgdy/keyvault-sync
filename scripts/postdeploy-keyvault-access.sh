#!/usr/bin/env bash
# Interactive azd postdeploy onboarding for existing, explicitly tagged Key Vault pairs.
set -euo pipefail

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

confirm() {
    local prompt="$1"
    local answer=''
    if ! read -r -p "$prompt [y/N] " answer; then
        printf '\nNo interactive response was available; vault access was not changed.\n'
        return 1
    fi
    [[ "$answer" == 'y' || "$answer" == 'Y' || "$answer" == 'yes' || "$answer" == 'YES' ]]
}

for dependency in az jq; do
    command -v "$dependency" >/dev/null 2>&1 || fail "$dependency is required."
done

subscription_id="${AZURE_SUBSCRIPTION_ID:-}"
identity_id="${KEYVAULTSYNC_IDENTITY_RESOURCE_ID:-}"
[[ -n "$subscription_id" ]] || fail 'AZURE_SUBSCRIPTION_ID was not provided by azd.'
[[ -n "$identity_id" ]] || fail 'KEYVAULTSYNC_IDENTITY_RESOURCE_ID was not provided by the deployment outputs.'

if [[ "${AZD_NON_INTERACTIVE:-false}" == 'true' ]]; then
    printf 'Skipping optional Key Vault access onboarding because azd is running non-interactively.\n'
    exit 0
fi

script_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
grant_script="$script_directory/grant-keyvault-access.sh"
[[ -f "$grant_script" ]] || fail "Grant script was not found: $grant_script"

cat <<'EOF'

KeyVaultSync vault access is not granted automatically.

Before continuing, declare every source/target pair you want KeyVaultSync to discover
using either of these tag styles:
  Source tag: sync-vault-id=<target vault's full ARM resource ID>
  Target tag: sync-source-keyvault-id=<source vault's full ARM resource ID>

Example value:
  /subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.KeyVault/vaults/<vault-name>

Source and target must be in this deployment's subscription. Do not put
sync-vault-id on a target or sync-source-keyvault-id on a source in a chained
mapping. If both tags declare the same pair, their IDs must agree. Set
KeyVaultSyncDisabled=true on either vault to keep that pair disabled. Verify
every mapping before granting access.
EOF

if ! confirm 'Have you finished tagging the vault pairs and want to preview access for every enabled pair?'; then
    printf 'Skipped Key Vault access onboarding. You can rerun it with: azd hooks run postdeploy\n'
    exit 0
fi

vault_list=$(az keyvault list --subscription "$subscription_id" --resource-type vault --only-show-errors --output json)
pairs=$(jq -ce '
    def tag($vault; $name):
      [($vault.tags // {} | to_entries[])
       | select((.key | ascii_downcase) == ($name | ascii_downcase))
       | (if (.value | type) == "string" then (.value | gsub("^\\s+|\\s+$"; "")) else "" end)][0] // "";
    def disabled($vault): (tag($vault; "keyvaultsyncdisabled") | ascii_downcase) == "true";
    def normalize_id($id): ($id | gsub("/+$"; "") | ascii_downcase);
    def find_vault($vaults; $id):
      [$vaults[] | select(normalize_id(.id) == normalize_id($id))][0] // null;
    if type != "array" then error("Key Vault discovery did not return an array.")
    else
      . as $vaults
      | ([
          $vaults[] as $source
          | tag($source; "sync-vault-id") as $targetId
          | select($targetId != "")
          | {mode:"source",sourceId:$source.id,targetId:$targetId,vaultId:$source.id}
        ] + [
          $vaults[] as $target
          | tag($target; "sync-source-keyvault-id") as $sourceId
          | select($sourceId != "")
          | {mode:"target",sourceId:$sourceId,targetId:$target.id,vaultId:$target.id}
        ])
      | map(. as $pair
          | find_vault($vaults; $pair.sourceId) as $source
          | find_vault($vaults; $pair.targetId) as $target
          | select((disabled($source) | not) and (disabled($target) | not))
          | $pair + {sourceName:($source.name // $pair.sourceId),targetName:($target.name // $pair.targetId)})
      | group_by((normalize_id(.sourceId)) + "=>" + (normalize_id(.targetId)))
      | map(sort_by(if .mode == "source" then 0 else 1 end)[0])
      | sort_by((normalize_id(.sourceId)), (normalize_id(.targetId)))
    end' <<<"$vault_list") || fail 'Key Vault discovery returned invalid metadata.'

pair_count=$(jq 'length' <<<"$pairs")
if [[ "$pair_count" == 0 ]]; then
    printf 'No enabled sync mappings were found in subscription %s.\n' "$subscription_id"
    exit 0
fi

printf '\nFound %s enabled mapping pair(s):\n' "$pair_count"
jq -r '.[] | "  \(.sourceName) -> \(.targetName)\n    source: \(.sourceId)\n    target: \(.targetId)\n    declared through: \(if .mode == "source" then "sync-vault-id" else "sync-source-keyvault-id" end)"' <<<"$pairs"
printf '\nPreflighting every pair; this phase performs reads only.\n'

while IFS= read -r pair; do
    mode=$(jq -r '.mode' <<<"$pair")
    vault_id=$(jq -r '.vaultId' <<<"$pair")
    bash "$grant_script" --identity-id "$identity_id" "--${mode}-vault-id" "$vault_id"
done < <(jq -c '.[]' <<<"$pairs")

printf '\nAll pair previews completed without writes.\n'
if ! confirm "Apply the displayed access grants for all $pair_count enabled pair(s)?"; then
    printf 'Skipped Key Vault access changes.\n'
    exit 0
fi

printf 'Applying reviewed grants. A failure can leave earlier pairs applied; rerun to converge safely.\n'
while IFS= read -r pair; do
    mode=$(jq -r '.mode' <<<"$pair")
    vault_id=$(jq -r '.vaultId' <<<"$pair")
    bash "$grant_script" --identity-id "$identity_id" "--${mode}-vault-id" "$vault_id" --apply
done < <(jq -c '.[]' <<<"$pairs")

printf 'Key Vault access onboarding completed for %s mapping pair(s).\n' "$pair_count"
