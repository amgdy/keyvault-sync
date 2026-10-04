#!/usr/bin/env bash
# Interactive azd postdeploy onboarding for existing, explicitly tagged Key Vault pairs.
# The script performs a read-only preview for every enabled mapping before asking once
# for permission to call the per-pair grant script with --apply. Pipelines skip this hook.
set -euo pipefail

# Print one terminal error and stop before any later pair can be applied.
fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

# Ask an interactive question whose empty response means no.
confirm() {
    local prompt="$1"
    local answer=''
    if ! read -r -p "$prompt [y/N] " answer; then
        printf '\nNo interactive response was available; vault access was not changed.\n'
        return 1
    fi
    [[ "$answer" == 'y' || "$answer" == 'Y' || "$answer" == 'yes' || "$answer" == 'YES' ]]
}

# Validate azd outputs before discovering any vaults.
for dependency in az jq; do
    command -v "$dependency" >/dev/null 2>&1 || fail "$dependency is required."
done

subscriptions="${KEYVAULTSYNC_SUBSCRIPTIONS:-${AZURE_SUBSCRIPTION_ID:-}}"
identity_id="${KEYVAULTSYNC_IDENTITY_RESOURCE_ID:-}"
[[ -n "$subscriptions" ]] || fail 'KEYVAULTSYNC_SUBSCRIPTIONS was not provided by azd.'
[[ -n "$identity_id" ]] || fail 'KEYVAULTSYNC_IDENTITY_RESOURCE_ID was not provided by the deployment outputs.'

if [[ "${AZD_NON_INTERACTIVE:-false}" == 'true' ]]; then
    printf 'Skipping optional Key Vault access onboarding because azd is running non-interactively.\n'
    exit 0
fi

script_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
grant_script="$script_directory/grant-keyvault-access.sh"
[[ -f "$grant_script" ]] || fail "Grant script was not found: $grant_script"

# Explain the target-owned mapping contract before the operator approves discovery.
cat <<'EOF'

KeyVaultSync vault access is not granted automatically.

Before continuing, declare every source/target pair on the target vault:
  sync-source-keyvault-id=<source vault's full ARM resource ID>

Example value:
  /subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.KeyVault/vaults/<vault-name>

Source and target may be in different configured subscriptions, but must use
Azure RBAC and the same tenant. Set KeyVaultSyncDisabled=true on either vault
to keep that pair disabled. Verify every mapping before granting access.
EOF

if ! confirm 'Have you finished tagging the vault pairs and want to preview access for every enabled pair?'; then
    printf 'Skipped Key Vault access onboarding. You can rerun it with: azd hooks run postdeploy\n'
    exit 0
fi

# Discover value-free Key Vault ARM metadata from every configured subscription.
vault_list='[]'
while IFS= read -r subscription_id; do
    [[ -n "$subscription_id" ]] || continue
    subscription_vaults=$(az keyvault list --subscription "$subscription_id" --resource-type vault --only-show-errors --output json)
    vault_list=$(jq -cn --argjson current "$vault_list" --argjson added "$subscription_vaults" '$current + $added')
done < <(tr ',;' '\n\n' <<<"$subscriptions" | tr -s '[:space:]' '\n')

# Convert discovered target tags into a stable, deduplicated mapping list.
pairs=$(jq -ce '
    def tag($vault; $name):
      [($vault.tags // {} | to_entries[])
       | select((.key | ascii_downcase) == ($name | ascii_downcase))
       | (if (.value | type) == "string" then (.value | gsub("^\\s+|\\s+$"; "")) else "" end)][0] // "";
    def disabled($vault): (tag($vault; "keyvaultsyncdisabled") | ascii_downcase) == "true";
    if type != "array" then error("Key Vault discovery did not return an array.")
    else
      [.[] as $target
       | tag($target; "sync-source-keyvault-id") as $sourceId
       | select($sourceId != "" and (disabled($target) | not))
       | {sourceId:$sourceId,targetId:$target.id,targetName:($target.name // $target.id)}]
      | unique_by(.targetId | ascii_downcase)
      | sort_by(.targetId | ascii_downcase)
    end' <<<"$vault_list") || fail 'Key Vault discovery returned invalid metadata.'

pair_count=$(jq 'length' <<<"$pairs")
if [[ "$pair_count" == 0 ]]; then
    printf 'No enabled target-declared sync mappings were found in the configured subscriptions.\n'
    exit 0
fi

# Render the discovered mappings as an aligned table so the operator can review the
# subscription, resource group, and vault name of both sides before approving any write.
printf '\nFound %s enabled mapping pair(s):\n\n' "$pair_count"
jq -r '
    def pad($width): if $width > length then . + (" " * ($width - length)) else . end;
    def segment($pattern): (capture($pattern; "i").v // "");
    def coordinates($id; $fallbackName):
      { pair: "",
        role: "",
        subscription: ($id | segment("/subscriptions/(?<v>[^/]+)")),
        group: ($id | segment("/resourcegroups/(?<v>[^/]+)")),
        vault: (($id | segment("/providers/[^/]+/vaults/(?<v>[^/]+)")) | if . == "" then $fallbackName else . end) };
    [ to_entries[]
      | ((.key + 1) | tostring) as $index
      | .value as $pair
      | (coordinates($pair.sourceId; "") + { pair: $index, role: "source" }),
        (coordinates($pair.targetId; $pair.targetName) + { pair: "", role: "target" }) ] as $rows
    | ([{ pair: "#", role: "ROLE", subscription: "SUBSCRIPTION", group: "RESOURCE GROUP", vault: "KEY VAULT" }] + $rows) as $table
    | ($table | map(.pair | length) | max) as $pairWidth
    | ($table | map(.role | length) | max) as $roleWidth
    | ($table | map(.subscription | length) | max) as $subscriptionWidth
    | ($table | map(.group | length) | max) as $groupWidth
    | [ $table[]
        | "  " + (.pair | pad($pairWidth))
        + "  " + (.role | pad($roleWidth))
        + "  " + (.subscription | pad($subscriptionWidth))
        + "  " + (.group | pad($groupWidth))
        + "  " + .vault ] as $lines
    | ($lines | map(length) | max) as $width
    | $lines[0], ("  " + ("-" * ($width - 2))), $lines[1:][]' <<<"$pairs"
printf '\nPreflighting every pair; this phase performs reads only.\n'

# Preview every pair first; no IAM write occurs in this phase.
while IFS= read -r pair; do
    vault_id=$(jq -r '.targetId' <<<"$pair")
    bash "$grant_script" --identity-id "$identity_id" --target-vault-id "$vault_id"
done < <(jq -c '.[]' <<<"$pairs")

printf '\nAll pair previews completed without writes.\n'
if ! confirm "Apply the displayed access grants for all $pair_count enabled pair(s)?"; then
    printf 'Skipped Key Vault access changes.\n'
    exit 0
fi

# Apply the already reviewed pairs sequentially. Rerunning is safe if a later pair fails.
printf 'Applying reviewed grants. A failure can leave earlier pairs applied; rerun to converge safely.\n'
while IFS= read -r pair; do
    vault_id=$(jq -r '.targetId' <<<"$pair")
    bash "$grant_script" --identity-id "$identity_id" --target-vault-id "$vault_id" --apply
done < <(jq -c '.[]' <<<"$pairs")

printf 'Key Vault access onboarding completed for %s mapping pair(s).\n' "$pair_count"
