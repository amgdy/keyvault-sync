#!/usr/bin/env bash
# Offline interaction and discovery checks for the azd postdeploy hook.
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture_directory=$(mktemp -d)
trap 'rm -rf "$fixture_directory"' EXIT
mkdir -p "$fixture_directory/scripts" "$fixture_directory/bin"
cp "$repository_root/scripts/postdeploy-keyvault-access.sh" "$fixture_directory/scripts/"

cat >"$fixture_directory/scripts/grant-keyvault-access.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$fixture_directory/grants.log"
if [[ "${mock_preview_failure:-false}" == true && "$*" != *"--apply"* ]]; then
    exit 70
fi
EOF
chmod +x "$fixture_directory/scripts/grant-keyvault-access.sh"

cat >"$fixture_directory/bin/az" <<'EOF'
#!/usr/bin/env bash
[[ "$1 $2" == 'keyvault list' ]] || exit 99
cat "$fixture_directory/vaults.json"
EOF
chmod +x "$fixture_directory/bin/az"

export fixture_directory
export PATH="$fixture_directory/bin:$PATH"
export AZURE_SUBSCRIPTION_ID='11111111-1111-1111-1111-111111111111'
export KEYVAULTSYNC_IDENTITY_RESOURCE_ID="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/identity/providers/Microsoft.ManagedIdentity/userAssignedIdentities/keyvaultsync"
source_one="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/source-one"
source_two="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/source-two"
source_disabled="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/source-disabled"
source_target_disabled="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/source-target-disabled"
source_three="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/source-three"
target_one="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/target-one"
target_two="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/target-two"
target_three="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/vaults/providers/Microsoft.KeyVault/vaults/target-three"
jq -n --arg sourceOne "$source_one" --arg sourceTwo "$source_two" --arg disabled "$source_disabled" \
    --arg targetDisabledSource "$source_target_disabled" \
    --arg sourceThree "$source_three" --arg targetOne "$target_one" --arg targetTwo "$target_two" \
    --arg targetThree "$target_three" '[
      {id:$sourceOne,name:"source-one",tags:{}},
      {id:$sourceTwo,name:"source-two",tags:{}},
      {id:$disabled,name:"source-disabled",tags:{"sync-vault-id":$targetOne,KeyVaultSyncDisabled:"TRUE"}},
      {id:$targetDisabledSource,name:"source-target-disabled",tags:{"sync-vault-id":($targetTwo + "-disabled")}},
      {id:$sourceThree,name:"source-three",tags:{}},
      {id:$targetOne,name:"target-one",tags:{"sync-source-keyvault-id":$sourceOne}},
      {id:$targetTwo,name:"target-two",tags:{"SYNC-SOURCE-KEYVAULT-ID":$sourceTwo}},
      {id:$targetThree,name:"target-three",tags:{"sync-source-keyvault-id":$sourceThree}},
      {id:($targetTwo + "-disabled"),name:"target-disabled",tags:{KeyVaultSyncDisabled:"true"}}
    ]' >"$fixture_directory/vaults.json"

: >"$fixture_directory/grants.log"
export AZD_NON_INTERACTIVE=true
bash "$fixture_directory/scripts/postdeploy-keyvault-access.sh" >/dev/null
[[ ! -s "$fixture_directory/grants.log" ]]
unset AZD_NON_INTERACTIVE
printf 'PASS non-interactive azd mode skips onboarding without reads or writes\n'

: >"$fixture_directory/grants.log"
printf 'n\n' | bash "$fixture_directory/scripts/postdeploy-keyvault-access.sh" >/dev/null
[[ ! -s "$fixture_directory/grants.log" ]]
printf 'PASS declining tag confirmation performs no pair previews or writes\n'

: >"$fixture_directory/grants.log"
hook_output=$(printf 'y\nn\n' | bash "$fixture_directory/scripts/postdeploy-keyvault-access.sh")
jq -eRsc --arg targetOne "$target_one" --arg targetTwo "$target_two" --arg targetThree "$target_three" '
  split("\n") | map(select(length > 0))
  | length == 3
    and all(.[]; contains("--identity-id") and (contains("--apply") | not))
    and any(.[]; contains("--target-vault-id") and contains($targetOne))
    and any(.[]; contains("--target-vault-id") and contains($targetTwo))
    and any(.[]; contains("--target-vault-id") and contains($targetThree))' "$fixture_directory/grants.log" >/dev/null
printf 'PASS every enabled target declaration is previewed\n'

grep -q '^  #  ROLE  *SUBSCRIPTION  *RESOURCE GROUP  *KEY VAULT$' <<<"$hook_output"
grep -q "^  1  source  $AZURE_SUBSCRIPTION_ID  *vaults  *source-one$" <<<"$hook_output"
grep -q "^     target  $AZURE_SUBSCRIPTION_ID  *vaults  *target-one$" <<<"$hook_output"
grep -q "^  2  source  $AZURE_SUBSCRIPTION_ID  *vaults  *source-three$" <<<"$hook_output"
printf 'PASS discovered mappings are rendered as an aligned source and target table\n'

: >"$fixture_directory/grants.log"
printf 'y\ny\n' | bash "$fixture_directory/scripts/postdeploy-keyvault-access.sh" >/dev/null
jq -eRsc '
  split("\n") | map(select(length > 0))
  | length == 6
    and all(.[0:3][]; contains("--apply") | not)
    and all(.[3:6][]; contains("--apply"))' "$fixture_directory/grants.log" >/dev/null
printf 'PASS explicit second confirmation applies every preflighted pair\n'

: >"$fixture_directory/grants.log"
export mock_preview_failure=true
if printf 'y\ny\n' | bash "$fixture_directory/scripts/postdeploy-keyvault-access.sh" >/dev/null 2>&1; then
    printf 'Expected preview failure.\n' >&2
    exit 1
fi
! grep -q -- '--apply' "$fixture_directory/grants.log"
printf 'PASS a preview failure prevents all apply calls\n'

printf 'All azd postdeploy hook checks passed without live Azure calls.\n'
