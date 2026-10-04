#!/usr/bin/env bash
# Offline checks for the shared azd provision/deploy preparation hook.
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture_directory=$(mktemp -d)
trap 'rm -rf "$fixture_directory"' EXIT
mkdir -p "$fixture_directory/bin"
test_hmac_key=$(dd if=/dev/zero bs=32 count=1 2>/dev/null | base64 | tr -d '\r\n')
generated_hmac_key=$({ printf '\001'; dd if=/dev/zero bs=31 count=1 2>/dev/null; } | base64 | tr -d '\r\n')

grep -F 'run: bash ./scripts/prepare-deployment.sh provision' "$repository_root/azure.yaml" >/dev/null
grep -F 'run: bash ./scripts/prepare-deployment.sh deploy' "$repository_root/azure.yaml" >/dev/null
grep -F 'run: bash ./scripts/postdeploy-keyvault-access.sh' "$repository_root/azure.yaml" >/dev/null
jq -e '
  .parameters.keyVaultSyncSubscriptions.value == "${KEYVAULTSYNC_SUBSCRIPTIONS=}"
  and .parameters.keyVaultSyncHmacKey.value == "${KEYVAULTSYNC_HMAC_KEY=}"' \
  "$repository_root/infra/main.parameters.json" >/dev/null
printf 'PASS azd POSIX hooks do not depend on executable file modes\n'
printf 'PASS required dynamic values are initialized by the preprovision hook\n'

cat >"$fixture_directory/bin/azd" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == 'env' && "$2" == 'get-value' ]]; then
    case "$3" in
        KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME)
            if [[ -z "${MOCK_AZD_TAG_NAME:-}" ]]; then
                printf 'ERROR: key not found in environment values\n'
                exit 1
            fi
            printf '%s\n' "$MOCK_AZD_TAG_NAME"
            ;;
        KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE)
            if [[ -z "${MOCK_AZD_TAG_VALUE:-}" ]]; then
                printf 'ERROR: key not found in environment values\n'
                exit 1
            fi
            printf '%s\n' "$MOCK_AZD_TAG_VALUE"
            ;;
        KEYVAULTSYNC_HMAC_KEY)
            if [[ -z "${MOCK_AZD_HMAC_KEY:-}" ]]; then
                printf 'ERROR: key not found in environment values\n'
                exit 1
            fi
            printf '%s\n' "$MOCK_AZD_HMAC_KEY"
            ;;
        KEYVAULTSYNC_SUBSCRIPTIONS)
            if [[ -z "${MOCK_AZD_SUBSCRIPTIONS:-}" ]]; then
                printf 'ERROR: key not found in environment values\n'
                exit 1
            fi
            printf '%s\n' "$MOCK_AZD_SUBSCRIPTIONS"
            ;;
        *)
            printf 'ERROR: key not found in environment values\n'
            exit 1
            ;;
    esac
    exit 0
fi
jq -cn --args '$ARGS.positional' -- "$@" >>"$fixture_directory/azd-calls.jsonl"
EOF
chmod +x "$fixture_directory/bin/azd"

cat >"$fixture_directory/bin/openssl" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == 'rand' && "$2" == '-base64' && "$3" == '32' ]]; then
    printf '%s\n' "$MOCK_GENERATED_HMAC_KEY"
    exit 0
fi
exit 98
EOF
chmod +x "$fixture_directory/bin/openssl"

cat >"$fixture_directory/bin/az" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == 'storage' && "$2" == 'container' && "$3" == 'exists' ]]; then
    if [[ "${MOCK_STORAGE_DATA_PLANE_REACHABLE:-true}" != 'true' ]]; then
        exit 1
    fi
    printf '{"exists":true}\n'
    exit 0
fi
jq -cn \
    --arg publicNetworkAccess "${MOCK_PUBLIC_NETWORK_ACCESS:-Enabled}" \
    --arg bypass "${MOCK_NETWORK_BYPASS:-AzureServices}" \
    '{publicNetworkAccess:$publicNetworkAccess,bypass:$bypass}'
EOF
chmod +x "$fixture_directory/bin/az"

export fixture_directory
export PATH="$fixture_directory/bin:$PATH"
export AZURE_ENV_NAME='test'
export KEYVAULTSYNC_NETWORK_MODE='public'
unset KEYVAULTSYNC_HMAC_KEY
export MOCK_AZD_HMAC_KEY="$test_hmac_key"
export MOCK_AZD_SUBSCRIPTIONS='11111111-1111-1111-1111-111111111111'
export MOCK_GENERATED_HMAC_KEY="$generated_hmac_key"
hook="$repository_root/scripts/prepare-deployment.sh"

: >"$fixture_directory/azd-calls.jsonl"
unset MOCK_AZD_SUBSCRIPTIONS
export KEYVAULTSYNC_SUBSCRIPTIONS='11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222'
export AZD_NON_INTERACTIVE=true
bash "$hook" provision >/dev/null
jq -se '
  length == 1
  and .[0] == ["env","set","KEYVAULTSYNC_SUBSCRIPTIONS","11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222","--environment","test"]' \
  "$fixture_directory/azd-calls.jsonl" >/dev/null
unset AZD_NON_INTERACTIVE KEYVAULTSYNC_SUBSCRIPTIONS
export MOCK_AZD_SUBSCRIPTIONS='11111111-1111-1111-1111-111111111111'
printf 'PASS whitespace-separated subscription IDs are validated and persisted\n'

: >"$fixture_directory/azd-calls.jsonl"
unset MOCK_AZD_SUBSCRIPTIONS
export KEYVAULTSYNC_SUBSCRIPTIONS='"11111111-1111-1111-1111-111111111111"'
export AZD_NON_INTERACTIVE=true
bash "$hook" provision >/dev/null
jq -se '
  length == 1
  and .[0] == ["env","set","KEYVAULTSYNC_SUBSCRIPTIONS","11111111-1111-1111-1111-111111111111","--environment","test"]' \
  "$fixture_directory/azd-calls.jsonl" >/dev/null
unset AZD_NON_INTERACTIVE KEYVAULTSYNC_SUBSCRIPTIONS
export MOCK_AZD_SUBSCRIPTIONS='11111111-1111-1111-1111-111111111111'
printf 'PASS quoted subscription input is normalized before validation\n'

: >"$fixture_directory/azd-calls.jsonl"
unset MOCK_AZD_SUBSCRIPTIONS
export KEYVAULTSYNC_SUBSCRIPTIONS='not-a-subscription'
export AZD_NON_INTERACTIVE=true
if bash "$hook" provision >"$fixture_directory/invalid-subscriptions.out" 2>&1; then
    printf 'Expected an invalid subscription list to fail.\n' >&2
    exit 1
fi
grep -F 'must contain Azure subscription GUIDs separated by commas, semicolons, or whitespace' \
    "$fixture_directory/invalid-subscriptions.out" >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
unset AZD_NON_INTERACTIVE KEYVAULTSYNC_SUBSCRIPTIONS
export MOCK_AZD_SUBSCRIPTIONS='11111111-1111-1111-1111-111111111111'
printf 'PASS invalid subscription IDs fail before persistence\n'

: >"$fixture_directory/azd-calls.jsonl"
unset MOCK_AZD_SUBSCRIPTIONS
export AZURE_SUBSCRIPTION_ID='33333333-3333-3333-3333-333333333333'
export AZD_NON_INTERACTIVE=true
bash "$hook" provision >/dev/null
jq -se '
  length == 1
  and .[0] == ["env","set","KEYVAULTSYNC_SUBSCRIPTIONS","33333333-3333-3333-3333-333333333333","--environment","test"]' \
  "$fixture_directory/azd-calls.jsonl" >/dev/null
unset AZD_NON_INTERACTIVE AZURE_SUBSCRIPTION_ID
export MOCK_AZD_SUBSCRIPTIONS='11111111-1111-1111-1111-111111111111'
printf 'PASS the azd deployment subscription initializes the discovery list\n'

: >"$fixture_directory/azd-calls.jsonl"
unset MOCK_AZD_SUBSCRIPTIONS
export AZD_NON_INTERACTIVE=true
if bash "$hook" provision >"$fixture_directory/missing-subscriptions.out" 2>&1; then
    printf 'Expected a missing subscription list to fail.\n' >&2
    exit 1
fi
grep -F 'KEYVAULTSYNC_SUBSCRIPTIONS is required' "$fixture_directory/missing-subscriptions.out" >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
unset AZD_NON_INTERACTIVE
export MOCK_AZD_SUBSCRIPTIONS='11111111-1111-1111-1111-111111111111'
printf 'PASS missing subscription configuration fails before persistence\n'

: >"$fixture_directory/azd-calls.jsonl"
export AZD_NON_INTERACTIVE=true
bash "$hook" provision >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
unset AZD_NON_INTERACTIVE
printf 'PASS non-interactive mode preserves configuration without prompting\n'

: >"$fixture_directory/azd-calls.jsonl"
unset KEYVAULTSYNC_NETWORK_MODE
private_vault_ids='/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/example/providers/Microsoft.KeyVault/vaults/source,/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/example/providers/Microsoft.KeyVault/vaults/target'
printf 'r\nm\n%s\nn\n' "$private_vault_ids" | bash "$hook" provision >/dev/null
jq -se '
  length == 3
  and .[0] == ["env","set","KEYVAULTSYNC_NETWORK_MODE","private","--environment","test"]
  and .[1] == ["env","set","KEYVAULTSYNC_NETWORK_SOURCE","managed","--environment","test"]
  and .[2][0:3] == ["env","set","KEYVAULTSYNC_PRIVATE_VAULT_RESOURCE_IDS"]' \
  "$fixture_directory/azd-calls.jsonl" >/dev/null
export KEYVAULTSYNC_NETWORK_MODE='public'
printf 'PASS interactive networking selection persists private managed mode and approved vault endpoints\n'

: >"$fixture_directory/azd-calls.jsonl"
export KEYVAULTSYNC_NETWORK_MODE='private'
export KEYVAULTSYNC_NETWORK_SOURCE='managed'
export AZD_NON_INTERACTIVE=true
if bash "$hook" provision >"$fixture_directory/missing-private-vaults.out" 2>&1; then
    printf 'Expected managed private networking without vault IDs to fail.\n' >&2
    exit 1
fi
grep -F 'KEYVAULTSYNC_PRIVATE_VAULT_RESOURCE_IDS is required' \
    "$fixture_directory/missing-private-vaults.out" >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
unset AZD_NON_INTERACTIVE KEYVAULTSYNC_NETWORK_SOURCE
export KEYVAULTSYNC_NETWORK_MODE='public'
printf 'PASS managed private networking requires an explicit vault endpoint list\n'

: >"$fixture_directory/azd-calls.jsonl"
export KEYVAULTSYNC_NETWORK_MODE='private'
export KEYVAULTSYNC_NETWORK_SOURCE='existing'
export AZD_NON_INTERACTIVE=true
if bash "$hook" provision >"$fixture_directory/incomplete-network.out" 2>&1; then
    printf 'Expected incomplete existing-network configuration to fail.\n' >&2
    exit 1
fi
grep -F 'KEYVAULTSYNC_EXISTING_FUNCTION_SUBNET_ID is required' \
    "$fixture_directory/incomplete-network.out" >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
unset AZD_NON_INTERACTIVE KEYVAULTSYNC_NETWORK_SOURCE
export KEYVAULTSYNC_NETWORK_MODE='public'
printf 'PASS incomplete existing-network configuration fails before Bicep\n'

: >"$fixture_directory/azd-calls.jsonl"
export AZD_NON_INTERACTIVE=true
export KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME='IncompleteTag'
unset KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE || true
if bash "$hook" provision >"$fixture_directory/incomplete.out" 2>&1; then
    printf 'Expected an incomplete non-interactive tag to fail.\n' >&2
    exit 1
fi
grep -F 'Set both KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME and KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE' \
    "$fixture_directory/incomplete.out" >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
unset AZD_NON_INTERACTIVE KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME
printf 'PASS incomplete non-interactive tag configuration fails before Bicep\n'

: >"$fixture_directory/azd-calls.jsonl"
unset KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE || true
printf 'n\n' | bash "$hook" provision >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
printf 'PASS declining the optional tag performs no environment writes\n'

: >"$fixture_directory/azd-calls.jsonl"
printf 'y\nComplianceClass\nReviewed\n\n' | bash "$hook" provision >/dev/null
jq -se '
  length == 2
  and .[0] == ["env","set","KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME","ComplianceClass","--environment","test"]
  and .[1] == ["env","set","KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE","Reviewed","--environment","test"]' \
  "$fixture_directory/azd-calls.jsonl" >/dev/null
printf 'PASS an operator-selected tag is persisted to the active azd environment\n'

: >"$fixture_directory/azd-calls.jsonl"
export KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME='ExistingTag'
export KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE='ExistingValue'
printf '\n' | bash "$hook" provision >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
printf 'PASS existing complete tag configuration can be retained\n'

: >"$fixture_directory/azd-calls.jsonl"
unset KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE || true
export MOCK_AZD_TAG_NAME='PersistedTag'
export MOCK_AZD_TAG_VALUE='PersistedValue'
printf '\n' | bash "$hook" provision >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
printf 'PASS persisted azd tag configuration is loaded when hook variables are not exported\n'

unset MOCK_AZD_HMAC_KEY MOCK_AZD_TAG_NAME MOCK_AZD_TAG_VALUE
export AZD_NON_INTERACTIVE=true
: >"$fixture_directory/azd-calls.jsonl"
if bash "$hook" provision >"$fixture_directory/missing-hmac.out" 2>&1; then
    printf 'Expected missing HMAC configuration to fail in non-interactive mode.\n' >&2
    exit 1
fi
grep -F 'KEYVAULTSYNC_HMAC_KEY is required for non-interactive deployment' \
    "$fixture_directory/missing-hmac.out" >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
unset AZD_NON_INTERACTIVE
printf 'PASS missing non-interactive HMAC configuration fails without generating a replacement\n'

export MOCK_AZD_HMAC_KEY='invalid-noninteractive-value'
export AZD_NON_INTERACTIVE=true
: >"$fixture_directory/azd-calls.jsonl"
if bash "$hook" provision >"$fixture_directory/invalid-noninteractive-hmac.out" 2>&1; then
    printf 'Expected invalid HMAC configuration to fail in non-interactive mode.\n' >&2
    exit 1
fi
grep -F 'KEYVAULTSYNC_HMAC_KEY is invalid' "$fixture_directory/invalid-noninteractive-hmac.out" >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
unset AZD_NON_INTERACTIVE MOCK_AZD_HMAC_KEY
printf 'PASS invalid non-interactive HMAC configuration fails without replacement\n'

export KEYVAULTSYNC_HMAC_KEY="$test_hmac_key"
export AZD_NON_INTERACTIVE=true
: >"$fixture_directory/azd-calls.jsonl"
bash "$hook" provision >"$fixture_directory/noninteractive-hmac.out"
jq -se --arg key "$test_hmac_key" '
  length == 1
  and .[0] == ["env","set","KEYVAULTSYNC_HMAC_KEY",$key,"--environment","test"]' \
  "$fixture_directory/azd-calls.jsonl" >/dev/null
! grep -F "$test_hmac_key" "$fixture_directory/noninteractive-hmac.out" >/dev/null
unset AZD_NON_INTERACTIVE KEYVAULTSYNC_HMAC_KEY
printf 'PASS protected non-interactive HMAC input is persisted without being printed\n'

: >"$fixture_directory/azd-calls.jsonl"
printf 'g\nn\n' | bash "$hook" provision >"$fixture_directory/generated-hmac.out"
jq -se --arg key "$generated_hmac_key" '
  length == 1
  and .[0] == ["env","set","KEYVAULTSYNC_HMAC_KEY",$key,"--environment","test"]' \
  "$fixture_directory/azd-calls.jsonl" >/dev/null
! grep -F "$generated_hmac_key" "$fixture_directory/generated-hmac.out" >/dev/null
export MOCK_AZD_HMAC_KEY="$generated_hmac_key"
printf 'PASS generated HMAC key is saved without being printed\n'

export MOCK_AZD_HMAC_KEY="\"$generated_hmac_key\""
: >"$fixture_directory/azd-calls.jsonl"
export AZD_NON_INTERACTIVE=true
bash "$hook" provision >"$fixture_directory/quoted-hmac.out"
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
! grep -F "$generated_hmac_key" "$fixture_directory/quoted-hmac.out" >/dev/null
unset AZD_NON_INTERACTIVE
export MOCK_AZD_HMAC_KEY="$generated_hmac_key"
printf 'PASS quoted saved HMAC key is normalized without rotation\n'

export MOCK_AZD_HMAC_KEY='invalid-saved-value'
: >"$fixture_directory/azd-calls.jsonl"
printf 'g\nn\n' | bash "$hook" provision >"$fixture_directory/repaired-hmac.out"
jq -se --arg key "$generated_hmac_key" '
  length == 1
  and .[0] == ["env","set","KEYVAULTSYNC_HMAC_KEY",$key,"--environment","test"]' \
  "$fixture_directory/azd-calls.jsonl" >/dev/null
grep -F 'saved KEYVAULTSYNC_HMAC_KEY is not valid' "$fixture_directory/repaired-hmac.out" >/dev/null
! grep -F 'invalid-saved-value' "$fixture_directory/repaired-hmac.out" >/dev/null
! grep -F "$generated_hmac_key" "$fixture_directory/repaired-hmac.out" >/dev/null
export MOCK_AZD_HMAC_KEY="$generated_hmac_key"
printf 'PASS invalid saved HMAC key can be replaced by a generated valid key\n'

export KEYVAULTSYNC_HMAC_KEY="$test_hmac_key"
: >"$fixture_directory/azd-calls.jsonl"
if bash "$hook" provision >"$fixture_directory/mismatched-hmac.out" 2>&1; then
    printf 'Expected conflicting process and azd HMAC keys to fail.\n' >&2
    exit 1
fi
grep -F 'contain different HMAC keys' "$fixture_directory/mismatched-hmac.out" >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
unset KEYVAULTSYNC_HMAC_KEY
printf 'PASS conflicting HMAC keys fail without changing the saved key\n'

unset MOCK_AZD_HMAC_KEY
: >"$fixture_directory/azd-calls.jsonl"
printf 's\n%s\nn\n' "$test_hmac_key" | bash "$hook" provision >"$fixture_directory/supplied-hmac.out"
jq -se --arg key "$test_hmac_key" '
  length == 1
  and .[0] == ["env","set","KEYVAULTSYNC_HMAC_KEY",$key,"--environment","test"]' \
  "$fixture_directory/azd-calls.jsonl" >/dev/null
! grep -F "$test_hmac_key" "$fixture_directory/supplied-hmac.out" >/dev/null
printf 'PASS supplied HMAC key is validated, saved, and not printed\n'

unset MOCK_AZD_HMAC_KEY
: >"$fixture_directory/azd-calls.jsonl"
if printf 's\ninvalid\n' | bash "$hook" provision >"$fixture_directory/invalid-hmac.out" 2>&1; then
    printf 'Expected invalid HMAC input to fail.\n' >&2
    exit 1
fi
grep -F 'The HMAC key must be Base64 for exactly 32 bytes' "$fixture_directory/invalid-hmac.out" >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
printf 'PASS invalid HMAC input fails before persistence\n'

export MOCK_AZD_HMAC_KEY="$test_hmac_key"
export AZURE_SUBSCRIPTION_ID='11111111-1111-1111-1111-111111111111'
export AZURE_RESOURCE_GROUP='example-resource-group'
export KEYVAULTSYNC_STORAGE_ACCOUNT_URI='https://example.blob.core.windows.net/'

MOCK_PUBLIC_NETWORK_ACCESS='Enabled' bash "$hook" deploy >"$fixture_directory/deploy-enabled.out"
grep -F 'Verified deployment storage example' "$fixture_directory/deploy-enabled.out" >/dev/null
printf 'PASS direct deploy revalidates the HMAC key and accessible deployment storage\n'

KEYVAULTSYNC_NETWORK_MODE='private' MOCK_PUBLIC_NETWORK_ACCESS='Disabled' \
    bash "$hook" deploy >"$fixture_directory/deploy-private.out"
grep -F 'Verified private deployment storage example through the Blob data plane' \
    "$fixture_directory/deploy-private.out" >/dev/null
printf 'PASS private deploy verifies Blob data-plane connectivity\n'

if KEYVAULTSYNC_NETWORK_MODE='private' MOCK_PUBLIC_NETWORK_ACCESS='Disabled' \
    MOCK_STORAGE_DATA_PLANE_REACHABLE='false' \
    bash "$hook" deploy >"$fixture_directory/deploy-private-unreachable.out" 2>&1; then
    printf 'Expected unreachable private deployment storage to fail.\n' >&2
    exit 1
fi
grep -F 'not reachable through the deployment agent' \
    "$fixture_directory/deploy-private-unreachable.out" >/dev/null
printf 'PASS unreachable private deployment storage fails before package upload\n'

if MOCK_PUBLIC_NETWORK_ACCESS='Disabled' MOCK_NETWORK_BYPASS='None' \
    bash "$hook" deploy >"$fixture_directory/deploy-disabled.out" 2>&1; then
    printf 'Expected inaccessible deployment storage to fail.\n' >&2
    exit 1
fi
grep -F 'requires a reachable Blob endpoint' "$fixture_directory/deploy-disabled.out" >/dev/null
printf 'PASS inaccessible deployment storage fails before package upload\n'

printf 'All deployment preparation checks passed without Azure changes.\n'
