#!/usr/bin/env bash
# Offline interaction checks for the azd resource-group tag preprovision hook.
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture_directory=$(mktemp -d)
trap 'rm -rf "$fixture_directory"' EXIT
mkdir -p "$fixture_directory/bin"

cat >"$fixture_directory/bin/azd" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == 'env' && "$2" == 'get-value' ]]; then
    case "$3" in
        KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME)
            [[ -n "${MOCK_AZD_TAG_NAME:-}" ]] || exit 1
            printf '%s\n' "$MOCK_AZD_TAG_NAME"
            ;;
        KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE)
            [[ -n "${MOCK_AZD_TAG_VALUE:-}" ]] || exit 1
            printf '%s\n' "$MOCK_AZD_TAG_VALUE"
            ;;
        *)
            exit 1
            ;;
    esac
    exit 0
fi
jq -cn --args '$ARGS.positional' -- "$@" >>"$fixture_directory/azd-calls.jsonl"
EOF
chmod +x "$fixture_directory/bin/azd"

export fixture_directory
export PATH="$fixture_directory/bin:$PATH"
export AZURE_ENV_NAME='test'
hook="$repository_root/scripts/preprovision-resource-group-tag.sh"

: >"$fixture_directory/azd-calls.jsonl"
export AZD_NON_INTERACTIVE=true
bash "$hook" >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
unset AZD_NON_INTERACTIVE
printf 'PASS non-interactive mode preserves configuration without prompting\n'

: >"$fixture_directory/azd-calls.jsonl"
export AZD_NON_INTERACTIVE=true
export KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME='IncompleteTag'
unset KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE || true
if bash "$hook" >"$fixture_directory/incomplete.out" 2>&1; then
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
printf 'n\n' | bash "$hook" >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
printf 'PASS declining the optional tag performs no environment writes\n'

: >"$fixture_directory/azd-calls.jsonl"
printf 'y\nComplianceClass\nReviewed\n\n' | bash "$hook" >/dev/null
jq -se '
  length == 2
  and .[0] == ["env","set","KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME","ComplianceClass","--environment","test"]
  and .[1] == ["env","set","KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE","Reviewed","--environment","test"]' \
  "$fixture_directory/azd-calls.jsonl" >/dev/null
printf 'PASS an operator-selected tag is persisted to the active azd environment\n'

: >"$fixture_directory/azd-calls.jsonl"
export KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME='ExistingTag'
export KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE='ExistingValue'
printf '\n' | bash "$hook" >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
printf 'PASS existing complete tag configuration can be retained\n'

: >"$fixture_directory/azd-calls.jsonl"
unset KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE || true
export MOCK_AZD_TAG_NAME='PersistedTag'
export MOCK_AZD_TAG_VALUE='PersistedValue'
printf '\n' | bash "$hook" >/dev/null
[[ ! -s "$fixture_directory/azd-calls.jsonl" ]]
printf 'PASS persisted azd tag configuration is loaded when hook variables are not exported\n'

printf 'All resource-group tag preprovision hook checks passed without Azure calls.\n'
