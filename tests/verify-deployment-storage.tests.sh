#!/usr/bin/env bash
# Offline checks for the azd Flex deployment-storage predeploy guard.
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture_directory=$(mktemp -d)
trap 'rm -rf "$fixture_directory"' EXIT
mkdir -p "$fixture_directory/bin"

cat >"$fixture_directory/bin/az" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${MOCK_PUBLIC_NETWORK_ACCESS:-Enabled}"
EOF
chmod +x "$fixture_directory/bin/az"

export PATH="$fixture_directory/bin:$PATH"
export AZURE_SUBSCRIPTION_ID='11111111-1111-1111-1111-111111111111'
export AZURE_RESOURCE_GROUP='example-resource-group'
export KEYVAULTSYNC_STORAGE_ACCOUNT_URI='https://example.blob.core.windows.net/'
hook="$repository_root/scripts/verify-deployment-storage.sh"

MOCK_PUBLIC_NETWORK_ACCESS='Enabled' bash "$hook" >"$fixture_directory/enabled.out"
grep -F 'Verified Flex deployment storage example' "$fixture_directory/enabled.out" >/dev/null
printf 'PASS accessible deployment storage passes the predeploy guard\n'

if MOCK_PUBLIC_NETWORK_ACCESS='Disabled' bash "$hook" >"$fixture_directory/disabled.out" 2>&1; then
    printf 'Expected disabled deployment storage to fail.\n' >&2
    exit 1
fi
grep -F 'requires a reachable Blob endpoint' "$fixture_directory/disabled.out" >/dev/null
grep -F "environment's approved architecture" "$fixture_directory/disabled.out" >/dev/null
printf 'PASS inaccessible deployment storage fails before package upload with neutral remediation\n'

printf 'All deployment-storage predeploy checks passed without Azure changes.\n'
