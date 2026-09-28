#!/usr/bin/env bash
# Fail before package upload when the Flex deployment storage endpoint is inaccessible by design.
set -euo pipefail

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

command -v az >/dev/null 2>&1 || fail 'Azure CLI is required.'

storage_uri="${KEYVAULTSYNC_STORAGE_ACCOUNT_URI:-}"
subscription_id="${AZURE_SUBSCRIPTION_ID:-}"
resource_group="${AZURE_RESOURCE_GROUP:-}"

[[ -n "$storage_uri" ]] || fail 'KEYVAULTSYNC_STORAGE_ACCOUNT_URI is missing. Run azd provision before azd deploy.'
[[ -n "$subscription_id" ]] || fail 'AZURE_SUBSCRIPTION_ID is missing.'
[[ -n "$resource_group" ]] || fail 'AZURE_RESOURCE_GROUP is missing.'

case "$storage_uri" in
    https://*.blob.core.windows.net | https://*.blob.core.windows.net/)
        storage_host="${storage_uri#https://}"
        storage_host="${storage_host%%/*}"
        storage_account="${storage_host%%.*}"
        ;;
    *)
        fail "KEYVAULTSYNC_STORAGE_ACCOUNT_URI is not a supported Azure Blob service URI: $storage_uri"
        ;;
esac

public_network_access=$(
    az storage account show \
        --subscription "$subscription_id" \
        --resource-group "$resource_group" \
        --name "$storage_account" \
        --query publicNetworkAccess \
        --output tsv
) || fail "Could not read storage account $storage_account."

if [[ "$public_network_access" != 'Enabled' ]]; then
    cat >&2 <<EOF
Error: Flex deployment storage $storage_account has publicNetworkAccess=$public_network_access.
This deployment path requires a reachable Blob endpoint. Align the storage network configuration
with the environment's approved architecture before retrying azd deploy.
EOF
    exit 1
fi

printf 'Verified Flex deployment storage %s has public network access enabled.\n' "$storage_account"
