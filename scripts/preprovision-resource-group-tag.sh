#!/usr/bin/env bash
# Collect one optional deployment tag before azd resolves the Bicep parameters.
set -euo pipefail

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

confirm_default_yes() {
    local prompt="$1"
    local answer=''
    read -r -p "$prompt [Y/n] " answer || return 2
    [[ -z "$answer" || "$answer" == 'y' || "$answer" == 'Y' || "$answer" == 'yes' || "$answer" == 'YES' ]]
}

confirm_yes() {
    local prompt="$1"
    local answer=''
    read -r -p "$prompt [y/N] " answer || return 1
    [[ "$answer" == 'y' || "$answer" == 'Y' || "$answer" == 'yes' || "$answer" == 'YES' ]]
}

set_azd_value() {
    local name="$1"
    local value="$2"
    if [[ -n "${AZURE_ENV_NAME:-}" ]]; then
        azd env set "$name" "$value" --environment "$AZURE_ENV_NAME"
    else
        azd env set "$name" "$value"
    fi
}

get_azd_value() {
    local name="$1"
    local value=''
    if [[ -n "${AZURE_ENV_NAME:-}" ]]; then
        value=$(azd env get-value "$name" --environment "$AZURE_ENV_NAME" 2>/dev/null) || true
    else
        value=$(azd env get-value "$name" 2>/dev/null) || true
    fi
    printf '%s' "$value"
}

command -v azd >/dev/null 2>&1 || fail 'azd is required.'

current_name="${KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME:-$(get_azd_value KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME)}"
current_value="${KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE:-$(get_azd_value KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE)}"

if [[ "${AZD_NON_INTERACTIVE:-false}" == 'true' ]]; then
    if [[ -n "$current_name" && -n "$current_value" ]]; then
        printf 'Using the preconfigured optional deployment tag %s=%s.\n' "$current_name" "$current_value"
    elif [[ -n "$current_name" || -n "$current_value" ]]; then
        fail 'The optional deployment tag is incomplete. Set both KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME and KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE, or clear both.'
    else
        printf 'No optional deployment tag is configured; continuing without one.\n'
    fi
    exit 0
fi

cat <<'EOF'

KeyVaultSync can add one optional tag to the deployment resource group and
tagged resources managed by this deployment. Existing tags are preserved.
Do not use tag names or values to store secrets or personal information.
EOF

if [[ -n "$current_name" && -n "$current_value" ]]; then
    confirm_default_yes "Use the configured tag $current_name=$current_value?" || confirmation_status=$?
    if [[ "${confirmation_status:-0}" -eq 0 ]]; then
        exit 0
    elif [[ "$confirmation_status" -eq 2 ]]; then
        printf 'Using the configured deployment tag %s=%s without prompting.\n' "$current_name" "$current_value"
        exit 0
    fi
elif [[ -z "$current_name" && -z "$current_value" ]]; then
    if ! confirm_yes 'Add an optional tag to this deployment?'; then
        printf 'Continuing without an optional deployment tag.\n'
        exit 0
    fi
else
    printf 'The current optional deployment tag is incomplete and must be replaced or cleared.\n'
fi

read -r -p 'Tag name: ' tag_name \
    || fail 'No interactive response was available.'
[[ -n "$tag_name" ]] || fail 'The tag name cannot be empty.'
[[ ${#tag_name} -le 512 ]] || fail 'The tag name must be 512 characters or fewer.'
[[ "$tag_name" != *'<'* && "$tag_name" != *'>'* && "$tag_name" != *'%'* && "$tag_name" != *'&'* \
    && "$tag_name" != *'\'* && "$tag_name" != *'?'* && "$tag_name" != *'/'* ]] \
    || fail 'The tag name contains a character Azure resource-group tags do not allow.'

read -r -p 'Tag value: ' tag_value || fail 'No interactive response was available.'
[[ -n "$tag_value" ]] || fail 'The tag value cannot be empty.'
[[ ${#tag_value} -le 256 ]] || fail 'The tag value must be 256 characters or fewer.'

if ! confirm_default_yes "Use optional deployment tag $tag_name=$tag_value?"; then
    printf 'Optional deployment tag was not changed.\n'
    exit 0
fi

set_azd_value KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME "$tag_name"
set_azd_value KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE "$tag_value"
printf 'Configured the optional deployment tag for azd environment %s.\n' "${AZURE_ENV_NAME:-current}"
