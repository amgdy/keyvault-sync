#!/usr/bin/env bash
# Prepare protected azd configuration before provisioning or package deployment.
# Provision phase: validate the mapping subscriptions, establish the stable HMAC key,
# and optionally configure one deployment tag. Deploy phase: preserve the HMAC key and
# verify that Flex deployment storage is reachable. The HMAC value is never displayed.
set -euo pipefail

# Validate the azd hook phase before doing any configuration work.
phase="${1:-}"
case "$phase" in
    provision | deploy) ;;
    *)
        printf 'Usage: bash %s <provision|deploy>\n' "$0" >&2
        exit 2
        ;;
esac

# Print one terminal error and stop the current azd hook.
fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

# Ask an interactive question whose empty response means yes.
confirm_default_yes() {
    local prompt="$1"
    local answer=''
    read -r -p "$prompt [Y/n] " answer || return 2
    [[ -z "$answer" || "$answer" == 'y' || "$answer" == 'Y' || "$answer" == 'yes' || "$answer" == 'YES' ]]
}

# Ask an interactive question whose empty response means no.
confirm_yes() {
    local prompt="$1"
    local answer=''
    read -r -p "$prompt [y/N] " answer || return 1
    [[ "$answer" == 'y' || "$answer" == 'Y' || "$answer" == 'yes' || "$answer" == 'YES' ]]
}

# Persist one value in the selected azd environment.
set_azd_value() {
    local name="$1"
    local value="$2"
    if [[ -n "${AZURE_ENV_NAME:-}" ]]; then
        azd env set "$name" "$value" --environment "$AZURE_ENV_NAME"
    else
        azd env set "$name" "$value"
    fi
}

# Normalize one scalar passed through an azd environment or process variable.
normalize_scalar() {
    local value="$1"
    value=$(printf '%s' "$value" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    if [[ ${#value} -ge 2 ]]; then
        if [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]] \
            || [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
            value="${value:1:${#value}-2}"
        fi
    fi
    printf '%s' "$value"
}

# Read one value from the selected azd environment without failing when it is absent.
get_azd_value() {
    local name="$1"
    local value=''
    if [[ -n "${AZURE_ENV_NAME:-}" ]]; then
        if ! value=$(azd env get-value "$name" --environment "$AZURE_ENV_NAME" 2>/dev/null); then
            value=''
        fi
    else
        if ! value=$(azd env get-value "$name" 2>/dev/null); then
            value=''
        fi
    fi
    normalize_scalar "$value"
}

# Read one value from an explicitly named azd environment.
get_azd_environment_value() {
    local name="$1"
    local environment_name="$2"
    local value=''
    if ! value=$(azd env get-value "$name" --environment "$environment_name" 2>/dev/null); then
        value=''
    fi
    normalize_scalar "$value"
}

# Validate the exact Base64 shape of a 32-byte HMAC key without printing it.
is_valid_hmac_key() {
    local value="$1"
    [[ ${#value} -eq 44 && "$value" =~ ^[A-Za-z0-9+/]{43}=$ ]]
}

# Store protected HMAC material while suppressing command output.
persist_hmac_key() {
    local environment_name="$1"
    local value="$2"
    if ! azd env set KEYVAULTSYNC_HMAC_KEY "$value" --environment "$environment_name" >/dev/null 2>&1; then
        fail 'Could not persist KEYVAULTSYNC_HMAC_KEY in the active azd environment.'
    fi
}

# Generate a cryptographically random 32-byte HMAC key.
generate_hmac_key() {
    command -v openssl >/dev/null 2>&1 || fail 'openssl is required to generate the HMAC key.'
    local value=''
    value=$(openssl rand -base64 32 2>/dev/null) || fail 'openssl could not generate the HMAC key.'
    printf '%s' "$value"
}

# Reuse, import, or interactively generate the stable per-environment HMAC key.
ensure_hmac_key() {
    local environment_name=''
    local environment_key=''
    local process_key=''
    local hmac_key=''
    local choice=''

    environment_name=$(normalize_scalar "${AZURE_ENV_NAME:-$(get_azd_value AZURE_ENV_NAME)}")
    process_key=$(normalize_scalar "${KEYVAULTSYNC_HMAC_KEY:-}")
    [[ -n "$environment_name" ]] || fail 'AZURE_ENV_NAME is missing; select an azd environment before provisioning.'
    environment_key=$(get_azd_environment_value KEYVAULTSYNC_HMAC_KEY "$environment_name")

    if [[ -n "$environment_key" && -n "$process_key" && "$environment_key" != "$process_key" ]]; then
        fail 'The process and azd environment contain different HMAC keys. Resolve the mismatch without rotating the key accidentally.'
    fi

    hmac_key="${environment_key:-$process_key}"
    if [[ -n "$hmac_key" ]]; then
        if is_valid_hmac_key "$hmac_key"; then
            if [[ -z "$environment_key" ]]; then
                persist_hmac_key "$environment_name" "$hmac_key"
            fi
            printf 'Reusing the configured HMAC key for azd environment %s.\n' "$environment_name"
            return
        fi

        if [[ "${AZD_NON_INTERACTIVE:-false}" == 'true' ]]; then
            fail 'KEYVAULTSYNC_HMAC_KEY is invalid. Provide Base64 for exactly 32 bytes through protected pipeline configuration.'
        fi

        cat <<'EOF'

The saved KEYVAULTSYNC_HMAC_KEY is not valid Base64 for exactly 32 bytes and
cannot be used for object signatures. Choose a replacement below. The invalid
value will not be displayed and will be overwritten only after the replacement
passes validation.
EOF
        hmac_key=''
    fi

    if [[ "${AZD_NON_INTERACTIVE:-false}" == 'true' ]]; then
        fail 'KEYVAULTSYNC_HMAC_KEY is required for non-interactive deployment. Provide it through protected pipeline configuration or run azd interactively to supply or generate it.'
    fi

    cat <<'EOF'

Supported object synchronization requires a stable Base64-encoded 32-byte HMAC key.
The key is stored in the active azd environment's .env file and passed to the Function
App through a secure Bicep parameter. The local .env file is plaintext; protect it and
its backups. Reuse the saved key on later deployments; generating a replacement makes
existing object baselines incompatible.
EOF

    printf 'Choose [G]enerate a new key (recommended) or [S]upply an existing Base64 key [G]: '
    read -r choice || fail 'No interactive response was available.'
    case "$choice" in
        '' | g | G)
            hmac_key=$(generate_hmac_key)
            ;;
        s | S)
            read -r -s -p 'Enter the Base64-encoded 32-byte key (input hidden): ' hmac_key \
                || fail 'No interactive response was available.'
            printf '\n'
            ;;
        *)
            fail 'Choose G to generate a key or S to supply one.'
            ;;
    esac

    is_valid_hmac_key "$hmac_key" || fail 'The HMAC key must be Base64 for exactly 32 bytes. No key was saved.'
    persist_hmac_key "$environment_name" "$hmac_key"
    printf 'Configured the HMAC key for azd environment %s; the value was not displayed.\n' "$environment_name"
}

# Verify the deployed storage network posture required by Flex package deployment.
verify_deployment_storage() {
    command -v az >/dev/null 2>&1 || fail 'Azure CLI is required.'
    command -v jq >/dev/null 2>&1 || fail 'jq is required.'

    local storage_uri="${KEYVAULTSYNC_STORAGE_ACCOUNT_URI:-}"
    local subscription_id="${AZURE_SUBSCRIPTION_ID:-}"
    local resource_group="${AZURE_RESOURCE_GROUP:-}"
    local storage_host=''
    local storage_account=''
    local storage_network=''
    local public_network_access=''
    local bypass=''
    local network_mode="${KEYVAULTSYNC_NETWORK_MODE:-$(get_azd_value KEYVAULTSYNC_NETWORK_MODE)}"
    local container_status=''

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

    storage_network=$(
        az storage account show \
            --subscription "$subscription_id" \
            --resource-group "$resource_group" \
            --name "$storage_account" \
            --query '{publicNetworkAccess:publicNetworkAccess,bypass:networkRuleSet.bypass}' \
            --output json
    ) || fail "Could not read storage account $storage_account."

    public_network_access=$(jq -r '.publicNetworkAccess // ""' <<<"$storage_network")
    bypass=$(jq -r '.bypass // ""' <<<"$storage_network")
    network_mode="${network_mode:-public}"
    if [[ "$network_mode" == 'private' ]]; then
        [[ "$public_network_access" == 'Disabled' ]] \
            || fail "Private mode requires deployment storage publicNetworkAccess=Disabled; found $public_network_access."
        container_status=$(
            az storage container exists \
                --account-name "$storage_account" \
                --name function-releases \
                --auth-mode login \
                --only-show-errors \
                --output json
        ) || fail "Private deployment storage $storage_account is not reachable through the deployment agent's DNS and network path."
        [[ "$(jq -r '.exists // false' <<<"$container_status")" == 'true' ]] \
            || fail "Private deployment storage container function-releases was not reachable in $storage_account."
        printf 'Verified private deployment storage %s through the Blob data plane.\n' "$storage_account"
        return
    fi

    if [[ "$network_mode" != 'public' ]]; then
        fail "KEYVAULTSYNC_NETWORK_MODE must be public or private; found $network_mode."
    fi
    if [[ "$public_network_access" != 'Enabled' && "$bypass" != *'AzureServices'* ]]; then
        cat >&2 <<EOF
Error: Flex deployment storage $storage_account has publicNetworkAccess=$public_network_access and bypass=$bypass.
This deployment path requires a reachable Blob endpoint. Align the storage network configuration
with the environment's approved architecture before retrying azd deploy.
EOF
        exit 1
    fi

    printf 'Verified deployment storage %s is reachable by the deployment service (publicNetworkAccess=%s, bypass=%s).\n' \
        "$storage_account" "$public_network_access" "$bypass"
}

# Validate every delimiter-separated entry as an Azure subscription GUID.
is_valid_subscription_list() {
    local value="$1"
    local subscription=''
    local found=false
    IFS=$',; \t\r\n' read -r -a subscriptions <<<"$value"
    for subscription in "${subscriptions[@]}"; do
        [[ -n "$subscription" ]] || continue
        found=true
        [[ "$subscription" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] || return 1
    done
    [[ "$found" == true ]]
}

# Resolve and persist the complete subscription discovery list.
ensure_subscription_list() {
    local configured=''
    configured=$(normalize_scalar "${KEYVAULTSYNC_SUBSCRIPTIONS:-$(get_azd_value KEYVAULTSYNC_SUBSCRIPTIONS)}")
    configured="${configured:-$(normalize_scalar "${AZURE_SUBSCRIPTION_ID:-$(get_azd_value AZURE_SUBSCRIPTION_ID)}")}"
    [[ -n "$configured" ]] || fail 'KEYVAULTSYNC_SUBSCRIPTIONS is required. Supply one or more Azure subscription IDs.'
    is_valid_subscription_list "$configured" || fail 'KEYVAULTSYNC_SUBSCRIPTIONS must contain Azure subscription GUIDs separated by commas, semicolons, or whitespace.'
    if [[ -z "$(get_azd_value KEYVAULTSYNC_SUBSCRIPTIONS)" ]]; then
        set_azd_value KEYVAULTSYNC_SUBSCRIPTIONS "$configured" >/dev/null
    fi
    printf 'Configured %s subscription list for KeyVaultSync discovery.\n' "${AZURE_ENV_NAME:-current}"
}

# Persist an explicit public/private posture and private network ownership model.
ensure_network_configuration() {
    local network_mode="${KEYVAULTSYNC_NETWORK_MODE:-$(get_azd_value KEYVAULTSYNC_NETWORK_MODE)}"
    local network_source="${KEYVAULTSYNC_NETWORK_SOURCE:-$(get_azd_value KEYVAULTSYNC_NETWORK_SOURCE)}"
    local choice=''

    if [[ -z "$network_mode" ]]; then
        if [[ "${AZD_NON_INTERACTIVE:-false}" == 'true' ]]; then
            network_mode='public'
        else
            printf 'Choose [P]ublic endpoints (default) or p[R]ivate networking [P]: '
            read -r choice || fail 'No interactive response was available.'
            case "$choice" in
                '' | p | P) network_mode='public' ;;
                r | R) network_mode='private' ;;
                *) fail 'Choose P for public endpoints or R for private networking.' ;;
            esac
        fi
        set_azd_value KEYVAULTSYNC_NETWORK_MODE "$network_mode" >/dev/null
    fi

    [[ "$network_mode" == 'public' || "$network_mode" == 'private' ]] \
        || fail "KEYVAULTSYNC_NETWORK_MODE must be public or private; found $network_mode."
    if [[ "$network_mode" == 'public' ]]; then
        printf 'Configured public service networking.\n'
        return
    fi

    if [[ -z "$network_source" ]]; then
        if [[ "${AZD_NON_INTERACTIVE:-false}" == 'true' ]]; then
            fail 'KEYVAULTSYNC_NETWORK_SOURCE is required for non-interactive private deployment.'
        fi
        printf 'Choose [M]anaged VNet (default) or [E]xisting enterprise network [M]: '
        read -r choice || fail 'No interactive response was available.'
        case "$choice" in
            '' | m | M) network_source='managed' ;;
            e | E) network_source='existing' ;;
            *) fail 'Choose M for a managed VNet or E for an existing enterprise network.' ;;
        esac
        set_azd_value KEYVAULTSYNC_NETWORK_SOURCE "$network_source" >/dev/null
    fi

    [[ "$network_source" == 'managed' || "$network_source" == 'existing' ]] \
        || fail "KEYVAULTSYNC_NETWORK_SOURCE must be managed or existing; found $network_source."
    if [[ "$network_source" == 'managed' ]]; then
        local private_vault_ids="${KEYVAULTSYNC_PRIVATE_VAULT_RESOURCE_IDS:-$(get_azd_value KEYVAULTSYNC_PRIVATE_VAULT_RESOURCE_IDS)}"
        if [[ -z "$private_vault_ids" ]]; then
            if [[ "${AZD_NON_INTERACTIVE:-false}" == 'true' ]]; then
                fail 'KEYVAULTSYNC_PRIVATE_VAULT_RESOURCE_IDS is required for private/managed networking. Supply the comma-separated source and target vault resource IDs approved for private endpoints.'
            fi
            read -r -p 'Approved source and target Key Vault resource IDs (comma-separated): ' private_vault_ids \
                || fail 'No interactive response was available.'
            [[ -n "$private_vault_ids" ]] || fail 'At least one approved Key Vault resource ID is required for a managed private network.'
            set_azd_value KEYVAULTSYNC_PRIVATE_VAULT_RESOURCE_IDS "$private_vault_ids" >/dev/null
        fi
    fi
    if [[ "$network_source" == 'existing' ]]; then
        local required_name=''
        local required_value=''
        local existing_function_subnet="${KEYVAULTSYNC_EXISTING_FUNCTION_SUBNET_ID:-$(get_azd_value KEYVAULTSYNC_EXISTING_FUNCTION_SUBNET_ID)}"
        local existing_endpoint_subnet="${KEYVAULTSYNC_EXISTING_PRIVATE_ENDPOINT_SUBNET_ID:-$(get_azd_value KEYVAULTSYNC_EXISTING_PRIVATE_ENDPOINT_SUBNET_ID)}"
        local required_existing_values=(
            KEYVAULTSYNC_EXISTING_FUNCTION_SUBNET_ID
            KEYVAULTSYNC_EXISTING_PRIVATE_ENDPOINT_SUBNET_ID
            KEYVAULTSYNC_EXISTING_BLOB_PRIVATE_DNS_ZONE_ID
            KEYVAULTSYNC_EXISTING_QUEUE_PRIVATE_DNS_ZONE_ID
            KEYVAULTSYNC_EXISTING_TABLE_PRIVATE_DNS_ZONE_ID
            KEYVAULTSYNC_EXISTING_KEYVAULT_PRIVATE_DNS_ZONE_ID
            KEYVAULTSYNC_EXISTING_MONITOR_PRIVATE_DNS_ZONE_ID
            KEYVAULTSYNC_EXISTING_OMS_PRIVATE_DNS_ZONE_ID
            KEYVAULTSYNC_EXISTING_ODS_PRIVATE_DNS_ZONE_ID
            KEYVAULTSYNC_EXISTING_AGENTSVC_PRIVATE_DNS_ZONE_ID
            KEYVAULTSYNC_EXISTING_AMPLS_ID
        )
        for required_name in "${required_existing_values[@]}"; do
            required_value="${!required_name:-$(get_azd_value "$required_name")}"
            [[ -n "$required_value" ]] || fail "$required_name is required for private/existing networking."
        done
        [[ "$existing_function_subnet" != "$existing_endpoint_subnet" ]] \
            || fail 'The Function integration subnet and private endpoint subnet must be different.'
    fi

    printf 'Configured private networking with networkSource=%s.\n' "$network_source"
}

command -v azd >/dev/null 2>&1 || fail 'azd is required.'

# Both phases must establish the same protected HMAC key before any Azure deployment step.
ensure_hmac_key

if [[ "$phase" == 'deploy' ]]; then
    # Predeploy performs no configuration prompts; it only validates the package-deployment path.
    verify_deployment_storage
    exit 0
fi

# Preprovision validates runtime discovery scope before Bicep receives parameters.
ensure_subscription_list
ensure_network_configuration

current_name="${KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME:-$(get_azd_value KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME)}"
current_value="${KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE:-$(get_azd_value KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE)}"

if [[ "${AZD_NON_INTERACTIVE:-false}" == 'true' ]]; then
    # Pipelines may use a complete preconfigured tag or omit tagging; partial input is rejected.
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

# Interactive tagging changes only azd environment values consumed by Bicep.
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
