#!/usr/bin/env bash
# Prepare protected azd configuration before provisioning or package deployment.
# Provision phase: validate subscriptions, establish CAF-style resource-group naming,
# collect and persist network configuration, establish the stable HMAC key, and optionally
# configure one deployment tag. Deploy phase: preserve the HMAC key and verify that Flex
# deployment storage is reachable.
# The HMAC value is never displayed.
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

# Render a numbered menu and resolve the chosen option into SELECTED_OPTION.
# Each option is "value|label|alias,alias"; the first option answers empty input.
# A global is used instead of stdout capture so fail() stops the hook, not a subshell.
SELECTED_OPTION=''
select_option() {
    local title="$1"
    shift
    local options=("$@")
    local total=${#options[@]}
    local index=0
    local value='' label='' aliases='' answer='' suffix=''

    printf '%s\n' "$title"
    for ((index = 0; index < total; index++)); do
        IFS='|' read -r value label aliases <<<"${options[index]}"
        suffix=''
        if [[ $index -eq 0 ]]; then
            suffix=' (default)'
        fi
        printf '  %d) %s%s\n' "$((index + 1))" "$label" "$suffix"
    done
    printf 'Enter a number [1]: '
    read -r answer || fail 'No interactive response was available.'

    answer=$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]' \
        | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    if [[ -z "$answer" ]]; then
        IFS='|' read -r value label aliases <<<"${options[0]}"
        SELECTED_OPTION="$value"
        return 0
    fi

    for ((index = 0; index < total; index++)); do
        IFS='|' read -r value label aliases <<<"${options[index]}"
        if [[ "$answer" == "$((index + 1))" || "$answer" == "$value" || ",$aliases," == *",$answer,"* ]]; then
            SELECTED_OPTION="$value"
            return 0
        fi
    done

    fail "Enter a number between 1 and $total, or press Enter for the default."
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
cannot be used for object signatures. Supply a replacement below. The invalid
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

    # A single prompt covers both paths: supplied input is validated, empty input generates a key.
    read -r -s -p 'Enter an existing Base64-encoded 32-byte HMAC key, or press Enter to generate a new one (input hidden): ' hmac_key \
        || fail 'No interactive response was available.'
    printf '\n'
    hmac_key=$(normalize_scalar "$hmac_key")
    if [[ -z "$hmac_key" ]]; then
        hmac_key=$(generate_hmac_key)
        printf 'No key was entered; generated a new HMAC key.\n'
    fi

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
    local network_profile=''
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
    network_profile=$(resolve_network_profile)
    network_profile="${network_profile:-public}"
    if [[ "$network_profile" == 'private-managed' || "$network_profile" == 'private-existing' ]]; then
        [[ "$public_network_access" == 'Disabled' ]] \
            || fail "A private networking profile requires deployment storage publicNetworkAccess=Disabled; found $public_network_access."
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

    if [[ "$network_profile" != 'public' ]]; then
        fail "KEYVAULTSYNC_NETWORK_PROFILE must be public, private-managed, or private-existing; found $network_profile."
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

# Resolve the single networking profile, migrating the retired mode/source pair when present.
resolve_network_profile() {
    local network_profile=''
    local legacy_mode=''
    local legacy_source=''

    network_profile=$(normalize_scalar "${KEYVAULTSYNC_NETWORK_PROFILE:-$(get_azd_value KEYVAULTSYNC_NETWORK_PROFILE)}")
    if [[ -n "$network_profile" ]]; then
        printf '%s' "$network_profile"
        return
    fi

    legacy_mode=$(normalize_scalar "${KEYVAULTSYNC_NETWORK_MODE:-$(get_azd_value KEYVAULTSYNC_NETWORK_MODE)}")
    legacy_source=$(normalize_scalar "${KEYVAULTSYNC_NETWORK_SOURCE:-$(get_azd_value KEYVAULTSYNC_NETWORK_SOURCE)}")
    if [[ -z "$legacy_mode" ]]; then
        return
    fi

    case "$legacy_mode|$legacy_source" in
        public | public\|managed | public\|existing)
            network_profile='public'
            ;;
        private\|managed)
            network_profile='private-managed'
            ;;
        private\|existing)
            network_profile='private-existing'
            ;;
        private\|)
            fail 'The retired private network configuration is incomplete. Set KEYVAULTSYNC_NETWORK_PROFILE to private-managed or private-existing.'
            ;;
        *)
            fail "The retired KEYVAULTSYNC_NETWORK_MODE/KEYVAULTSYNC_NETWORK_SOURCE values are invalid: $legacy_mode/$legacy_source."
            ;;
    esac

    set_azd_value KEYVAULTSYNC_NETWORK_PROFILE "$network_profile" >/dev/null
    printf '%s' "$network_profile"
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

# Preserve an existing resource-group name or configure the CAF-style name azd will create.
ensure_resource_group_name() {
    local resource_group=''
    local region_code=''
    local environment_name=''
    local resource_group_environment=''

    resource_group=$(normalize_scalar "${AZURE_RESOURCE_GROUP:-$(get_azd_value AZURE_RESOURCE_GROUP)}")
    if [[ -n "$resource_group" ]]; then
        printf 'Using configured deployment resource group %s.\n' "$resource_group"
        return
    fi

    region_code=$(normalize_scalar "${KEYVAULTSYNC_REGION_CODE:-$(get_azd_value KEYVAULTSYNC_REGION_CODE)}")
    if [[ -z "$region_code" ]]; then
        if [[ "${AZD_NON_INTERACTIVE:-false}" == 'true' ]]; then
            fail 'KEYVAULTSYNC_REGION_CODE is required when AZURE_RESOURCE_GROUP is not configured. Provide a three-letter Azure region abbreviation such as eun or swc.'
        fi
        read -r -p 'Three-letter Azure region abbreviation for the new resource group (for example eun or swc): ' region_code \
            || fail 'No interactive response was available.'
        region_code=$(normalize_scalar "$region_code")
    fi
    region_code=$(printf '%s' "$region_code" | tr '[:upper:]' '[:lower:]')
    [[ "$region_code" =~ ^[a-z]{3}$ ]] \
        || fail 'KEYVAULTSYNC_REGION_CODE must contain exactly three ASCII letters.'

    environment_name=$(normalize_scalar "${AZURE_ENV_NAME:-$(get_azd_value AZURE_ENV_NAME)}")
    [[ -n "$environment_name" ]] || fail 'AZURE_ENV_NAME is missing; select an azd environment before provisioning.'
    resource_group_environment=$(printf '%s' "$environment_name" \
        | tr '[:upper:]_' '[:lower:]-' \
        | sed -E 's/[^a-z0-9-]+/-/g; s/-+/-/g; s/^-//; s/-$//')
    [[ -n "$resource_group_environment" ]] \
        || fail 'AZURE_ENV_NAME must contain at least one letter or number for resource-group naming.'

    resource_group="rg-keyvaultsync-${region_code}-${resource_group_environment}"
    [[ ${#resource_group} -le 90 ]] || fail 'The generated resource-group name exceeds Azure'\''s 90-character limit.'

    set_azd_value KEYVAULTSYNC_REGION_CODE "$region_code" >/dev/null
    set_azd_value AZURE_RESOURCE_GROUP "$resource_group" >/dev/null
    printf 'Configured new deployment resource group %s.\n' "$resource_group"
}

# Resolve one network value, preferring an explicit process value over the saved azd value.
resolve_network_value() {
    local name="$1"
    local process_value="${!name:-}"
    local saved_value=''

    process_value=$(normalize_scalar "$process_value")
    saved_value=$(get_azd_value "$name")
    if [[ -n "$process_value" ]]; then
        if [[ "$saved_value" != "$process_value" ]]; then
            set_azd_value "$name" "$process_value" >/dev/null
        fi
        printf '%s' "$process_value"
        return
    fi
    printf '%s' "$saved_value"
}

# Prompt for and persist one missing network value.
prompt_network_value() {
    local name="$1"
    local prompt="$2"
    local default_value="${3:-}"
    local value=''

    if [[ -n "$default_value" ]]; then
        read -r -p "$prompt [$default_value]: " value || fail 'No interactive response was available.'
        value="${value:-$default_value}"
    else
        read -r -p "$prompt: " value || fail 'No interactive response was available.'
    fi
    value=$(normalize_scalar "$value")
    [[ -n "$value" ]] || fail "$name cannot be empty."
    set_azd_value "$name" "$value" >/dev/null
    printf '%s' "$value"
}

# Prompt for missing managed VNet and subnet values, with safe standalone defaults.
ensure_managed_network_values() {
    local names=(
        KEYVAULTSYNC_MANAGED_VNET_ADDRESS_PREFIX
        KEYVAULTSYNC_MANAGED_FUNCTION_SUBNET_NAME
        KEYVAULTSYNC_MANAGED_FUNCTION_SUBNET_PREFIX
        KEYVAULTSYNC_MANAGED_PRIVATE_ENDPOINT_SUBNET_NAME
        KEYVAULTSYNC_MANAGED_PRIVATE_ENDPOINT_SUBNET_PREFIX
    )
    local prompts=(
        'Managed VNet address prefix'
        'Function integration subnet name'
        'Function integration subnet address prefix'
        'Private endpoint subnet name'
        'Private endpoint subnet address prefix'
    )
    local defaults=(
        '10.42.0.0/24'
        'snet-functions'
        '10.42.0.0/27'
        'snet-private-endpoints'
        '10.42.0.32/27'
    )
    local values=()
    local missing_count=0
    local index=0

    for index in "${!names[@]}"; do
        values[index]=$(resolve_network_value "${names[index]}")
        [[ -n "${values[index]}" ]] || missing_count=$((missing_count + 1))
    done

    if [[ "$missing_count" -eq 0 || "${AZD_NON_INTERACTIVE:-false}" == 'true' ]]; then
        return
    fi

    cat <<'EOF'

Recommended managed private network:
  VNet:                         10.42.0.0/24
  Function integration subnet: 10.42.0.0/27
  Private endpoint subnet:     10.42.0.32/27

Confirm that these ranges do not overlap with connected enterprise, VPN,
peering, or ExpressRoute networks.
EOF

    if [[ "$missing_count" -eq "${#names[@]}" ]]; then
        select_option 'How should the managed private network be configured?' \
            'defaults|Use the recommended network names and ranges|d' \
            'customize|Customize the network names or ranges|c'
        if [[ "$SELECTED_OPTION" == 'defaults' ]]; then
            for index in "${!names[@]}"; do
                set_azd_value "${names[index]}" "${defaults[index]}" >/dev/null
            done
            return
        fi
    fi

    for index in "${!names[@]}"; do
        if [[ -z "${values[index]}" ]]; then
            values[index]=$(prompt_network_value "${names[index]}" "${prompts[index]}" "${defaults[index]}")
        fi
    done
}

# Persist one explicit networking profile and collect only the inputs that profile needs.
ensure_network_configuration() {
    local network_profile=''

    network_profile=$(resolve_network_profile)
    if [[ -z "$network_profile" ]]; then
        if [[ "${AZD_NON_INTERACTIVE:-false}" == 'true' ]]; then
            network_profile='public'
        else
            select_option 'Select the networking profile for KeyVaultSync-managed components:' \
                'public|Public service endpoints|p' \
                'private-managed|Private with a dedicated KeyVaultSync network|m,managed' \
                'private-existing|Private with existing enterprise networking|e,existing'
            network_profile="$SELECTED_OPTION"
        fi
        set_azd_value KEYVAULTSYNC_NETWORK_PROFILE "$network_profile" >/dev/null
    fi

    [[ "$network_profile" == 'public' || "$network_profile" == 'private-managed' || "$network_profile" == 'private-existing' ]] \
        || fail "KEYVAULTSYNC_NETWORK_PROFILE must be public, private-managed, or private-existing; found $network_profile."
    if [[ "$network_profile" == 'public' ]]; then
        printf 'Configured public service networking.\n'
        return
    fi

    if [[ "$network_profile" == 'private-managed' ]]; then
        ensure_managed_network_values
    fi
    if [[ "$network_profile" == 'private-existing' ]]; then
        local required_name=''
        local required_value=''
        local existing_function_subnet=''
        local existing_endpoint_subnet=''
        local required_existing_values=(
            KEYVAULTSYNC_EXISTING_FUNCTION_SUBNET_ID
            KEYVAULTSYNC_EXISTING_PRIVATE_ENDPOINT_SUBNET_ID
            KEYVAULTSYNC_EXISTING_BLOB_PRIVATE_DNS_ZONE_ID
            KEYVAULTSYNC_EXISTING_QUEUE_PRIVATE_DNS_ZONE_ID
            KEYVAULTSYNC_EXISTING_TABLE_PRIVATE_DNS_ZONE_ID
            KEYVAULTSYNC_EXISTING_MONITOR_PRIVATE_DNS_ZONE_ID
            KEYVAULTSYNC_EXISTING_OMS_PRIVATE_DNS_ZONE_ID
            KEYVAULTSYNC_EXISTING_ODS_PRIVATE_DNS_ZONE_ID
            KEYVAULTSYNC_EXISTING_AGENTSVC_PRIVATE_DNS_ZONE_ID
            KEYVAULTSYNC_EXISTING_AMPLS_ID
        )
        local required_existing_prompts=(
            'Existing Function integration subnet resource ID'
            'Existing private endpoint subnet resource ID'
            'Existing Blob private DNS zone resource ID'
            'Existing Queue private DNS zone resource ID'
            'Existing Table private DNS zone resource ID'
            'Existing Azure Monitor private DNS zone resource ID'
            'Existing OMS private DNS zone resource ID'
            'Existing ODS private DNS zone resource ID'
            'Existing agent-service private DNS zone resource ID'
            'Existing Azure Monitor Private Link Scope resource ID'
        )
        local index=0

        printf '\nSupply the existing enterprise network resources used by KeyVaultSync.\n'
        for index in "${!required_existing_values[@]}"; do
            required_name="${required_existing_values[index]}"
            required_value=$(resolve_network_value "$required_name")
            if [[ -z "$required_value" ]]; then
                if [[ "${AZD_NON_INTERACTIVE:-false}" == 'true' ]]; then
                    fail "$required_name is required for the private-existing networking profile."
                fi
                required_value=$(prompt_network_value "$required_name" "${required_existing_prompts[index]}")
            fi
            if [[ "$required_name" == 'KEYVAULTSYNC_EXISTING_FUNCTION_SUBNET_ID' ]]; then
                existing_function_subnet="$required_value"
            elif [[ "$required_name" == 'KEYVAULTSYNC_EXISTING_PRIVATE_ENDPOINT_SUBNET_ID' ]]; then
                existing_endpoint_subnet="$required_value"
            fi
        done
        [[ "$existing_function_subnet" != "$existing_endpoint_subnet" ]] \
            || fail 'The Function integration subnet and private endpoint subnet must be different.'
    fi

    printf 'Configured networking profile %s.\n' "$network_profile"
    printf 'Private networking covers KeyVaultSync components only (Function App, storage, monitoring).\n'
    printf 'Source and target Key Vaults stay customer-owned; confirm they are reachable from the Function subnet.\n'
}

command -v azd >/dev/null 2>&1 || fail 'azd is required.'

# Both phases must establish the same protected HMAC key before any Azure deployment step.
ensure_hmac_key

if [[ "$phase" == 'deploy' ]]; then
    # Predeploy performs no configuration prompts; it only validates the package-deployment path.
    verify_deployment_storage
    exit 0
fi

# Preprovision validates deployment naming and runtime discovery scope before Bicep receives parameters.
ensure_subscription_list
ensure_resource_group_name
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
    select_option "How should the configured tag $current_name=$current_value be handled?" \
        'keep|Keep the configured tag|k' \
        'replace|Replace the configured tag|r'
    if [[ "$SELECTED_OPTION" == 'keep' ]]; then
        exit 0
    fi
elif [[ -z "$current_name" && -z "$current_value" ]]; then
    select_option 'Would you like to add an optional deployment tag?' \
        'skip|Continue without an optional tag|n,no' \
        'add|Add an optional tag|y,yes'
    if [[ "$SELECTED_OPTION" == 'skip' ]]; then
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

select_option "Save optional deployment tag $tag_name=$tag_value?" \
    'save|Save this tag|y,yes' \
    'cancel|Do not change the optional tag|n,no'
if [[ "$SELECTED_OPTION" == 'cancel' ]]; then
    printf 'Optional deployment tag was not changed.\n'
    exit 0
fi

set_azd_value KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME "$tag_name"
set_azd_value KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE "$tag_value"
printf 'Configured the optional deployment tag for azd environment %s.\n' "${AZURE_ENV_NAME:-current}"
