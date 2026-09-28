#!/usr/bin/env bash

set -euo pipefail

usage() {
    echo "Usage: $0 [--replace-target] <source-vault> <target-vault> [backup-directory] [subscription-id]" >&2
}

replace_target=false
if [[ "${1:-}" == "--replace-target" ]]; then
    replace_target=true
    shift
fi

if [[ $# -lt 2 || $# -gt 4 ]]; then
    usage
    exit 2
fi

source_vault="$1"
target_vault="$2"
backup_directory="${3:-./keyvault-backup-$(date -u +%Y%m%dT%H%M%SZ)}"
subscription_id="${4:-}"

if ! command -v az >/dev/null 2>&1; then
    echo "Azure CLI (az) is required." >&2
    exit 1
fi

if [[ "$source_vault" == "$target_vault" ]]; then
    echo "Source and target vaults must be different." >&2
    exit 1
fi

if [[ -n "$subscription_id" ]]; then
    az account set --subscription "$subscription_id"
fi

source_resource_id="$(az keyvault show --name "$source_vault" --query id -o tsv)"
target_resource_id="$(az keyvault show --name "$target_vault" --query id -o tsv)"
source_subscription_id="$(cut -d/ -f3 <<<"$source_resource_id")"
target_subscription_id="$(cut -d/ -f3 <<<"$target_resource_id")"

if [[ "$source_subscription_id" != "$target_subscription_id" ]]; then
    echo "Backup and restore require both vaults to be in the same subscription." >&2
    exit 1
fi

if [[ "$replace_target" == true ]]; then
    echo "WARNING: --replace-target is a destructive lab operation, not a production recovery workflow." >&2
    purge_protection="$(az keyvault show \
        --name "$target_vault" \
        --query 'properties.enablePurgeProtection' \
        -o tsv)"

    if [[ "$purge_protection" == "true" ]]; then
        echo "Target replacement requires purge protection to be disabled." >&2
        exit 1
    fi
else
    for object_type in secret key certificate; do
        target_count="$(az keyvault "$object_type" list \
            --vault-name "$target_vault" \
            --query 'length(@)' \
            -o tsv)"

        if [[ "$target_count" != "0" ]]; then
            echo "Target vault is not empty: found $target_count ${object_type}(s)." >&2
            echo "Use --replace-target only for an intentional destructive refresh." >&2
            exit 1
        fi
    done
fi

if [[ -e "$backup_directory" ]]; then
    echo "Backup path already exists: $backup_directory" >&2
    exit 1
fi
mkdir -p "$backup_directory"
certificate_names_file="$backup_directory/certificate-names.txt"

az keyvault certificate list \
    --vault-name "$source_vault" \
    --query '[].name' \
    -o tsv >"$certificate_names_file"

is_certificate_backing_object() {
    local object_name="$1"
    grep -Fxq -- "$object_name" "$certificate_names_file"
}

echo "Backing up certificates from $source_vault..."
while IFS= read -r certificate_name; do
    [[ -n "$certificate_name" ]] || continue
    az keyvault certificate backup \
        --vault-name "$source_vault" \
        --name "$certificate_name" \
        --file "$backup_directory/certificate-$certificate_name.bak" \
        --output none
done <"$certificate_names_file"

echo "Backing up independent secrets from $source_vault..."
while IFS= read -r secret_name; do
    [[ -n "$secret_name" ]] || continue
    if is_certificate_backing_object "$secret_name"; then
        continue
    fi

    az keyvault secret backup \
        --vault-name "$source_vault" \
        --name "$secret_name" \
        --file "$backup_directory/secret-$secret_name.bak" \
        --output none
done < <(az keyvault secret list --vault-name "$source_vault" --query '[].name' -o tsv)

echo "Backing up independent keys from $source_vault..."
while IFS= read -r key_name; do
    [[ -n "$key_name" ]] || continue
    if is_certificate_backing_object "$key_name"; then
        continue
    fi

    az keyvault key backup \
        --vault-name "$source_vault" \
        --name "$key_name" \
        --file "$backup_directory/key-$key_name.bak" \
        --output none
done < <(az keyvault key list --vault-name "$source_vault" --query '[].name' -o tsv)

if [[ "$replace_target" == true ]]; then
    echo "Deleting and purging all data objects from $target_vault..."
    for object_type in certificate secret key; do
        while IFS= read -r object_name; do
            [[ -n "$object_name" ]] || continue
            az keyvault "$object_type" delete \
                --vault-name "$target_vault" \
                --name "$object_name" \
                --output none
        done < <(az keyvault "$object_type" list \
            --vault-name "$target_vault" \
            --query '[].name' \
            -o tsv)
    done

    for object_type in certificate secret key; do
        while IFS= read -r object_name; do
            [[ -n "$object_name" ]] || continue
            az keyvault "$object_type" purge \
                --vault-name "$target_vault" \
                --name "$object_name" \
                --output none
        done < <(az keyvault "$object_type" list-deleted \
            --vault-name "$target_vault" \
            --query '[].name' \
            -o tsv)
    done
fi

echo "Restoring certificates to $target_vault..."
for backup_file in "$backup_directory"/certificate-*.bak; do
    [[ -e "$backup_file" ]] || continue
    az keyvault certificate restore \
        --vault-name "$target_vault" \
        --file "$backup_file" \
        --output none
done

echo "Restoring independent secrets to $target_vault..."
for backup_file in "$backup_directory"/secret-*.bak; do
    [[ -e "$backup_file" ]] || continue
    az keyvault secret restore \
        --vault-name "$target_vault" \
        --file "$backup_file" \
        --output none
done

echo "Restoring independent keys to $target_vault..."
for backup_file in "$backup_directory"/key-*.bak; do
    [[ -e "$backup_file" ]] || continue
    az keyvault key restore \
        --vault-name "$target_vault" \
        --file "$backup_file" \
        --output none
done

object_inventory() {
    local vault_name="$1"
    local object_type="$2"

    while IFS= read -r object_name; do
        [[ -n "$object_name" ]] || continue
        version_count="$(az keyvault "$object_type" list-versions \
            --vault-name "$vault_name" \
            --name "$object_name" \
            --query 'length(@)' \
            -o tsv)"
        printf '%s\t%s\n' "$object_name" "$version_count"
    done < <(az keyvault "$object_type" list \
        --vault-name "$vault_name" \
        --query '[].name' \
        -o tsv)
}

for object_type in secret key certificate; do
    source_inventory="$(object_inventory "$source_vault" "$object_type" | sort)"
    target_inventory="$(object_inventory "$target_vault" "$object_type" | sort)"

    if [[ "$source_inventory" != "$target_inventory" ]]; then
        echo "Verification failed for ${object_type} names or version counts." >&2
        diff \
            <(printf '%s\n' "$source_inventory") \
            <(printf '%s\n' "$target_inventory") >&2 || true
        exit 1
    fi

    object_count="$(printf '%s\n' "$source_inventory" | sed '/^$/d' | wc -l | tr -d ' ')"
    echo "Verified ${object_type}s: $object_count object(s), names and version counts match"
done

echo "Backup and restore completed. Encrypted backups are in $backup_directory."