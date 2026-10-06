#!/usr/bin/env bash
# Verify azd environment values reach Bicep parameters and Function settings, and optional tags reach tagged resources.
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
compiled_template=$(mktemp)
trap 'rm -f "$compiled_template"' EXIT

jq -e '
  .parameters.keyVaultSyncHmacKey.value == "${KEYVAULTSYNC_HMAC_KEY=}"
  and .parameters.optionalResourceGroupTagName.value == "${KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME=}"
  and .parameters.optionalResourceGroupTagValue.value == "${KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE=}"
  and .parameters.networkProfile.value == "${KEYVAULTSYNC_NETWORK_PROFILE=public}"
' "$repository_root/infra/main.parameters.json" >/dev/null

az bicep build \
    --file "$repository_root/infra/main.bicep" \
    --outfile "$compiled_template" >/dev/null

jq -e --arg hmacSettingExpression "'KEYVAULTSYNC_HMAC_KEY', parameters('keyVaultSyncHmacKey')" '
  .parameters.keyVaultSyncHmacKey.type == "securestring"
  and ([.resources[]
    | select(.type == "Microsoft.Web/sites/config")
    | .properties
    | select(type == "string" and contains($hmacSettingExpression))
  ] | length) == 1
' "$compiled_template" >/dev/null

jq -e \
    --arg tagNameExpression "parameters('optionalResourceGroupTagName')" \
    --arg tagValueExpression "parameters('optionalResourceGroupTagValue')" '
  .variables.optionalDeploymentTags
    | contains($tagNameExpression)
      and contains($tagValueExpression)
' "$compiled_template" >/dev/null

jq -e \
    --arg condition "[variables('applyOptionalResourceGroupTag')]" \
    --arg tagsExpression "[union(resourceGroup().tags, variables('optionalDeploymentTags'))]" '
  ([.resources[]
    | select(.type == "Microsoft.Resources/tags")
    | select(.condition == $condition)
    | select(.properties.tags == $tagsExpression)
  ] | length) == 1
' "$compiled_template" >/dev/null

jq -e \
    --arg resourceTags "[variables('resourceTags')]" \
    --arg functionTags "[union(variables('resourceTags'), createObject('azd-service-name', 'keyvaultsync'))]" '
  [.resources[]
    | select(.type == "Microsoft.Resources/deployments")
    | select(.properties.parameters.tags? != null)
    | .properties.parameters.tags.value
  ] as $tagValues
  | ($tagValues | length) == 7
    and ($tagValues | map(. == $resourceTags or . == $functionTags) | all)
' "$compiled_template" >/dev/null

jq -e '
  .parameters.networkProfile.defaultValue == "public"
  and .parameters.networkProfile.allowedValues == ["public", "private-managed", "private-existing"]
  and (.parameters | has("networkMode") | not)
  and (.parameters | has("networkSource") | not)
  and ([.resources[]
    | select(.type == "Microsoft.Resources/deployments")
    | select(.name == "private-networking")
    | select(.condition == "[variables('\''isPrivateNetwork'\'')]")
    | select((.dependsOn | index("functionStorage")) != null)
    | select((.dependsOn | index("applicationInsights")) != null)
  ] | length) == 1
  and ([.resources[]
    | select(.type == "Microsoft.Resources/deployments")
    | select((.name | tostring) | contains("functionStorage"))
    | .properties.parameters.publicNetworkAccess
    | select(type == "string" and contains("isPrivateNetwork"))
  ] | length) == 1
  and ([.resources[]
    | select(.type == "Microsoft.Resources/deployments")
    | select((.name | tostring) | contains("applicationInsights"))
    | .properties.parameters.publicNetworkAccessForIngestion
    | select(type == "string" and contains("isPrivateNetwork"))
  ] | length) == 1
  and ([.resources[]
    | select(.type == "Microsoft.Resources/deployments")
    | select((.name | tostring) | contains("functionApp"))
    | .properties.parameters.virtualNetworkSubnetResourceId
    | select(type == "string" and contains("privateNetworking"))
  ] | length) == 1
' "$compiled_template" >/dev/null

jq -e '
  .variables.environmentUniqueToken == "[uniqueString(subscription().id, variables('\''lowerEnvironmentName'\''), toLower(parameters('\''location'\'')))]"
  and (.variables | has("environmentNameToken") | not)
  and (.variables | has("storageEnvironmentNameToken") | not)
  and (.variables | has("normalizedEnvironmentName") | not)
  and (.variables | has("nameSuffix") | not)
' "$compiled_template" >/dev/null

jq -e '
  [.resources[]
    | select(.type == "Microsoft.Resources/deployments")
    | select(.copy.name? == "subscriptionReaders")
    | .name
    | select(contains("environmentUniqueToken"))
    | select(contains("discoverySubscriptionIds"))
  ] | length == 1
' "$compiled_template" >/dev/null

jq -e '
  [.resources[]
    | select(.type == "Microsoft.Resources/deployments")
    | select(.name == "private-networking")
    | .properties.template.resources[]
  ] as $networkResources
  | ([$networkResources[] | select(.type == "Microsoft.Network/virtualNetworks")] | length) == 1
    and ([$networkResources[] | select(.type == "Microsoft.Network/privateDnsZones")] | length) == 1
    and ([$networkResources[] | select(.type == "Microsoft.Network/privateEndpoints")] | length) == 2
    and ([$networkResources[] | select(.type == "Microsoft.Network/privateEndpoints/privateDnsZoneGroups")] | length) == 2
    and ([$networkResources[] | select((.type | ascii_downcase) == "microsoft.insights/privatelinkscopes")] | length) == 1
    and ([$networkResources[] | select(.type == "Microsoft.Insights/privateLinkScopes/scopedResources")] | length) == 2
' "$compiled_template" >/dev/null

printf 'PASS azd values reach Bicep, deterministic environment naming is reused, private profiles wire service access, and optional tags reach all seven tagged modules\n'
