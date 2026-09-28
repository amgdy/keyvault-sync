#!/usr/bin/env bash
# Verify azd environment tag values are passed to Bicep and propagated to every tagged resource.
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
compiled_template=$(mktemp)
trap 'rm -f "$compiled_template"' EXIT

jq -e '
  .parameters.optionalResourceGroupTagName.value == "${KEYVAULTSYNC_RESOURCE_GROUP_TAG_NAME=}"
  and .parameters.optionalResourceGroupTagValue.value == "${KEYVAULTSYNC_RESOURCE_GROUP_TAG_VALUE=}"
' "$repository_root/infra/main.parameters.json" >/dev/null

az bicep build \
    --file "$repository_root/infra/main.bicep" \
    --outfile "$compiled_template" >/dev/null

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
  | ($tagValues | length) == 6
    and ($tagValues | map(. == $resourceTags or . == $functionTags) | all)
' "$compiled_template" >/dev/null

printf 'PASS azd tag parameters are wired through Bicep to the resource group and all six tagged modules\n'
