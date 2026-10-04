targetScope = 'resourceGroup'

@description('Azure region for the VNet and private endpoints.')
param location string

@allowed([
  'managed'
  'existing'
])
@description('Whether this module creates a dedicated VNet/DNS/AMPLS or attaches to enterprise-owned resources.')
param networkSource string

@description('Stable token used to name KeyVaultSync-owned network resources.')
param nameToken string

@description('Tags applied to KeyVaultSync-owned network resources.')
param tags object

@description('Managed VNet name.')
param managedVirtualNetworkName string

@description('Managed VNet address prefix.')
param managedVirtualNetworkAddressPrefix string

@description('Managed Flex Consumption integration subnet name.')
param managedFunctionIntegrationSubnetName string

@description('Managed Flex Consumption integration subnet prefix. Use /27 or larger.')
param managedFunctionIntegrationSubnetPrefix string

@description('Managed private endpoint subnet name.')
param managedPrivateEndpointSubnetName string

@description('Managed private endpoint subnet prefix.')
param managedPrivateEndpointSubnetPrefix string

@description('Existing Flex Consumption integration subnet resource ID.')
param existingFunctionIntegrationSubnetResourceId string

@description('Existing private endpoint subnet resource ID.')
param existingPrivateEndpointSubnetResourceId string

@description('Existing private DNS zone resource ID for Storage Blob.')
param existingBlobPrivateDnsZoneResourceId string

@description('Existing private DNS zone resource ID for Storage Queue.')
param existingQueuePrivateDnsZoneResourceId string

@description('Existing private DNS zone resource ID for Storage Table.')
param existingTablePrivateDnsZoneResourceId string

@description('Existing private DNS zone resource ID for Key Vault.')
param existingKeyVaultPrivateDnsZoneResourceId string

@description('Existing private DNS zone resource ID for Azure Monitor.')
param existingMonitorPrivateDnsZoneResourceId string

@description('Existing private DNS zone resource ID for Log Analytics OMS.')
param existingOmsPrivateDnsZoneResourceId string

@description('Existing private DNS zone resource ID for Log Analytics ODS.')
param existingOdsPrivateDnsZoneResourceId string

@description('Existing private DNS zone resource ID for Azure Automation agent service.')
param existingAgentServicePrivateDnsZoneResourceId string

@description('Existing Azure Monitor Private Link Scope resource ID.')
param existingAzureMonitorPrivateLinkScopeResourceId string

@description('KeyVaultSync storage account resource ID.')
param storageAccountResourceId string

@description('Log Analytics workspace resource ID.')
param logAnalyticsWorkspaceResourceId string

@description('Application Insights component resource ID.')
param applicationInsightsResourceId string

@description('Existing source and target Key Vault resource IDs that need KeyVaultSync-owned private endpoints.')
param keyVaultResourceIds array = []

var useManagedNetwork = networkSource == 'managed'
var useExistingNetwork = networkSource == 'existing'
var existingSubnetIdsAreDistinct = existingFunctionIntegrationSubnetResourceId != existingPrivateEndpointSubnetResourceId
var existingAzureMonitorPrivateLinkScopeSegments = split(existingAzureMonitorPrivateLinkScopeResourceId, '/')
var existingAzureMonitorPrivateLinkScopeIdValid = length(existingAzureMonitorPrivateLinkScopeSegments) >= 9 && contains(
  toLower(existingAzureMonitorPrivateLinkScopeResourceId),
  '/providers/microsoft.insights/privatelinkscopes/')
var existingPrivateDnsZoneResourceIds = [
  existingBlobPrivateDnsZoneResourceId
  existingQueuePrivateDnsZoneResourceId
  existingTablePrivateDnsZoneResourceId
  existingKeyVaultPrivateDnsZoneResourceId
  existingMonitorPrivateDnsZoneResourceId
  existingOmsPrivateDnsZoneResourceId
  existingOdsPrivateDnsZoneResourceId
  existingAgentServicePrivateDnsZoneResourceId
]
var existingInputsComplete = !empty(existingFunctionIntegrationSubnetResourceId) && !empty(existingPrivateEndpointSubnetResourceId) && existingSubnetIdsAreDistinct && !contains(existingPrivateDnsZoneResourceIds, '') && existingAzureMonitorPrivateLinkScopeIdValid
var validatedExistingInputs = useExistingNetwork && !existingInputsComplete
  ? fail('Existing private networking requires two distinct subnet IDs, all eight private DNS zone IDs, and an Azure Monitor Private Link Scope ID.')
  : true
var invalidKeyVaultResourceIds = filter(
  keyVaultResourceIds,
  keyVaultResourceId => !contains(toLower(keyVaultResourceId), '/providers/microsoft.keyvault/vaults/'))
var validatedKeyVaultResourceIds = useManagedNetwork && empty(keyVaultResourceIds)
  ? fail('Managed private networking requires at least one source or target Key Vault resource ID in privateKeyVaultResourceIds.')
  : (!empty(invalidKeyVaultResourceIds)
      ? fail('Every privateKeyVaultResourceIds entry must be a Microsoft.KeyVault/vaults resource ID.')
      : keyVaultResourceIds)

var privateDnsZoneNames = [
  'privatelink.blob.${environment().suffixes.storage}'
  'privatelink.queue.${environment().suffixes.storage}'
  'privatelink.table.${environment().suffixes.storage}'
  'privatelink.vaultcore.azure.net'
  'privatelink.monitor.azure.com'
  'privatelink.oms.opinsights.azure.com'
  'privatelink.ods.opinsights.azure.com'
  'privatelink.agentsvc.azure-automation.net'
]

resource managedVirtualNetwork 'Microsoft.Network/virtualNetworks@2024-07-01' = if (useManagedNetwork) {
  name: managedVirtualNetworkName
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        managedVirtualNetworkAddressPrefix
      ]
    }
    subnets: [
      {
        name: managedFunctionIntegrationSubnetName
        properties: {
          addressPrefix: managedFunctionIntegrationSubnetPrefix
          delegations: [
            {
              name: 'flex-consumption'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        name: managedPrivateEndpointSubnetName
        properties: {
          addressPrefix: managedPrivateEndpointSubnetPrefix
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

var managedVirtualNetworkResourceId = resourceId('Microsoft.Network/virtualNetworks', managedVirtualNetworkName)
var managedFunctionIntegrationSubnetResourceId = resourceId(
  'Microsoft.Network/virtualNetworks/subnets',
  managedVirtualNetworkName,
  managedFunctionIntegrationSubnetName)
var managedPrivateEndpointSubnetResourceId = resourceId(
  'Microsoft.Network/virtualNetworks/subnets',
  managedVirtualNetworkName,
  managedPrivateEndpointSubnetName)
var resolvedFunctionIntegrationSubnetResourceId = useManagedNetwork
  ? managedFunctionIntegrationSubnetResourceId
  : (validatedExistingInputs ? existingFunctionIntegrationSubnetResourceId : '')
var resolvedPrivateEndpointSubnetResourceId = useManagedNetwork
  ? managedPrivateEndpointSubnetResourceId
  : (validatedExistingInputs ? existingPrivateEndpointSubnetResourceId : '')

resource managedPrivateDnsZones 'Microsoft.Network/privateDnsZones@2024-06-01' = [for privateDnsZoneName in privateDnsZoneNames: if (useManagedNetwork) {
  name: privateDnsZoneName
  location: 'global'
  tags: tags
}]

resource managedPrivateDnsZoneLinks 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = [for (privateDnsZoneName, zoneIndex) in privateDnsZoneNames: if (useManagedNetwork) {
  name: 'keyvaultsync-${nameToken}'
  parent: managedPrivateDnsZones[zoneIndex]
  location: 'global'
  tags: tags
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: managedVirtualNetworkResourceId
    }
  }
  dependsOn: [
    managedVirtualNetwork
  ]
}]

var managedPrivateDnsZoneResourceIds = [for (privateDnsZoneName, zoneIndex) in privateDnsZoneNames: managedPrivateDnsZones[zoneIndex].id]
var resolvedPrivateDnsZoneResourceIds = useManagedNetwork ? managedPrivateDnsZoneResourceIds : (validatedExistingInputs ? existingPrivateDnsZoneResourceIds : [])

var storagePrivateLinkServices = [
  {
    name: 'blob'
    privateDnsZoneResourceId: resolvedPrivateDnsZoneResourceIds[0]
  }
  {
    name: 'queue'
    privateDnsZoneResourceId: resolvedPrivateDnsZoneResourceIds[1]
  }
  {
    name: 'table'
    privateDnsZoneResourceId: resolvedPrivateDnsZoneResourceIds[2]
  }
]

resource storagePrivateEndpoints 'Microsoft.Network/privateEndpoints@2024-07-01' = [for storageService in storagePrivateLinkServices: {
  name: 'pe-kvs-storage-${storageService.name}-${nameToken}'
  location: location
  tags: tags
  properties: {
    subnet: {
      id: resolvedPrivateEndpointSubnetResourceId
    }
    privateLinkServiceConnections: [
      {
        name: 'storage-${storageService.name}'
        properties: {
          privateLinkServiceId: storageAccountResourceId
          groupIds: [
            storageService.name
          ]
        }
      }
    ]
  }
  dependsOn: [
    managedVirtualNetwork
  ]
}]

resource storagePrivateDnsZoneGroups 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-07-01' = [for (storageService, serviceIndex) in storagePrivateLinkServices: {
  name: 'default'
  parent: storagePrivateEndpoints[serviceIndex]
  properties: {
    privateDnsZoneConfigs: [
      {
        name: storageService.name
        properties: {
          privateDnsZoneId: storageService.privateDnsZoneResourceId
        }
      }
    ]
  }
}]

resource keyVaultPrivateEndpoints 'Microsoft.Network/privateEndpoints@2024-07-01' = [for keyVaultResourceId in validatedKeyVaultResourceIds: {
  name: 'pe-kvs-vault-${take(uniqueString(keyVaultResourceId), 8)}'
  location: location
  tags: tags
  properties: {
    subnet: {
      id: resolvedPrivateEndpointSubnetResourceId
    }
    privateLinkServiceConnections: [
      {
        name: 'vault'
        properties: {
          privateLinkServiceId: keyVaultResourceId
          groupIds: [
            'vault'
          ]
        }
      }
    ]
  }
  dependsOn: [
    managedVirtualNetwork
  ]
}]

resource keyVaultPrivateDnsZoneGroups 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-07-01' = [for (keyVaultResourceId, vaultIndex) in validatedKeyVaultResourceIds: {
  name: 'default'
  parent: keyVaultPrivateEndpoints[vaultIndex]
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'vault'
        properties: {
          privateDnsZoneId: resolvedPrivateDnsZoneResourceIds[3]
        }
      }
    ]
  }
}]

resource managedAzureMonitorPrivateLinkScope 'Microsoft.Insights/privateLinkScopes@2021-07-01-preview' = if (useManagedNetwork) {
  name: 'ampls-keyvaultsync-${nameToken}'
  location: 'global'
  tags: tags
  properties: {
    accessModeSettings: {
      ingestionAccessMode: 'PrivateOnly'
      queryAccessMode: 'PrivateOnly'
    }
  }
}

resource managedLogAnalyticsAssociation 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-07-01-preview' = if (useManagedNetwork) {
  name: 'keyvaultsync-log-analytics'
  parent: managedAzureMonitorPrivateLinkScope
  properties: {
    linkedResourceId: logAnalyticsWorkspaceResourceId
  }
}

resource managedApplicationInsightsAssociation 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-07-01-preview' = if (useManagedNetwork) {
  name: 'keyvaultsync-application-insights'
  parent: managedAzureMonitorPrivateLinkScope
  properties: {
    linkedResourceId: applicationInsightsResourceId
  }
}

var existingAzureMonitorPrivateLinkScopeSubscriptionId = useExistingNetwork && validatedExistingInputs
  ? existingAzureMonitorPrivateLinkScopeSegments[2]
  : subscription().subscriptionId
var existingAzureMonitorPrivateLinkScopeResourceGroupName = useExistingNetwork && validatedExistingInputs
  ? existingAzureMonitorPrivateLinkScopeSegments[4]
  : resourceGroup().name
var existingAzureMonitorPrivateLinkScopeName = useExistingNetwork && validatedExistingInputs
  ? existingAzureMonitorPrivateLinkScopeSegments[8]
  : ''

module existingAzureMonitorAssociations './monitor-private-link-associations.bicep' = if (useExistingNetwork && validatedExistingInputs) {
  name: 'existing-ampls-associations-${nameToken}'
  scope: resourceGroup(
    existingAzureMonitorPrivateLinkScopeSubscriptionId,
    existingAzureMonitorPrivateLinkScopeResourceGroupName)
  params: {
    privateLinkScopeName: existingAzureMonitorPrivateLinkScopeName
    associationNameToken: nameToken
    logAnalyticsWorkspaceResourceId: logAnalyticsWorkspaceResourceId
    applicationInsightsResourceId: applicationInsightsResourceId
  }
}

var resolvedAzureMonitorPrivateLinkScopeResourceId = useManagedNetwork
  ? managedAzureMonitorPrivateLinkScope.id
  : (validatedExistingInputs ? existingAzureMonitorPrivateLinkScopeResourceId : '')

resource azureMonitorPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-07-01' = {
  name: 'pe-kvs-monitor-${nameToken}'
  location: location
  tags: tags
  properties: {
    subnet: {
      id: resolvedPrivateEndpointSubnetResourceId
    }
    privateLinkServiceConnections: [
      {
        name: 'azuremonitor'
        properties: {
          privateLinkServiceId: resolvedAzureMonitorPrivateLinkScopeResourceId
          groupIds: [
            'azuremonitor'
          ]
        }
      }
    ]
  }
  dependsOn: [
    managedVirtualNetwork
    managedLogAnalyticsAssociation
    managedApplicationInsightsAssociation
    existingAzureMonitorAssociations
  ]
}

resource azureMonitorPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-07-01' = {
  name: 'default'
  parent: azureMonitorPrivateEndpoint
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'monitor'
        properties: {
          privateDnsZoneId: resolvedPrivateDnsZoneResourceIds[4]
        }
      }
      {
        name: 'oms'
        properties: {
          privateDnsZoneId: resolvedPrivateDnsZoneResourceIds[5]
        }
      }
      {
        name: 'ods'
        properties: {
          privateDnsZoneId: resolvedPrivateDnsZoneResourceIds[6]
        }
      }
      {
        name: 'agentsvc'
        properties: {
          privateDnsZoneId: resolvedPrivateDnsZoneResourceIds[7]
        }
      }
      {
        name: 'blob'
        properties: {
          privateDnsZoneId: resolvedPrivateDnsZoneResourceIds[0]
        }
      }
    ]
  }
}

output functionIntegrationSubnetResourceId string = resolvedFunctionIntegrationSubnetResourceId
output privateEndpointSubnetResourceId string = resolvedPrivateEndpointSubnetResourceId
output azureMonitorPrivateLinkScopeResourceId string = resolvedAzureMonitorPrivateLinkScopeResourceId
