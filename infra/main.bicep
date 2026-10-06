targetScope = 'resourceGroup'

@description('The azd environment name (1-64 characters). Generated names use a bounded lowercase alphanumeric token; tags retain the full value.')
@minLength(1)
@maxLength(64)
param environmentName string

@description('Azure region for the resources.')
param location string = resourceGroup().location

@description('Optional existing or globally unique Function App name (2-60 alphanumerics/hyphens, no leading/trailing hyphen). Empty generates a CAF-style name; pin existing names before adoption.')
@maxLength(60)
param functionAppName string = ''

@description('Optional existing or resource-group-unique Flex plan name (1-60 alphanumerics/hyphens). Empty generates a CAF-style asp name.')
@maxLength(60)
param functionPlanName string = ''

@description('Optional existing or globally unique shared host/deployment/state storage name (3-24 alphanumerics, normalized to lowercase). Empty generates a CAF-style st name. Pin the existing name to retain state/history.')
@maxLength(24)
param functionStorageAccountName string = ''

@description('Optional existing or resource-group-unique Log Analytics name (4-63 alphanumerics/hyphens). Pin the existing name to retain telemetry; empty generates a CAF-style log name.')
@maxLength(63)
param logAnalyticsWorkspaceName string = ''

@description('Optional existing or resource-group-unique Application Insights name (1-260 characters subject to provider rules). Pin the existing name to retain telemetry; empty generates a CAF-style appi name.')
@maxLength(260)
param applicationInsightsName string = ''

@description('Optional name of the central user-assigned identity in this resource group (3-128 alphanumerics, hyphens, underscores; starts alphanumeric). Empty generates a CAF-style id name. Preserve this identity across Function replacements.')
@maxLength(128)
param managedIdentityName string = ''

@description('Timer schedule in NCRONTAB format. RunOnStartup remains disabled in code.')
param timerSchedule string = '0 */10 * * * *'

@description('Comma-separated Azure subscription IDs scanned as one complete Key Vault mapping graph.')
@minLength(36)
param keyVaultSyncSubscriptions string

@description('Base64-encoded 32-byte HMAC key validated by the azd deployment-preparation hook.')
@secure()
param keyVaultSyncHmacKey string

@description('Preserve existing Function App application settings not managed by this template during later provisioning.')
param preserveExistingAppSettings bool = false

@description('Optional tag name to add to the deployment resource group and all tagged resources managed by this template. Leave both optional tag parameters empty to make no optional tag change.')
param optionalResourceGroupTagName string = ''

@description('Optional tag value to add to the deployment resource group and all tagged resources managed by this template. Leave both optional tag parameters empty to make no optional tag change.')
param optionalResourceGroupTagValue string = ''

@description('Retention period for the Log Analytics workspace.')
@minValue(30)
@maxValue(730)
param logAnalyticsRetentionDays int = 30

@description('Maximum on-demand Flex Consumption instances per scaling group (1-1000). A ceiling, not reserved capacity or a single-writer guarantee.')
@minValue(1)
@maxValue(1000)
param maximumInstanceCount int = 10

@description('Flex Consumption instance memory in MB. Supported sizes are 512, 2048, and 4096; the default is 4096. Confirm the selected size is available for Flex Consumption in the target region before deploying.')
@allowed([
  512
  2048
  4096
])
param instanceMemoryMB int = 4096

@allowed([
  'public'
  'private-managed'
  'private-existing'
])
@description('Networking profile for KeyVaultSync-managed resources. Public preserves service endpoints; private-managed creates dedicated networking; private-existing attaches to supplied enterprise resources.')
param networkProfile string = 'public'

@description('Optional managed VNet name. Empty generates a CAF-style name.')
@maxLength(64)
param managedVirtualNetworkName string = ''

@description('Address prefix for the managed VNet.')
param managedVirtualNetworkAddressPrefix string = '10.42.0.0/24'

@description('Name of the managed Flex Consumption integration subnet.')
param managedFunctionIntegrationSubnetName string = 'snet-functions'

@description('Address prefix for the managed Flex Consumption integration subnet. Use /27 or larger.')
param managedFunctionIntegrationSubnetPrefix string = '10.42.0.0/27'

@description('Name of the managed private endpoint subnet.')
param managedPrivateEndpointSubnetName string = 'snet-private-endpoints'

@description('Address prefix for the managed private endpoint subnet.')
param managedPrivateEndpointSubnetPrefix string = '10.42.0.32/27'

@description('Existing Flex Consumption integration subnet resource ID. Required for the private-existing profile.')
param existingFunctionIntegrationSubnetResourceId string = ''

@description('Existing private endpoint subnet resource ID. Required for the private-existing profile and must differ from the integration subnet.')
param existingPrivateEndpointSubnetResourceId string = ''

@description('Existing Storage Blob private DNS zone resource ID. Required for the private-existing profile.')
param existingBlobPrivateDnsZoneResourceId string = ''

@description('Existing Storage Queue private DNS zone resource ID. Required for the private-existing profile.')
param existingQueuePrivateDnsZoneResourceId string = ''

@description('Existing Storage Table private DNS zone resource ID. Required for the private-existing profile.')
param existingTablePrivateDnsZoneResourceId string = ''

@description('Existing Azure Monitor private DNS zone resource ID. Required for the private-existing profile.')
param existingMonitorPrivateDnsZoneResourceId string = ''

@description('Existing Log Analytics OMS private DNS zone resource ID. Required for the private-existing profile.')
param existingOmsPrivateDnsZoneResourceId string = ''

@description('Existing Log Analytics ODS private DNS zone resource ID. Required for the private-existing profile.')
param existingOdsPrivateDnsZoneResourceId string = ''

@description('Existing Azure Automation agent-service private DNS zone resource ID. Required for the private-existing profile.')
param existingAgentServicePrivateDnsZoneResourceId string = ''

@description('Existing Azure Monitor Private Link Scope resource ID. Required for the private-existing profile.')
param existingAzureMonitorPrivateLinkScopeResourceId string = ''

// One deterministic token keeps generated names stable for a subscription, environment, and location.
var lowerEnvironmentName = toLower(environmentName)
var environmentUniqueToken = uniqueString(subscription().id, lowerEnvironmentName, toLower(location))
var resolvedFunctionAppName = empty(functionAppName) ? 'func-keyvaultsync-${environmentUniqueToken}' : functionAppName
var resolvedFunctionPlanName = empty(functionPlanName) ? 'asp-keyvaultsync-${environmentUniqueToken}' : functionPlanName
var resolvedFunctionStorageName = empty(functionStorageAccountName) ? 'stkvsfn${environmentUniqueToken}' : toLower(functionStorageAccountName)
var resolvedLogAnalyticsName = empty(logAnalyticsWorkspaceName) ? 'log-keyvaultsync-${environmentUniqueToken}' : logAnalyticsWorkspaceName
var resolvedApplicationInsightsName = empty(applicationInsightsName) ? 'appi-keyvaultsync-${environmentUniqueToken}' : applicationInsightsName
var resolvedManagedIdentityName = empty(managedIdentityName) ? 'id-keyvaultsync-${environmentUniqueToken}' : managedIdentityName
var resolvedManagedVirtualNetworkName = empty(managedVirtualNetworkName) ? 'vnet-keyvaultsync-${environmentUniqueToken}' : managedVirtualNetworkName
var runtimeIdentityResourceId = resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', resolvedManagedIdentityName)
var discoverySubscriptionIds = filter(
  map(split(replace(keyVaultSyncSubscriptions, ';', ','), ','), subscriptionId => trim(subscriptionId)),
  subscriptionId => !empty(subscriptionId))
var isPrivateNetwork = networkProfile != 'public'
var privateNetworkSource = networkProfile == 'private-managed' ? 'managed' : 'existing'

var baseResourceTags = {
  workload: 'KeyVaultSync'
  environment: environmentName
  'azd-env-name': environmentName
}

var hasOptionalResourceGroupTagName = !empty(trim(optionalResourceGroupTagName))
var hasOptionalResourceGroupTagValue = !empty(trim(optionalResourceGroupTagValue))
var applyOptionalResourceGroupTag = hasOptionalResourceGroupTagName == hasOptionalResourceGroupTagValue
  ? hasOptionalResourceGroupTagName
  : fail('Set both optionalResourceGroupTagName and optionalResourceGroupTagValue, or leave both empty.')
var optionalDeploymentTags = applyOptionalResourceGroupTag
  ? toObject([trim(optionalResourceGroupTagName)], tagName => tagName, tagName => optionalResourceGroupTagValue)
  : {}
var resourceTags = union(baseResourceTags, optionalDeploymentTags)

resource optionalResourceGroupTag 'Microsoft.Resources/tags@2025-04-01' = if (applyOptionalResourceGroupTag) {
  name: 'default'
  scope: resourceGroup()
  properties: {
    tags: union(
      resourceGroup().tags,
      optionalDeploymentTags
    )
  }
}

// Storage Blob Data Owner
var storageBlobDataOwnerRoleDefinitionId = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
// Monitoring Metrics Publisher
var monitoringMetricsPublisherRoleDefinitionId = '3913510d-42f4-4e42-8a64-420c390055eb'
// Reader
var readerRoleDefinitionId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
// Owner
var ownerRoleDefinitionId = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
var deploymentPrincipalId = deployer().objectId

// A standalone identity survives Function replacement. Restrict who can attach it to other hosts:
// every attached host receives the same permissions. Vault onboarding stays outside the runtime.
module runtimeIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.6.0' = {
  params: {
    name: resolvedManagedIdentityName
    location: location
    tags: resourceTags
    enableTelemetry: false
  }
  dependsOn: [
    optionalResourceGroupTag
  ]
}

// One account owns replaceable host/package artifacts and durable KeyVaultSync state/history.
// Do not consume AVM key/connection-string outputs. Private profiles permit only private endpoints.
module functionStorage 'br/public:avm/res/storage/storage-account:0.33.1' = {
  params: {
    name: resolvedFunctionStorageName
    location: location
    tags: resourceTags
    skuName: 'Standard_LRS'
    kind: 'StorageV2'
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: isPrivateNetwork ? 'Disabled' : 'Enabled'
    networkAcls: {
      bypass: isPrivateNetwork ? 'None' : 'AzureServices'
      defaultAction: isPrivateNetwork ? 'Deny' : 'Allow'
    }
    // This creation-only feature was absent from the original accounts; do not force-enable it on adoption.
    requireInfrastructureEncryption: false
    blobServices: {
      deleteRetentionPolicyEnabled: true
      deleteRetentionPolicyDays: 14
      deleteRetentionPolicyAllowPermanentDelete: false
      isVersioningEnabled: true
      containers: [
        {
          name: 'function-releases'
          publicAccess: 'None'
        }
        {
          name: 'keyvaultsync-state'
          publicAccess: 'None'
        }
        {
          name: 'keyvaultsync-runs'
          publicAccess: 'None'
        }
      ]
    }
    enableTelemetry: false
  }
  dependsOn: [
    optionalResourceGroupTag
  ]
}

resource functionStorageScope 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: resolvedFunctionStorageName
}

// Pin published AVM versions so module defaults cannot change during an unrelated azd provision.
// Runtime telemetry uses Entra ID; AVM usage telemetry is unrelated and is disabled here.
module logAnalytics 'br/public:avm/res/operational-insights/workspace:0.16.1' = {
  params: {
    name: resolvedLogAnalyticsName
    location: location
    tags: resourceTags
    skuName: 'PerGB2018'
    dataRetention: logAnalyticsRetentionDays
    forceCmkForQuery: false
    enableTelemetry: false
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
      disableLocalAuth: true
    }
  }
  dependsOn: [
    optionalResourceGroupTag
  ]
}

// Preserve workspace-based ingestion and IP masking rather than inheriting different AVM defaults.
module applicationInsights 'br/public:avm/res/insights/component:0.8.0' = {
  params: {
    name: resolvedApplicationInsightsName
    location: location
    tags: resourceTags
    kind: 'web'
    applicationType: 'web'
    disableLocalAuth: true
    disableIpMasking: false
    flowType: 'Bluefield'
    ingestionMode: 'LogAnalytics'
    retentionInDays: 90
    publicNetworkAccessForIngestion: isPrivateNetwork ? 'Disabled' : 'Enabled'
    publicNetworkAccessForQuery: isPrivateNetwork ? 'Disabled' : 'Enabled'
    workspaceResourceId: logAnalytics.outputs.resourceId
    enableTelemetry: false
  }
  dependsOn: [
    optionalResourceGroupTag
  ]
}

// A resource symbol supplies the RBAC scope; the module above remains the sole resource owner.
resource applicationInsightsScope 'Microsoft.Insights/components@2020-02-02' existing = {
  name: resolvedApplicationInsightsName
}

// FC1 selects AVM's FlexConsumption branch, not its default premium/always-on worker allocation.
module functionPlan 'br/public:avm/res/web/serverfarm:0.7.0' = {
  params: {
    name: resolvedFunctionPlanName
    location: location
    tags: resourceTags
    kind: 'functionapp'
    skuName: 'FC1'
    reserved: true
    zoneRedundant: false
    enableTelemetry: false
  }
  dependsOn: [
    optionalResourceGroupTag
  ]
}

module privateNetworking './modules/private-networking.bicep' = if (isPrivateNetwork) {
  name: 'private-networking'
  params: {
    location: location
    networkSource: privateNetworkSource
    nameToken: take(environmentUniqueToken, 8)
    tags: resourceTags
    managedVirtualNetworkName: resolvedManagedVirtualNetworkName
    managedVirtualNetworkAddressPrefix: managedVirtualNetworkAddressPrefix
    managedFunctionIntegrationSubnetName: managedFunctionIntegrationSubnetName
    managedFunctionIntegrationSubnetPrefix: managedFunctionIntegrationSubnetPrefix
    managedPrivateEndpointSubnetName: managedPrivateEndpointSubnetName
    managedPrivateEndpointSubnetPrefix: managedPrivateEndpointSubnetPrefix
    existingFunctionIntegrationSubnetResourceId: existingFunctionIntegrationSubnetResourceId
    existingPrivateEndpointSubnetResourceId: existingPrivateEndpointSubnetResourceId
    existingBlobPrivateDnsZoneResourceId: existingBlobPrivateDnsZoneResourceId
    existingQueuePrivateDnsZoneResourceId: existingQueuePrivateDnsZoneResourceId
    existingTablePrivateDnsZoneResourceId: existingTablePrivateDnsZoneResourceId
    existingMonitorPrivateDnsZoneResourceId: existingMonitorPrivateDnsZoneResourceId
    existingOmsPrivateDnsZoneResourceId: existingOmsPrivateDnsZoneResourceId
    existingOdsPrivateDnsZoneResourceId: existingOdsPrivateDnsZoneResourceId
    existingAgentServicePrivateDnsZoneResourceId: existingAgentServicePrivateDnsZoneResourceId
    existingAzureMonitorPrivateLinkScopeResourceId: existingAzureMonitorPrivateLinkScopeResourceId
    storageAccountResourceId: functionStorageScope.id
    logAnalyticsWorkspaceResourceId: logAnalytics.outputs.resourceId
    applicationInsightsResourceId: applicationInsightsScope.id
  }
  dependsOn: [
    functionStorage
    applicationInsights
  ]
}

// Flex owns runtime selection. Remove legacy connection selectors as well so an exact connection
// string cannot override the identity-based host connection, or conflict with its client ID.
var retiredFunctionAppSettingNames = [
  'FUNCTIONS_EXTENSION_VERSION'
  'FUNCTIONS_WORKER_RUNTIME'
  'FUNCTIONS_WORKER_RUNTIME_VERSION'
  'AZUREWEBJOBSSTORAGE'
  'AZUREWEBJOBSSTORAGE__MANAGEDIDENTITYRESOURCEID'
  'KEYVAULTSYNC_APPLY_SECRETS'
  'KEYVAULTSYNC_SEED_MISSING_KEYS_AND_CERTIFICATES'
  'KEYVAULTSYNC_SINGLE_WRITER_MODE'
  'AZURE_SUBSCRIPTION_ID'
  'KEYVAULTSYNC_RESOURCE_GROUP'
  'KEYVAULTSYNC_PAIR_TAG'
  'KEYVAULTSYNC_REBASELINE'
]

// Enabled mappings opt pairs into supported synchronization; the runner owns ordinary defaults
// (tag, containers, key-version label, log level).
var desiredFunctionAppSettings = {
  AZURE_CLIENT_ID: runtimeIdentity.outputs.clientId
  AzureWebJobsStorage__accountName: functionStorage.outputs.name
  AzureWebJobsStorage__credential: 'managedidentity'
  AzureWebJobsStorage__clientId: runtimeIdentity.outputs.clientId
  APPLICATIONINSIGHTS_CONNECTION_STRING: applicationInsights.outputs.connectionString
  APPLICATIONINSIGHTS_AUTHENTICATION_STRING: 'ClientId=${runtimeIdentity.outputs.clientId};Authorization=AAD'
  KEYVAULTSYNC_SUBSCRIPTIONS: keyVaultSyncSubscriptions
  KEYVAULTSYNC_STORAGE_ACCOUNT_URI: functionStorage.outputs.serviceEndpoints.blob
  KEYVAULTSYNC_HMAC_KEY: keyVaultSyncHmacKey
  KEYVAULTSYNC_PRINCIPAL_ID: runtimeIdentity.outputs.principalId
  KEYVAULTSYNC_TIMER_SCHEDULE: timerSchedule
}

// The standalone user-assigned identity is the only runtime principal. The guarded child
// resource owns template settings and can preserve other existing settings on later deployments.
module functionApp 'br/public:avm/res/web/site:0.24.0' = {
  params: {
    name: resolvedFunctionAppName
    location: location
    // Must match the service key in azure.yaml so azd deploy selects this app.
    tags: union(resourceTags, { 'azd-service-name': 'keyvaultsync' })
    kind: 'functionapp,linux'
    serverFarmResourceId: functionPlan.outputs.resourceId
    managedIdentities: {
      systemAssigned: false
      userAssignedResourceIds: [
        runtimeIdentity.outputs.resourceId
      ]
    }
    keyVaultAccessIdentityResourceId: runtimeIdentity.outputs.resourceId
    virtualNetworkSubnetResourceId: isPrivateNetwork ? privateNetworking!.outputs.functionIntegrationSubnetResourceId : null
    publicNetworkAccess: isPrivateNetwork ? 'Disabled' : 'Enabled'
    httpsOnly: true
    clientAffinityEnabled: false
    clientAffinityProxyEnabled: false
    // Override AVM's always-on/FTPS defaults; Flex scaling is configured in functionAppConfig.
    siteConfig: {
      http20Enabled: true
      minTlsVersion: '1.2'
    }
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${functionStorage.outputs.serviceEndpoints.blob}function-releases'
          authentication: {
            type: 'UserAssignedIdentity'
            userAssignedIdentityResourceId: runtimeIdentity.outputs.resourceId
          }
        }
      }
      runtime: {
        name: 'dotnet-isolated'
        version: '10.0'
      }
      scaleAndConcurrency: {
        maximumInstanceCount: maximumInstanceCount
        instanceMemoryMB: instanceMemoryMB
      }
    }
    diagnosticSettings: [
      {
        name: 'function-to-log-analytics'
        workspaceResourceId: logAnalytics.outputs.resourceId
        logCategoriesAndGroups: [
          {
            categoryGroup: 'allLogs'
          }
        ]
        metricCategories: [
          {
            category: 'AllMetrics'
          }
        ]
      }
    ]
    enableTelemetry: false
  }
  // Grants can precede app creation now that the principal is independent. Completion still does
  // not prove data-plane RBAC propagation; validate startup after provisioning and package deployment.
  dependsOn: [
    functionStorageBlobOwner
    applicationInsightsMetricsPublisher
    subscriptionReaders
  ]
}

resource functionAppScope 'Microsoft.Web/sites@2024-04-01' existing = {
  name: resolvedFunctionAppName
}

// Retain protected/custom settings only when requested, excluding deprecated host selectors and
// retired runtime gates. ARM replaces this collection, so filter before merging template-owned keys.
resource functionAppSettings 'Microsoft.Web/sites/config@2022-03-01' = {
  name: 'appsettings'
  parent: functionAppScope
  properties: preserveExistingAppSettings
    ? union(
        toObject(
          filter(
            items(list(resourceId('Microsoft.Web/sites/config', functionAppScope.name, 'appsettings'), '2022-03-01').properties),
            setting => !contains(retiredFunctionAppSettingNames, toUpper(setting.key))
          ),
          setting => setting.key,
          setting => setting.value
        ),
        desiredFunctionAppSettings
      )
    : desiredFunctionAppSettings
  dependsOn: [
    functionApp
  ]
}

// Assignment IDs include the identity resource ID, known before its principal exists and distinct
// from old Function-based seeds. Preserve the identity itself; retire old grants separately.
resource functionStorageBlobOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionStorageScope.id, runtimeIdentityResourceId, storageBlobDataOwnerRoleDefinitionId)
  scope: functionStorageScope
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataOwnerRoleDefinitionId)
    principalId: runtimeIdentity.outputs.principalId
    principalType: 'ServicePrincipal'
  }
  dependsOn: [
    functionStorage
  ]
}

resource deploymentPrincipalStorageBlobOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionStorageScope.id, deploymentPrincipalId, storageBlobDataOwnerRoleDefinitionId)
  scope: functionStorageScope
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataOwnerRoleDefinitionId)
    principalId: deploymentPrincipalId
  }
  dependsOn: [
    functionStorage
  ]
}

module deploymentPrincipalOwner 'br/public:avm/res/authorization/role-assignment/rg-scope:0.1.1' = {
  name: 'deployment-principal-owner'
  params: {
    name: guid(resourceGroup().id, deploymentPrincipalId, ownerRoleDefinitionId)
    principalId: deploymentPrincipalId
    roleDefinitionIdOrName: ownerRoleDefinitionId
    enableTelemetry: false
  }
}

module subscriptionReaders 'br/public:avm/res/authorization/role-assignment/sub-scope:0.1.1' = [for discoverySubscriptionId in discoverySubscriptionIds: {
  // Subscription-scope deployment names are immutable to their original location. Include the
  // reusable environment token and target subscription to avoid cross-region/environment reuse.
  name: 'subscription-reader-${take(uniqueString(discoverySubscriptionId, environmentUniqueToken), 8)}'
  scope: subscription(discoverySubscriptionId)
  params: {
    name: guid(discoverySubscriptionId, runtimeIdentity.outputs.principalId, readerRoleDefinitionId)
    principalId: runtimeIdentity.outputs.principalId
    roleDefinitionIdOrName: readerRoleDefinitionId
    principalType: 'ServicePrincipal'
    enableTelemetry: false
  }
}]

resource applicationInsightsMetricsPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(applicationInsightsScope.id, runtimeIdentityResourceId, monitoringMetricsPublisherRoleDefinitionId)
  scope: applicationInsightsScope
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherRoleDefinitionId)
    principalId: runtimeIdentity.outputs.principalId
    principalType: 'ServicePrincipal'
  }
  dependsOn: [
    applicationInsights
  ]
}

@description('Function App deployment target; retained for existing azd consumers.')
output AZURE_FUNCTIONAPP_NAME string = functionApp.outputs.name
@description('Compatible alternate Function App output name.')
output AZURE_FUNCTION_APP_NAME string = functionApp.outputs.name
@description('HTTPS hostname; the timer Function does not expose a synchronization HTTP endpoint.')
output AZURE_FUNCTIONAPP_URL string = 'https://${functionApp.outputs.defaultHostname}'
@description('Non-secret Blob service URI used with managed identity for state and run history.')
output KEYVAULTSYNC_STORAGE_ACCOUNT_URI string = functionStorage.outputs.serviceEndpoints.blob

@description('Non-secret central identity resource ID for the separate, approval-gated vault-access script. Not a runtime setting.')
output KEYVAULTSYNC_IDENTITY_RESOURCE_ID string = runtimeIdentity.outputs.resourceId
@description('Configured networking profile.')
output KEYVAULTSYNC_NETWORK_PROFILE string = networkProfile
@description('Flex integration subnet resource ID for either private profile; empty for the public profile.')
output KEYVAULTSYNC_FUNCTION_INTEGRATION_SUBNET_ID string = isPrivateNetwork ? privateNetworking!.outputs.functionIntegrationSubnetResourceId : ''
