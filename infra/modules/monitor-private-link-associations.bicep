targetScope = 'resourceGroup'

@description('Existing Azure Monitor Private Link Scope name.')
param privateLinkScopeName string

@description('Stable token used to keep scoped-resource names unique in a shared enterprise scope.')
param associationNameToken string

@description('Log Analytics workspace resource ID associated with the scope.')
param logAnalyticsWorkspaceResourceId string

@description('Application Insights component resource ID associated with the scope.')
param applicationInsightsResourceId string

resource privateLinkScope 'Microsoft.Insights/privateLinkScopes@2021-07-01-preview' existing = {
  name: privateLinkScopeName
}

resource logAnalyticsAssociation 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-07-01-preview' = {
  name: 'keyvaultsync-log-${associationNameToken}'
  parent: privateLinkScope
  properties: {
    linkedResourceId: logAnalyticsWorkspaceResourceId
  }
}

resource applicationInsightsAssociation 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-07-01-preview' = {
  name: 'keyvaultsync-appi-${associationNameToken}'
  parent: privateLinkScope
  properties: {
    linkedResourceId: applicationInsightsResourceId
  }
}
