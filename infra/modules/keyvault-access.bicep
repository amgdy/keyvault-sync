targetScope = 'resourceGroup'

@description('Name of an existing source or target Key Vault. This module never creates the vault.')
param vaultName string

@description('Object ID of the KeyVaultSync Function App managed identity.')
param principalId string

@description('Use Azure RBAC when true; otherwise append an access policy without replacing existing policies.')
param useRbacAuthorization bool

@description('Allow secret value reads for approved mutation verification. Keep false for read-only inventory.')
param allowSecretValueRead bool = false

// Key Vault Reader
var keyVaultReaderRoleDefinitionId = '21090545-7ca7-4776-b22c-e363652d74d2'
// Key Vault Secrets User
var keyVaultSecretsUserRoleDefinitionId = '4633458b-17de-408a-b874-0445c86b69e6'

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: vaultName
}

resource keyVaultReaderAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (useRbacAuthorization) {
  name: guid(vault.id, principalId, keyVaultReaderRoleDefinitionId)
  scope: vault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultReaderRoleDefinitionId)
    principalId: principalId
    principalType: 'ServicePrincipal'
  }
}

resource keyVaultSecretsUserAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (useRbacAuthorization && allowSecretValueRead) {
  name: guid(vault.id, principalId, keyVaultSecretsUserRoleDefinitionId)
  scope: vault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserRoleDefinitionId)
    principalId: principalId
    principalType: 'ServicePrincipal'
  }
}

resource keyVaultAccessPolicy 'Microsoft.KeyVault/vaults/accessPolicies@2023-07-01' = if (!useRbacAuthorization) {
  name: 'add'
  parent: vault
  properties: {
    accessPolicies: [
      {
        tenantId: tenant().tenantId
        objectId: principalId
        permissions: {
          certificates: [
            'get'
            'list'
          ]
          keys: [
            'get'
            'list'
          ]
          secrets: allowSecretValueRead ? [
            'get'
            'list'
          ] : [
            'list'
          ]
        }
      }
    ]
  }
}
