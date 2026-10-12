// Gives the connector's managed identity access to the Key Vault it uses as
// its key store, deployed in the vault's resource group. Vaults that use
// Azure RBAC get role assignments on the vault; vaults that use access
// policies get an access policy with the same permissions (see the
// Permissions section of plugins/azure-keyvault/README.md).

@description('Name of the Key Vault.')
param vaultName string

@description('Object id of the connector\'s managed identity.')
param principalId string

@description('The vault uses Azure RBAC rather than access policies.')
param useRbac bool

@description('Also allow importing certificates and reading their secrets, which a rollback needs.')
param allowRollback bool

@description('Id of the custom role with the key store permissions.')
param keyVaultRoleId string

@description('Id of the custom role with the rollback permissions.')
param keyVaultRollbackRoleId string

@description('Resource id of the Application Gateway\'s user-assigned identity to give read access to the vault\'s secrets, or an empty string.')
param appGatewayIdentityId string

// Key Vault Secrets User: read secret contents. The role Application
// Gateway's identity needs to load certificates from the vault.
var secretsUserRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')

var grantGateway = !empty(appGatewayIdentityId)

resource vault 'Microsoft.KeyVault/vaults@2025-05-01' existing = {
  name: vaultName
}

resource gatewayIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = if (grantGateway) {
  name: last(split(appGatewayIdentityId, '/'))
  scope: resourceGroup(split(appGatewayIdentityId, '/')[2], split(appGatewayIdentityId, '/')[4])
}

resource keyStore 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (useRbac) {
  name: guid(vault.id, principalId, keyVaultRoleId)
  scope: vault
  properties: {
    roleDefinitionId: keyVaultRoleId
    principalId: principalId
    principalType: 'ServicePrincipal'
    description: 'KrakenKey connector: Key Vault key store.'
  }
}

resource rollback 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (useRbac && allowRollback) {
  name: guid(vault.id, principalId, keyVaultRollbackRoleId)
  scope: vault
  properties: {
    roleDefinitionId: keyVaultRollbackRoleId
    principalId: principalId
    principalType: 'ServicePrincipal'
    description: 'KrakenKey connector: Key Vault rollback.'
  }
}

resource gatewaySecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (useRbac && grantGateway) {
  name: guid(vault.id, toLower(appGatewayIdentityId), secretsUserRoleId)
  scope: vault
  properties: {
    roleDefinitionId: secretsUserRoleId
    principalId: gatewayIdentity!.properties.principalId
    principalType: 'ServicePrincipal'
    description: 'Application Gateway: read certificates from the vault.'
  }
}

var connectorPolicy = {
  tenantId: tenant().tenantId
  objectId: principalId
  permissions: {
    certificates: concat(['get', 'list', 'create', 'update'], allowRollback ? ['import'] : [])
    secrets: allowRollback ? ['get'] : []
  }
}

var gatewayPolicy = grantGateway
  ? [
      {
        tenantId: tenant().tenantId
        objectId: gatewayIdentity!.properties.principalId
        permissions: {
          secrets: ['get']
        }
      }
    ]
  : []

resource policies 'Microsoft.KeyVault/vaults/accessPolicies@2025-05-01' = if (!useRbac) {
  parent: vault
  name: 'add'
  properties: {
    accessPolicies: concat([connectorPolicy], gatewayPolicy)
  }
}
