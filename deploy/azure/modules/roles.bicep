// Custom roles for the connector's managed identity, created in one
// subscription. They are the least-privilege roles from the plugin READMEs
// (plugins/azure-keyvault and plugins/azure-appgateway). The role ids are
// derived from the subscription id, so a second deployment in the same
// subscription updates the same roles instead of adding more, and main.bicep
// can compute the ids without reading this module's outputs. Role names
// must be unique in the tenant, so they end with the subscription id.
targetScope = 'subscription'

@description('Create the Key Vault roles in this subscription.')
param keyVaultRoles bool

@description('Create the Application Gateway role in this subscription.')
param appGatewayRole bool

@description('Create the Application Gateway linked resources role in this subscription.')
param linkedResourcesRole bool

var scopes = [subscription().id]
var suffix = ' (${subscription().subscriptionId})'

resource keyVault 'Microsoft.Authorization/roleDefinitions@2022-04-01' = if (keyVaultRoles) {
  name: guid(subscription().id, 'krakenkey-connector-keyvault')
  properties: {
    roleName: 'KrakenKey connector Key Vault${suffix}'
    description: 'Create, merge and read Key Vault certificates for the KrakenKey connector.'
    type: 'CustomRole'
    assignableScopes: scopes
    permissions: [
      {
        dataActions: [
          'Microsoft.KeyVault/vaults/certificates/read'
          'Microsoft.KeyVault/vaults/certificates/create/action'
          'Microsoft.KeyVault/vaults/certificates/update/action'
        ]
      }
    ]
  }
}

resource keyVaultRollback 'Microsoft.Authorization/roleDefinitions@2022-04-01' = if (keyVaultRoles) {
  name: guid(subscription().id, 'krakenkey-connector-keyvault-rollback')
  properties: {
    roleName: 'KrakenKey connector Key Vault rollback${suffix}'
    description: 'Import Key Vault certificates and read their secrets, so the KrakenKey connector can put a certificate back after a rollback.'
    type: 'CustomRole'
    assignableScopes: scopes
    permissions: [
      {
        dataActions: [
          'Microsoft.KeyVault/vaults/certificates/import/action'
          'Microsoft.KeyVault/vaults/secrets/getSecret/action'
        ]
      }
    ]
  }
}

resource appGateway 'Microsoft.Authorization/roleDefinitions@2022-04-01' = if (appGatewayRole) {
  name: guid(subscription().id, 'krakenkey-connector-appgateway')
  properties: {
    roleName: 'KrakenKey Application Gateway certificate writer${suffix}'
    description: 'Read and update Application Gateways.'
    type: 'CustomRole'
    assignableScopes: scopes
    permissions: [
      {
        actions: [
          'Microsoft.Network/applicationGateways/read'
          'Microsoft.Network/applicationGateways/write'
        ]
      }
    ]
  }
}

resource linkedResources 'Microsoft.Authorization/roleDefinitions@2022-04-01' = if (linkedResourcesRole) {
  name: guid(subscription().id, 'krakenkey-connector-appgateway-linked')
  properties: {
    roleName: 'KrakenKey Application Gateway linked resources${suffix}'
    description: 'Let an Application Gateway update keep its subnet, public IP, WAF policy and identity.'
    type: 'CustomRole'
    assignableScopes: scopes
    permissions: [
      {
        actions: [
          'Microsoft.Network/virtualNetworks/subnets/read'
          'Microsoft.Network/virtualNetworks/subnets/join/action'
          'Microsoft.Network/publicIPAddresses/read'
          'Microsoft.Network/publicIPAddresses/join/action'
          'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/read'
          'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/join/action'
          'Microsoft.ManagedIdentity/userAssignedIdentities/assign/action'
        ]
      }
    ]
  }
}
