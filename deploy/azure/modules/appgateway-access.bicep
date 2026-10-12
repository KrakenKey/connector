// Assigns the Application Gateway role to the connector's managed identity
// on the gateway itself, deployed in the gateway's resource group.

@description('Name of the Application Gateway.')
param gatewayName string

@description('Object id of the connector\'s managed identity.')
param principalId string

@description('Id of the custom Application Gateway role.')
param roleId string

resource gateway 'Microsoft.Network/applicationGateways@2025-05-01' existing = {
  name: gatewayName
}

resource assignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(gateway.id, principalId, roleId)
  scope: gateway
  properties: {
    roleDefinitionId: roleId
    principalId: principalId
    principalType: 'ServicePrincipal'
    description: 'KrakenKey connector: update the gateway\'s SSL certificates.'
  }
}
