// Assigns the Application Gateway linked resources role to the connector's
// managed identity on one resource the gateway links to: a subnet, a public
// IP address, a WAF policy or a user-assigned identity. Updating a gateway
// is a full PUT, so Azure checks the caller's rights on each of them.
// Deployed in that resource's resource group.

@description('Resource id of the linked resource.')
param resourceId string

@description('Object id of the connector\'s managed identity.')
param principalId string

@description('Id of the custom linked resources role.')
param roleId string

var parts = split(resourceId, '/')
var provider = toLower(parts[6])
var type = toLower(parts[7])
var isSubnet = provider == 'microsoft.network' && type == 'virtualnetworks' && length(parts) > 10
var isPublicIp = provider == 'microsoft.network' && type == 'publicipaddresses'
var isWafPolicy = provider == 'microsoft.network' && type == 'applicationgatewaywebapplicationfirewallpolicies'
var isIdentity = provider == 'microsoft.managedidentity' && type == 'userassignedidentities'

var assignmentDescription = 'KrakenKey connector: keep this resource linked when it updates the Application Gateway.'

resource vnet 'Microsoft.Network/virtualNetworks@2025-05-01' existing = if (isSubnet) {
  name: parts[8]

  resource subnet 'subnets' existing = {
    name: last(parts)
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2025-05-01' existing = if (isPublicIp) {
  name: parts[8]
}

resource wafPolicy 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies@2025-05-01' existing = if (isWafPolicy) {
  name: parts[8]
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = if (isIdentity) {
  name: parts[8]
}

resource onSubnet 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (isSubnet) {
  name: guid(resourceId, principalId, roleId)
  scope: vnet::subnet
  properties: {
    roleDefinitionId: roleId
    principalId: principalId
    principalType: 'ServicePrincipal'
    description: assignmentDescription
  }
}

resource onPublicIp 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (isPublicIp) {
  name: guid(resourceId, principalId, roleId)
  scope: publicIp
  properties: {
    roleDefinitionId: roleId
    principalId: principalId
    principalType: 'ServicePrincipal'
    description: assignmentDescription
  }
}

resource onWafPolicy 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (isWafPolicy) {
  name: guid(resourceId, principalId, roleId)
  scope: wafPolicy
  properties: {
    roleDefinitionId: roleId
    principalId: principalId
    principalType: 'ServicePrincipal'
    description: assignmentDescription
  }
}

resource onIdentity 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (isIdentity) {
  name: guid(resourceId, principalId, roleId)
  scope: identity
  properties: {
    roleDefinitionId: roleId
    principalId: principalId
    principalType: 'ServicePrincipal'
    description: assignmentDescription
  }
}
