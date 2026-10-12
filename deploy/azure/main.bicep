// KrakenKey connector on an Azure VM.
//
// Creates a small Ubuntu 24.04 LTS VM without a public IP address, with a
// system-assigned managed identity that gets least-privilege access to the
// Key Vault the connector uses as its key store and, optionally, to an
// Application Gateway it deploys certificates to. On the first boot,
// cloud-init installs the connector from packages.krakenkey.io, writes its
// config, enrolls it with a one-time enrollment token and starts the
// systemd service. See README.md in this directory.
//
// mainTemplate.json is compiled from this file: run `make azure-template`
// after changing it, and commit both.

metadata info = {
  title: 'KrakenKey connector'
  description: 'Runs the KrakenKey connector on an Ubuntu VM that renews certificates into Azure Key Vault and, optionally, an Application Gateway.'
}

// Basics

@description('Location for all resources.')
param location string = resourceGroup().location

@description('Name of the virtual machine. Also used as the prefix of the other resources\' names.')
@minLength(1)
@maxLength(52)
param vmName string = 'krakenkey-connector'

@description('Size of the virtual machine. The connector needs very little: the smallest sizes are enough.')
@allowed([
  'Standard_B2ats_v2'
  'Standard_B2als_v2'
  'Standard_B1s'
  'Standard_B1ms'
  'Standard_B2s'
])
param vmSize string = 'Standard_B2ats_v2'

@description('Type of the OS disk.')
@allowed([
  'StandardSSD_LRS'
  'Standard_LRS'
  'Premium_LRS'
])
param osDiskType string = 'StandardSSD_LRS'

@description('Name of the administrator account on the VM. Sign-in is by SSH key only.')
param adminUsername string

@description('SSH public key for the administrator account.')
param adminSshPublicKey string

// KrakenKey

@description('Enrollment token for the connector (kkce_...), from the KrakenKey dashboard. It works once and expires after 24 hours.')
@secure()
param enrollmentToken string

@description('KrakenKey API URL.')
param apiUrl string = 'https://api.krakenkey.io'

@description('''The certificates to manage. Each item: id (KrakenKey certificate id), names (the certificate's DNS names, comma separated, exactly as in KrakenKey), keyVaultCertificateName (the Key Vault certificate to keep the key and certificate in), and when an Application Gateway is used, appGatewaySslCertificate (the name of the gateway's SSL certificate entry; empty to leave the certificate off the gateway) and verifyHost (a name to check the gateway with after each deployment; empty for no check).''')
param certificates array

@description('Key type for new keys. Application Gateway needs an RSA key.')
@allowed([
  'rsa-2048'
  'rsa-3072'
  'rsa-4096'
  'ecdsa-p256'
  'ecdsa-p384'
])
param keyType string = 'rsa-2048'

// Key Vault

@description('Resource id of the Key Vault the connector keeps keys and certificates in.')
param keyVaultId string

@description('The Key Vault uses Azure RBAC. Set to false for a vault that uses access policies.')
param keyVaultUseRbac bool = true

@description('Let Key Vault release the private key (exportable). Application Gateway needs it.')
param keyExportable bool = true

@description('Also let the connector import certificates and read certificate secrets in the vault, so it can put a previous certificate back after a rollback. This lets the VM read every secret in the vault.')
param allowKeyVaultRollback bool = false

// Application Gateway

@description('Resource id of an Application Gateway v2 to deploy certificates to, or an empty string for none.')
param appGatewayId string = ''

@description('Resource ids of the subnets the gateway is in.')
param appGatewaySubnetIds array = []

@description('Resource ids of the gateway\'s public IP addresses.')
param appGatewayPublicIpIds array = []

@description('Resource id of the gateway\'s own WAF policy, or an empty string.')
param appGatewayFirewallPolicyId string = ''

@description('Resource ids of the WAF policies of the gateway\'s listeners.')
param appGatewayFirewallPolicyIds array = []

@description('Resource id of the gateway\'s user-assigned managed identity.')
param appGatewayIdentityId string = ''

@description('Give the gateway\'s identity read access to the vault\'s secrets (Key Vault Secrets User, or a secret Get access policy), which it needs to load certificates from the vault.')
param grantAppGatewayVaultAccess bool = false

// Networking

@description('Create a new virtual network, or use an existing one.')
@allowed([
  'new'
  'existing'
])
param virtualNetworkNewOrExisting string = 'new'

@description('Name of the virtual network.')
param virtualNetworkName string = '${vmName}-vnet'

@description('Resource group of an existing virtual network.')
param virtualNetworkResourceGroup string = resourceGroup().name

@description('Address prefixes of a new virtual network.')
param virtualNetworkAddressPrefixes array = [
  '10.0.0.0/24'
]

@description('Name of the subnet for the VM.')
param subnetName string = 'connector'

@description('Address prefix of the subnet, in a new virtual network.')
param subnetAddressPrefix string = '10.0.0.0/27'

@description('How the VM reaches the internet in a new virtual network: a NAT gateway (recommended), or Azure\'s default outbound access, which is free but being retired for new networks. An existing network must already provide outbound access.')
@allowed([
  'natGateway'
  'defaultOutboundAccess'
])
param outboundAccess string = 'natGateway'

// Customer usage attribution: lets Microsoft associate the resources this
// template deploys with KrakenKey as their publisher. See the Customer
// usage attribution section of README.md.
// TODO(marketplace): replace with the tracking id that Partner Center shows
// on the plan's Technical configuration page. While this is the all-zero
// placeholder, no attribution deployment is created.
var partnerAttributionId = '00000000-0000-0000-0000-000000000000'

var newNetwork = virtualNetworkNewOrExisting == 'new'
var useNatGateway = newNetwork && outboundAccess == 'natGateway'
var useAppGateway = !empty(appGatewayId)

var keyVaultParts = split(keyVaultId, '/')
var keyVaultSubscription = toLower(keyVaultParts[2])
var keyVaultResourceGroup = keyVaultParts[4]
var keyVaultName = last(keyVaultParts)

var appGatewayParts = split(appGatewayId, '/')
var appGatewaySubscription = useAppGateway ? toLower(appGatewayParts[2]) : keyVaultSubscription
var appGatewayResourceGroup = useAppGateway ? appGatewayParts[4] : keyVaultResourceGroup
var appGatewayName = useAppGateway ? last(appGatewayParts) : ''

// Everything a gateway update needs the linked resources role on. Lower
// case, so the same resource written two ways is one role assignment.
var appGatewayLinkedIds = useAppGateway
  ? map(
      union(
        appGatewaySubnetIds,
        appGatewayPublicIpIds,
        appGatewayFirewallPolicyIds,
        empty(appGatewayFirewallPolicyId) ? [] : [appGatewayFirewallPolicyId],
        empty(appGatewayIdentityId) ? [] : [appGatewayIdentityId]
      ),
      id => toLower(id)
    )
  : []
var linkedSubscriptions = map(appGatewayLinkedIds, id => split(id, '/')[2])

// The subscriptions that need custom roles, each once.
var roleSubscriptions = union(
  keyVaultUseRbac ? [keyVaultSubscription] : [],
  useAppGateway ? [appGatewaySubscription] : [],
  linkedSubscriptions
)

// Role ids, the same as in modules/roles.bicep.
var keyVaultRoleId = '/subscriptions/${keyVaultSubscription}/providers/Microsoft.Authorization/roleDefinitions/${guid('/subscriptions/${keyVaultSubscription}', 'krakenkey-connector-keyvault')}'
var keyVaultRollbackRoleId = '/subscriptions/${keyVaultSubscription}/providers/Microsoft.Authorization/roleDefinitions/${guid('/subscriptions/${keyVaultSubscription}', 'krakenkey-connector-keyvault-rollback')}'
var appGatewayRoleId = '/subscriptions/${appGatewaySubscription}/providers/Microsoft.Authorization/roleDefinitions/${guid('/subscriptions/${appGatewaySubscription}', 'krakenkey-connector-appgateway')}'

// The connector's config, written to /etc/krakenkey-connector/config.yaml
// on the first boot. See the Configuration section of the connector README.
var connectorCertificates = [
  for cert in certificates: union(
    {
      id: int(cert.id)
      names: filter(map(split(string(cert.names), ','), name => trim(name)), name => !empty(name))
      key_store: {
        plugin: 'azure-keyvault'
        key_type: keyType
        vault: keyVaultName
        certificate_name: cert.keyVaultCertificateName
        exportable: keyExportable
      }
    },
    useAppGateway && !empty(cert.?appGatewaySslCertificate ?? '')
      ? {
          targets: [
            union(
              {
                label: 'app-gateway'
                plugin: 'azure-appgateway'
                subscription_id: appGatewaySubscription
                resource_group: appGatewayResourceGroup
                gateway: appGatewayName
                ssl_certificate: cert.appGatewaySslCertificate
              },
              empty(cert.?verifyHost ?? '') ? {} : { verify: { host: cert.verifyHost } }
            )
          ]
        }
      : {}
  )
]

var connectorConfig = {
  krakenkey: {
    api_url: apiUrl
  }
  check_interval: '6h'
  data_dir: '/var/lib/krakenkey-connector'
  plugins: union(
    {
      'azure-keyvault': {}
    },
    useAppGateway
      ? {
          'azure-appgateway': {
            call_timeout: '15m'
          }
        }
      : {}
  )
  certificates: connectorCertificates
}

var cloudInit = format(
  loadTextContent('cloud-init.yaml'),
  base64(loadTextContent('bootstrap.sh')),
  base64(enrollmentToken),
  base64(string(connectorConfig))
)

// Networking

resource natPublicIp 'Microsoft.Network/publicIPAddresses@2025-05-01' = if (useNatGateway) {
  name: '${vmName}-nat-ip'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
}

resource natGateway 'Microsoft.Network/natGateways@2025-05-01' = if (useNatGateway) {
  name: '${vmName}-nat'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    idleTimeoutInMinutes: 4
    publicIpAddresses: [
      {
        id: natPublicIp.id
      }
    ]
  }
}

// No security rules: the connector only makes outbound connections, and
// nothing needs to reach it. Azure's default rules still allow traffic from
// inside the virtual network, for SSH through Azure Bastion or a VPN.
resource nsg 'Microsoft.Network/networkSecurityGroups@2025-05-01' = {
  name: '${vmName}-nsg'
  location: location
  properties: {}
}

resource vnet 'Microsoft.Network/virtualNetworks@2025-05-01' = if (newNetwork) {
  name: virtualNetworkName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: virtualNetworkAddressPrefixes
    }
    subnets: [
      {
        name: subnetName
        properties: union(
          {
            addressPrefix: subnetAddressPrefix
            networkSecurityGroup: {
              id: nsg.id
            }
            defaultOutboundAccess: !useNatGateway
          },
          useNatGateway
            ? {
                natGateway: {
                  id: natGateway.id
                }
              }
            : {}
        )
      }
    ]
  }
}

var subnetId = newNetwork
  ? resourceId('Microsoft.Network/virtualNetworks/subnets', virtualNetworkName, subnetName)
  : resourceId(virtualNetworkResourceGroup, 'Microsoft.Network/virtualNetworks/subnets', virtualNetworkName, subnetName)

resource nic 'Microsoft.Network/networkInterfaces@2025-05-01' = {
  name: '${vmName}-nic'
  location: location
  dependsOn: [
    vnet
  ]
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: subnetId
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: nsg.id
    }
  }
}

// The VM

resource vm 'Microsoft.Compute/virtualMachines@2025-04-01' = {
  name: vmName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: 'ubuntu-24_04-lts'
        sku: 'server'
        version: 'latest'
      }
      osDisk: {
        name: '${vmName}-osdisk'
        createOption: 'FromImage'
        deleteOption: 'Delete'
        managedDisk: {
          storageAccountType: osDiskType
        }
      }
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      customData: base64(cloudInit)
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: adminSshPublicKey
            }
          ]
        }
        provisionVMAgent: true
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: {
            deleteOption: 'Delete'
          }
        }
      ]
    }
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
      }
    }
  }
}

// Access for the VM's managed identity

var deploymentSuffix = uniqueString(resourceGroup().id, vmName)

module roles 'modules/roles.bicep' = [
  for sub in roleSubscriptions: {
    name: 'kk-roles-${uniqueString(sub, deploymentSuffix)}'
    scope: subscription(sub)
    params: {
      keyVaultRoles: keyVaultUseRbac && sub == keyVaultSubscription
      appGatewayRole: useAppGateway && sub == appGatewaySubscription
      linkedResourcesRole: contains(linkedSubscriptions, sub)
    }
  }
]

module keyVaultAccess 'modules/keyvault-access.bicep' = {
  name: 'kk-keyvault-${deploymentSuffix}'
  scope: resourceGroup(keyVaultSubscription, keyVaultResourceGroup)
  dependsOn: [
    roles
  ]
  params: {
    vaultName: keyVaultName
    principalId: vm.identity.principalId
    useRbac: keyVaultUseRbac
    allowRollback: allowKeyVaultRollback
    keyVaultRoleId: keyVaultRoleId
    keyVaultRollbackRoleId: keyVaultRollbackRoleId
    appGatewayIdentityId: useAppGateway && grantAppGatewayVaultAccess ? appGatewayIdentityId : ''
  }
}

module appGatewayAccess 'modules/appgateway-access.bicep' = if (useAppGateway) {
  name: 'kk-appgw-${deploymentSuffix}'
  scope: resourceGroup(appGatewaySubscription, appGatewayResourceGroup)
  dependsOn: [
    roles
  ]
  params: {
    gatewayName: appGatewayName
    principalId: vm.identity.principalId
    roleId: appGatewayRoleId
  }
}

module linkedAccess 'modules/linked-resource-access.bicep' = [
  for (id, i) in appGatewayLinkedIds: {
    name: 'kk-appgw-linked-${i}-${deploymentSuffix}'
    scope: resourceGroup(split(id, '/')[2], split(id, '/')[4])
    dependsOn: [
      roles
    ]
    params: {
      resourceId: id
      principalId: vm.identity.principalId
      roleId: '/subscriptions/${split(id, '/')[2]}/providers/Microsoft.Authorization/roleDefinitions/${guid('/subscriptions/${split(id, '/')[2]}', 'krakenkey-connector-appgateway-linked')}'
    }
  }
]

// Customer usage attribution (see above). An empty deployment whose name
// carries the tracking id.
#disable-next-line no-deployments-resources
resource partnerAttribution 'Microsoft.Resources/deployments@2025-04-01' = if (partnerAttributionId != '00000000-0000-0000-0000-000000000000') {
  name: 'pid-${partnerAttributionId}'
  properties: {
    mode: 'Incremental'
    template: {
      '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
      contentVersion: '1.0.0.0'
      resources: []
    }
  }
}

@description('Name of the VM.')
output vmName string = vm.name

@description('Object id of the VM\'s managed identity, which the connector uses for Azure.')
output principalId string = vm.identity.principalId
