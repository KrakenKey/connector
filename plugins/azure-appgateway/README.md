# azure-appgateway target plugin

A KrakenKey connector target that installs certificates on an Azure
Application Gateway v2. It points one of the gateway's SSL certificate
entries (`sslCertificates`) at a specific version of a Key Vault secret, the
one the `azure-keyvault` key store just completed.

Binary: `krakenkey-connector-plugin-azure-appgateway`.

## How it works

Application Gateway reads listener certificates from Key Vault with its own
managed identity. Microsoft documents that any change to the gateway makes it
check Key Vault again and present the new certificate right away; the
four-hourly Key Vault poll only matters for versionless secret IDs. This
plugin always sets a versioned secret ID, so:

- the new certificate goes live with the gateway update itself, not up to
  four hours later, and the connector can verify it;
- rolling back is pointing the entry at the previous version again.

The plugin never sees the private key. It only handles the Key Vault secret
ID (`KEY_FORMAT_VAULT_REF`).

| Call | What it does |
|------|--------------|
| `Describe` | Accepts `vault_ref` only. Needs an exportable key store (Application Gateway reads the PFX from the secret). Supports rollback. Key types `rsa-2048`, `rsa-3072`, `rsa-4096`. Default verify window 10 minutes. |
| `Validate` | Reads the gateway. Checks it is a v2 SKU, has a user-assigned managed identity, and has the configured SSL certificate entry (unless `create_if_missing`). |
| `Current` | Reads the entry's `publicCertData`, which the gateway fills in from the certificate it loaded, and returns the leaf's serial. Empty (meaning "cannot tell") when the entry is missing or the gateway reports no certificate data. |
| `Stage` | Checks that the key store's reference is a versioned Key Vault secret ID. Changes nothing. The staged ref is that ID. |
| `Activate` | Reads the gateway, sets the entry's `keyVaultSecretId` to the staged ID (dropping any uploaded PFX data and password on that entry), and writes the gateway back with `If-Match` on the ETag it read. If someone else changed the gateway in between (HTTP 412), it reads and tries again, up to 3 times. It then waits for the update to finish. The previous ref is the entry's old `keyVaultSecretId`, exactly as it was. |
| `Rollback` | Same update path, restoring the previous `keyVaultSecretId` (versioned or not), or removing the entry if `Activate` created it. |
| `Discard` | Nothing to clean up; always succeeds. |

When an update fails in Azure, the plugin reads the gateway again and reports
what it shows. If the failed update left the new secret ID in the gateway
model, `Activate` writes the old one back before returning the error. If the
update is still running when the call deadline approaches, the plugin stops
waiting with enough time left to read the gateway and report its state, and
returns a temporary error so the connector tries again on a later pass.

## Requirements

- An Application Gateway with a v2 SKU (`Standard_v2` or `WAF_v2`). Key
  Vault certificates are not supported on v1.
- A user-assigned managed identity on the gateway, with the **Key Vault
  Secrets User** role on the vault (or a "Get" secret permission if the vault
  uses access policies). This is part of setting up the gateway; the
  connector does not grant it.
- The vault reachable from the gateway (public access, trusted services, or a
  private endpoint with the `privatelink.vaultcore.azure.net` zone linked to
  the gateway's virtual network).
- A key store that hands over Key Vault secret IDs of certificates with
  exportable keys: the `azure-keyvault` plugin.

## Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `subscription_id` | string (GUID) | required | Subscription that holds the gateway. |
| `resource_group` | string | required | The gateway's resource group. |
| `gateway` | string | required | Application Gateway name. |
| `ssl_certificate` | string | required | Name of the gateway's SSL certificate entry that the HTTPS listeners use. |
| `create_if_missing` | bool | `false` | Add the entry on the first activation if the gateway does not have it. A listener still has to be pointed at it. |

Unknown keys are rejected.

## Example

```yaml
plugins:
  azure-keyvault: { version: 0.1.0, sha256: "<hex>" }
  azure-appgateway: { version: 0.1.0, sha256: "<hex>", call_timeout: 15m }

certificates:
  - id: 1043
    names: [app.example.com]
    key_store:
      plugin: azure-keyvault
      key_type: rsa-2048
      # key store settings: see the azure-keyvault README
    targets:
      - label: prod-agw
        plugin: azure-appgateway
        subscription_id: 00000000-0000-0000-0000-000000000000
        resource_group: rg-edge
        gateway: agw-prod
        ssl_certificate: app-example-com
        verify: { host: app.example.com, port: 443 }
```

Gateway updates usually take a few minutes. Set `call_timeout` on the plugin
to 15 minutes or so; with the default 5 minutes a slow update is reported as
still running and finished on a later pass.

## Credentials

The plugin uses the Azure SDK's `DefaultAzureCredential`, which tries, in
order: environment variables (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID` plus
`AZURE_CLIENT_SECRET` or `AZURE_CLIENT_CERTIFICATE_PATH`), workload identity
(AKS), managed identity (VM, App Service, Container Apps), then the Azure CLI,
Azure Developer CLI and Azure PowerShell logins. On Azure, use a managed
identity for the connector, and set `AZURE_TOKEN_CREDENTIALS=prod` to skip the
developer tool logins. If several user-assigned identities are attached to
the host, set `AZURE_CLIENT_ID` to the one to use. The plugin inherits the
connector's environment.

Only Azure's public cloud is supported for now.

## Permissions

Updating a gateway is a full `PUT` of the gateway resource, so Azure checks
the caller's rights on the gateway and on the resources the gateway links to:
its subnet, public IP address, WAF policy and user-assigned identity. A
least-privilege custom role:

```json
{
  "Name": "KrakenKey Application Gateway certificate operator",
  "IsCustom": true,
  "Description": "Point Application Gateway SSL certificates at Key Vault secret versions.",
  "Actions": [
    "Microsoft.Network/applicationGateways/read",
    "Microsoft.Network/applicationGateways/write",
    "Microsoft.Network/virtualNetworks/subnets/read",
    "Microsoft.Network/virtualNetworks/subnets/join/action",
    "Microsoft.Network/publicIPAddresses/read",
    "Microsoft.Network/publicIPAddresses/join/action",
    "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/read",
    "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/join/action",
    "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
  ],
  "NotActions": [],
  "DataActions": [],
  "NotDataActions": [],
  "AssignableScopes": ["/subscriptions/<subscription-id>/resourceGroups/<resource-group>"]
}
```

Assign it to the connector's identity on the gateway, the gateway's subnet,
its public IP address, its WAF policy (if any) and the gateway's
user-assigned identity, or once on the resource group if they all live
there. `Validate` and `Current` only need
`Microsoft.Network/applicationGateways/read`.

The built-in **Network Contributor** role covers the `Microsoft.Network`
actions but is much broader (every network resource in its scope), and it
does not include `userAssignedIdentities/assign/action`; add **Managed
Identity Operator** on the gateway's identity if you use it.

The connector's identity needs no Key Vault access for this plugin. The
gateway's own identity needs **Key Vault Secrets User** on the vault (see
Requirements).

When a permission is missing, Azure names the denied action and the plugin
reports it as a permanent failure, so the connector does not retry until the
config or the role changes.

## Limitations

- RSA keys only. Microsoft does not document ECDSA listener certificates for
  Application Gateway v2, so the plugin does not offer them.
- Rolling back to a certificate that was uploaded to the gateway directly
  (PFX data instead of a Key Vault reference) is not possible: Azure never
  returns uploaded certificate data. The first activation over such an entry
  works, but a rollback after it fails with a permanent error and the new
  certificate stays.
- Pinning a secret version turns off the gateway's own four-hourly rotation
  for that entry. That is intended: the connector decides when a new version
  goes live.
- The gateway is written back as the SDK models it (API version
  2026-01-01). Infrastructure-as-code tools that manage the same gateway will
  see the certificate entry change; tell them to ignore
  `sslCertificates[*].keyVaultSecretId`.
- Every activation and rollback is a gateway update. Azure applies updates
  one update domain at a time and drains connections gracefully, but other
  changes to the gateway have to wait for it.
