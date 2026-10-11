# azure-appgateway target plugin

A KrakenKey connector target that installs certificates on an Azure
Application Gateway v2. It points one of the gateway's SSL certificate
entries (`sslCertificates`) at a specific version of a Key Vault secret, the
one the `azure-keyvault` key store just completed.

Binary: `krakenkey-connector-plugin-azure-appgateway`.

Every connector release includes this plugin, in the container image and as
a release archive, with the connector's version. See
[Included plugins](../../README.md#included-plugins) for how to install it.

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
| `Validate` | Reads the gateway. Checks it is a v2 SKU, has a user-assigned managed identity, and has the configured SSL certificate entry. An entry holding an uploaded certificate is a problem unless `replace_uploaded_certificate` is set. A versionless secret ID on the entry is logged as a warning (see Rollback). |
| `Current` | Reads the entry's `publicCertData`, which the gateway fills in from the certificate it loaded, and returns the leaf's serial. Empty (meaning "cannot tell") when the entry is missing or the gateway reports no certificate data. |
| `Stage` | Checks that the key store's reference is a versioned Key Vault secret ID. Changes nothing. The staged ref is that ID. |
| `Activate` | Reads the gateway, sets the entry's `keyVaultSecretId` to the staged ID (dropping uploaded PFX data and password on that entry), and writes the gateway back once, with `If-Match` on the ETag it read. If someone else changed the gateway in between (HTTP 412), it reads again and retries, up to 3 times; if the entry itself changed in between it stops. It then waits for the update to finish. The previous ref records the entry's old `keyVaultSecretId`, exactly as it was, and the ID it installed. |
| `Rollback` | Checks that the entry still shows what `Activate` installed, then puts the old `keyVaultSecretId` back the same way. If someone changed the entry since, it refuses rather than overwrite that change. |
| `Discard` | Nothing to clean up; always succeeds. |

When an update fails in Azure, or the PUT gets no clear answer (a network
error, or a 408 or 5xx from the front door), the plugin reads the gateway
again and reports what it shows. If the failed update left the new secret ID
in the gateway model, `Activate` writes the old one back before returning the
error. If the update is still running when the call deadline approaches, the
plugin stops waiting with enough time left to read the gateway and report its
state, and returns a temporary error.

`Rollback` refuses (permanent error, and the new certificate stays) when
what was there before cannot be put back:

- the entry held a certificate uploaded to the gateway (Azure never returns
  uploaded certificates);
- the entry held a versionless ID of the same secret the key store writes
  to, which already resolves to the new version;
- the entry already pointed at the staged version when `Activate` first read
  it, so what was live before is unknown. This happens when an earlier
  activation finished in Azure after its call gave up.

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
- The SSL certificate entry already on the gateway and used by the HTTPS
  listeners. The plugin does not create entries: a new entry has no listener,
  so verification could never pass.
- A key store that hands over Key Vault secret IDs of certificates with
  exportable keys: the `azure-keyvault` plugin.

## Settings

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `subscription_id` | string (GUID) | required | Subscription that holds the gateway. |
| `resource_group` | string | required | The gateway's resource group. |
| `gateway` | string | required | Application Gateway name. |
| `ssl_certificate` | string | required | Name of the gateway's SSL certificate entry that the HTTPS listeners use. |
| `replace_uploaded_certificate` | bool | `false` | Allow the first activation to replace a certificate uploaded to the gateway (PFX data instead of a Key Vault reference). That activation cannot be rolled back. |

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
        ssl_certificate: app-example-com   # existing entry used by the HTTPS listener
        verify: { host: app.example.com, port: 443 }
```

Gateway updates usually take a few minutes. Set `call_timeout: 15m` on the
plugin; with the default 5 minutes a slow update is reported as still
running, and the connector works out what happened on a later pass.

## Credentials

The plugin uses the Azure SDK's `DefaultAzureCredential`, which tries, in
order: environment variables (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID` plus
`AZURE_CLIENT_SECRET` or `AZURE_CLIENT_CERTIFICATE_PATH`), workload identity
(AKS), managed identity (VM, App Service, Container Apps), then the Azure CLI,
Azure Developer CLI and Azure PowerShell logins. On Azure, use a managed
identity for the connector, and set `AZURE_TOKEN_CREDENTIALS=prod` to skip the
developer tool logins. If several user-assigned identities are attached to
the host, set `AZURE_CLIENT_ID` to the one to use.

The plugin inherits the connector's environment, and these variables decide
where it asks for tokens and where it sends them, so control them as you
would the credentials themselves:

- `AZURE_TOKEN_CREDENTIALS`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
  `AZURE_CLIENT_SECRET`, `AZURE_CLIENT_CERTIFICATE_PATH`,
  `AZURE_FEDERATED_TOKEN_FILE`: which identity is used.
- `AZURE_AUTHORITY_HOST`: where client credentials and workload identity
  tokens are requested.
- `IDENTITY_ENDPOINT`, `IDENTITY_HEADER`, `MSI_ENDPOINT`, `MSI_SECRET`,
  `IMDS_ENDPOINT`: where managed identity tokens are requested.
- `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`: proxies for all Azure traffic.
- `SSL_CERT_FILE`, `SSL_CERT_DIR`: which CAs are trusted for TLS to Azure.

Only Azure's public cloud is supported: Resource Manager at
`management.azure.com` and Key Vault secret IDs on `*.vault.azure.net`.

## Permissions

Updating a gateway is a full `PUT` of the gateway resource, so Azure checks
the caller's rights on the gateway and on the resources the gateway links to:
its subnet, public IP address, WAF policy and user-assigned identity. These
often live in different resource groups (for example a hub virtual network),
so least privilege takes two custom roles.

Gateway role, assigned on the gateway itself only:

```json
{
  "Name": "KrakenKey Application Gateway certificate writer",
  "IsCustom": true,
  "Description": "Read and update Application Gateways.",
  "Actions": [
    "Microsoft.Network/applicationGateways/read",
    "Microsoft.Network/applicationGateways/write"
  ],
  "NotActions": [],
  "DataActions": [],
  "NotDataActions": [],
  "AssignableScopes": ["/subscriptions/<subscription-id>/resourceGroups/<gateway-resource-group>"]
}
```

Linked resources role, assigned on the gateway's subnet, its public IP
address, its WAF policy (if any) and its user-assigned identity:

```json
{
  "Name": "KrakenKey Application Gateway linked resources",
  "IsCustom": true,
  "Description": "Let an Application Gateway update keep its subnet, public IP, WAF policy and identity.",
  "Actions": [
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
  "AssignableScopes": [
    "/subscriptions/<subscription-id>/resourceGroups/<gateway-resource-group>",
    "/subscriptions/<subscription-id>/resourceGroups/<network-resource-group>",
    "/subscriptions/<subscription-id>/resourceGroups/<identity-resource-group>"
  ]
}
```

`AssignableScopes` must list every resource group (or subscription) that
holds one of those resources. Assign each role at the narrowest scope: the
gateway role on the gateway resource, the linked resources role on each
linked resource. `Validate` and `Current` only need
`Microsoft.Network/applicationGateways/read`.

The built-in **Network Contributor** role covers the `Microsoft.Network`
actions but is much broader (every network resource in its scope), and it
does not include `userAssignedIdentities/assign/action`; add **Managed
Identity Operator** on the gateway's identity if you use it.

The connector's identity needs no Key Vault access for this plugin. The
gateway's own identity needs **Key Vault Secrets User** on the vault (see
Requirements).

When a permission is missing, Azure names the denied action and the plugin
reports it as a permanent failure. The connector still retries failed
targets with backoff, so it keeps failing the same way until the role or the
config is fixed.

Errors keep the HTTP status, Azure's error code and the denied action, but
not Azure's message, which names the caller's application and object ids,
its tenant and the subscription. Token errors keep the HTTP status and the
Microsoft Entra error code (`AADSTS...`). Ids and token issuer URLs are
removed from any other error text from the Azure SDK, so none of them reach
the connector's log or the status reported to KrakenKey.

## Limitations

- RSA keys only. Microsoft does not document ECDSA listener certificates for
  Application Gateway v2, so the plugin does not offer them.
- The gateway is read and written back through the Azure SDK's model
  (`armnetwork` v12, API version 2026-01-01). A gateway setting that model
  does not describe is not sent back on the PUT. Other SSL certificate
  entries that hold uploaded certificates are sent without their PFX data
  and password, which Azure never returns; the update relies on Azure
  keeping them as they are. That is how the Azure CLI and PowerShell update
  gateways too, but it has not been checked against a live gateway yet.
- Replacing an uploaded certificate needs `replace_uploaded_certificate:
  true`, and that activation cannot be rolled back.
- Pinning a secret version turns off the gateway's own four-hourly rotation
  for that entry. That is intended: the connector decides when a new version
  goes live.
- Infrastructure-as-code tools that manage the same gateway will see the
  certificate entry change; tell them to ignore
  `sslCertificates[*].keyVaultSecretId`.
- Every activation and rollback is a gateway update. Azure applies updates
  one update domain at a time and drains connections gracefully, but other
  changes to the gateway have to wait for it.
