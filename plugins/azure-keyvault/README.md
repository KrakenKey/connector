# azure-keyvault plugin

A KrakenKey connector plugin for
[Azure Key Vault](https://learn.microsoft.com/azure/key-vault/certificates/about-certificates).
It is two things in one binary:

- a **key store** that keeps private keys and certificates in Key Vault
  (this section and [How it works](#how-it-works)), and
- a **target** that deploys certificates to Key Vault certificates, so that
  services which read them without a version pick up each renewal (see
  [Target](#target)). When Key Vault is the key store, the certificate is
  deployed there already, and the connector adds that target by itself.

Key Vault generates the key pair and the CSR. The connector sends the CSR to
KrakenKey, then merges the issued certificate and its chain back into Key
Vault. The private key stays in the vault: the connector only sees it if the
certificate is exportable and a target asks for the key as PEM or PFX.
Targets that read from Key Vault themselves, such as Azure Application
Gateway, get a versioned secret id instead (`vault_ref`).

## How it works

| Connector call | What the plugin does in Key Vault |
|---|---|
| `Validate` | Checks the settings, then reads the certificate's policy and ownership tag. A missing certificate is fine (it is created on first issuance); a certificate the connector does not own, or a soft-deleted one, is reported; a 403 fails with the permission to grant. For exportable certificates it also checks that the identity may read secrets (see [Permissions](#permissions)). |
| `CreateCSR` | Checks [ownership](#ownership), then creates a new version of `certificate_name` with issuer `Unknown`, subject `CN=<first name of 64 characters or fewer>`, every name as a DNS SAN, content type `application/x-pkcs12`, the key type, `exportable` and `reuse_key` settings, and the ownership tag. Returns the CSR of the pending request. |
| `PublicKey` | Reads the key from the pending request's CSR, or from the certificate of a completed version. |
| `Complete` | Merges the issued leaf and intermediates (x5c, leaf first) into the pending request, with the ownership tag. The result is a new certificate version. |
| `Export` | `vault_ref`: the versioned secret id `https://<vault>.vault.azure.net/secrets/<name>/<version>`. `pem` and `pfx`: reads that secret (exportable certificates only). |
| `Release` | Deletes a pending request that will not be completed. Completed versions are left alone. |

### Key references

The connector stores an opaque key reference per key. This plugin uses:

- Pending (after `CreateCSR`):
  `https://<vault>/certificates/<name>/pending?certificate_id=<id>&spki_sha256=<hex>`.
  Key Vault allows one pending request per certificate; the SHA-256 of the
  CSR's public key tells this request apart from a later one.
  `certificate_id` is the KrakenKey certificate id, written into the ownership
  tag on `Complete`.
- Completed (after `Complete`): the certificate version id,
  `https://<vault>/certificates/<name>/<version>`. The matching secret id,
  which `Export` returns for `vault_ref`, is
  `https://<vault>/secrets/<name>/<version>`.

### Ownership

Every version the connector creates carries the tag
`krakenkey-connector-certificate-id=<KrakenKey certificate id>`. Before it
changes anything, `CreateCSR` reads the latest version of `certificate_name`:

- No certificate with that name: it is created.
- Latest version tagged with this KrakenKey certificate's id: the connector
  owns it and adds a version.
- No tag (created by hand, by a Key Vault issuer, or imported), or the tag of
  another KrakenKey certificate: the call fails and nothing is changed.
- A pending request but no version yet to read the tag from: the call fails,
  because the connector cannot tell who started the request.

Set `adopt: true` to take over such a certificate: the connector then
replaces its policy, deletes a pending `Unknown`-issuer request, and adds
tagged versions. `validate` reports each of these cases. Two connectors that
manage the same KrakenKey certificate with the same `certificate_name` still
share it (the tag holds the KrakenKey certificate id, not the connector);
give each connector its own `certificate_name` or vault.

### Interrupted runs

If the connector stops between `CreateCSR` and saving its state, the request
it started stays pending in Key Vault. The next `CreateCSR` for a
certificate the connector owns deletes it and starts a new one. The connector records a key
before it sends the CSR to KrakenKey, so a request it never recorded was
never sent; starting over is simpler and safer than checking whether the old
request matches the new names, key type and settings. A pending request with
an issuer other than `Unknown` was not started by the connector: the plugin
leaves it alone and reports an error. If this happens on the very first
issuance, there is no tagged version yet: delete the pending request in Key
Vault, or set `adopt: true` once.

If `Complete` merged the certificate but the connector did not record the
result, the next `Complete` finds the merged version and returns it instead
of failing.

### Renewal with the same key

KrakenKey can renew a certificate from the CSR it already has, so the new
certificate carries the same public key. The connector then calls `Complete`
with the current version. The plugin creates a new version with
`reuse_key: true`, which makes Key Vault sign the CSR with the latest
version's key, and merges the renewed certificate into it. This works for
keys that cannot be exported. The new version gets the tags of the version
it renews. If Key Vault does not reuse the key (for example because the
reference is not the latest version), the call fails and nothing is left
pending. If a request is already pending on the certificate (a renewal of the
connector's own in progress), the call returns "unavailable" and leaves that
request alone.

### Old versions

Each issuance, and each import by the [target](#target), adds a certificate
version. `Release` does not delete completed
versions: Key Vault keeps every version as history, deletes versions only
together with the whole certificate, and some services may still point at an
older version. Deleting versions is out of scope for the plugin.

If your policy requires it, you can disable old versions yourself, but only
versions that no target serves any more and that a rollback will not need.
A rollback deploys the previous certificate again and reads its secret; a
disabled version makes that fail (`this version is disabled in Key Vault`).

## Target

The target deploys a certificate to a Key Vault certificate as its latest
version. Services that reference the certificate without a version read the
latest enabled version on their own schedule (see
[When services pick up a new version](#when-services-pick-up-a-new-version)).

### The key store's own certificate (implicit target)

With `key_store: { plugin: azure-keyvault }` the connector merges every
issued certificate into `certificate_name` as a new version, so that
certificate is deployed the moment the key store completes it. The plugin
tells the connector so, and the connector adds an
[implicit target](../../README.md#implicit-targets) for it:

- It is labeled with the plugin's name from the `plugins` block (normally
  `azure-keyvault`), deployed before the other targets, and listed by
  `validate` as `implicit`.
- Its settings come from the key store: `vault`, `certificate_name`,
  `adopt` and `exportable`.
- `Stage` and `Activate` find the certificate in place and change nothing
  (no import, no secret read). The previous ref is the version that was the
  latest before it, so a rollback knows what to put back.
- Without a `verify` block it is reported as activated but not verified.
- A configured target with `plugin: azure-keyvault` and the key store's
  `vault` and `certificate_name` (in any spelling, for example the vault name
  or its URL) replaces the implicit target. Use one to add `verify` or
  `then`, or another label. Keep the label `azure-keyvault` to keep the
  target's deployment history.

**The new version is live before the other targets deploy.** The key store
merges the certificate when it is issued, so services that read the
certificate without a version can pick it up before the connector has
deployed to any other target, and whether or not those deployments
succeed. If that order matters, have those services pin a version (as the
[`azure-appgateway`](../azure-appgateway/README.md) target does), or use
another `certificate_name` for the key store and import into the
certificate the services read with a separate target.

### Other vaults and certificate names

A configured target for another vault, or another `certificate_name` in the
same vault, imports the certificate, its chain and its key as a new version
(PKCS#12, content type `application/x-pkcs12`, which Application Gateway,
App Service, Front Door and Azure CDN require). Use it to put the same
certificate in several vaults (regions, a disaster recovery vault, other
subscriptions), or in a vault when the key is kept somewhere else (the
built-in `local` key store).

It needs the private key:

- With the `azure-keyvault` key store, the connector hands over a vault
  reference and the plugin reads the key from the key store's secret
  itself, so the key does not pass through the connector. The key store
  needs `exportable: true`; `validate` refuses the pair otherwise.
- With the `local` key store, the connector hands over the key as PEM.

Before the first import into a certificate that already exists, the plugin
reads its latest version's ownership tag, with the same rules and `adopt`
setting as the key store (see [Ownership](#ownership)). Every imported
version carries the ownership tag and the configured `tags`.

### Target calls

| Connector call | What the plugin does in Key Vault |
|---|---|
| `Validate` | Checks the settings and reports the vault URL and certificate name as the deployment id. For a certificate other than the key store's own: reads the latest version's ownership tag, and checks for a soft-deleted certificate with that name. |
| `Current` | Reads the latest version and returns its serial number; nothing when there is none or it is disabled (versionless consumers cannot read a disabled version). |
| `Stage` | Reads the latest version. If it is the certificate being deployed, nothing else happens. Otherwise checks ownership, gets the key (reads the source secret for a vault reference), checks that it belongs to the certificate, and builds the PKCS#12 bundle in memory. |
| `Activate` | Certificate in place: lists the versions to find the one that was the latest before it. Otherwise imports the bundle as a new version and returns the serial of the version it replaced. A failed import leaves the latest version as it was; if the answer is lost, the plugin checks whether the version went in. |
| `Rollback` | Imports the previous certificate and its key again as a new latest version (see [Rollback](#rollback)). Does nothing if that certificate is already the latest version. |
| `Discard` | Drops the staged bundle from memory. |

Staged bundles live only in the plugin's memory, for at most an hour, and
are wiped after `Activate` or `Discard`.

### Rollback

Key Vault always serves the latest enabled version to versionless
consumers. It cannot make an older version current again, and disabling the
newer version does not help: consumers that ask for the latest version then
fail instead of falling back. So a rollback imports the previous certificate
and its key once more, as a new version. The connector hands them back
(`rollback_needs_material`):

| Case | Rollback |
|---|---|
| Key store's own certificate, `exportable: true` | The previous version's key is read from its secret and imported again with the previous certificate. |
| Key store's own certificate, `exportable: false` | Refused: the key cannot be read, so the previous certificate cannot be imported again. `validate` warns that rollback is unavailable; a failed deployment keeps the new version and is reported as failed. |
| Another certificate, `azure-keyvault` key store | As for the key store's own certificate (the key store must be exportable for this target at all). |
| Another certificate, `local` key store | The previous key is handed over as PEM and imported again. |
| First deployment (no earlier version) | Refused: Key Vault cannot delete a single version, so the new version stays. |

The plugin reports `propagates_async`: services pick up a new version on
their own schedule, so a failed `verify` check is reported, not rolled back.
A rollback happens when a `then` command fails, or when the connector finds
an interrupted deployment of an older certificate. Rolling back on every
failed check would import the old certificate again while services may
already have picked up the new one.

### Target configuration

| Key | Type | Default | Meaning |
|---|---|---|---|
| `vault` | string | required | Vault name or URL, as for the key store. |
| `certificate_name` | string | required | Key Vault certificate to deploy to. Created by the first import. |
| `adopt` | bool | `false` | Let the connector add versions to a certificate it did not create. See [Ownership](#ownership). |
| `exportable` | bool | `true` | Whether the private key of imported versions can be read from their secret. Application Gateway, App Service and Front Door need it. |
| `tags` | map | none | Extra tags on every imported version (at most 14; `krakenkey-connector-certificate-id` is set by the connector). |

For the implicit target, all of these come from the key store's settings.

### When services pick up a new version

What Microsoft documents for services that reference a Key Vault
certificate without a version:

| Service | Picks up a new version | Faster |
|---|---|---|
| [Application Gateway v2](https://learn.microsoft.com/azure/application-gateway/key-vault-certs) | polls every 4 hours | any change to the gateway (for example a tag) makes it check at once |
| [App Service and Functions](https://learn.microsoft.com/azure/app-service/configure-ssl-certificate) | within 24 hours | **Sync** on the imported certificate in the portal |
| [Container Apps](https://learn.microsoft.com/azure/container-apps/key-vault-certificates-manage) | up to 12 hours | not documented |
| [API Management custom domains](https://learn.microsoft.com/azure/api-management/configure-custom-domain) | up to 1-2 days | **Sync certificates** in the portal |
| [API Management named values](https://learn.microsoft.com/azure/api-management/api-management-howto-properties) | within 4 hours | refresh in the portal or through the management REST API |
| [Front Door Standard/Premium](https://learn.microsoft.com/azure/frontdoor/domain), version **Latest** | up to 72 hours | not documented |
| [Azure CDN](https://learn.microsoft.com/azure/cdn/cdn-custom-ssl) (Standard Microsoft) | up to 72 hours | not documented |
| [AKS Secrets Store CSI driver](https://learn.microsoft.com/azure/aks/csi-secrets-store-configuration-options) | every 2 minutes, once rotation is enabled (`--enable-secret-rotation`; off by default) | `--rotation-poll-interval` |
| [VM Key Vault extension](https://learn.microsoft.com/azure/virtual-machines/extensions/key-vault-linux) | every hour by default (`pollingIntervalInS`, 5 to 60 minutes) | restart the extension's service |

The connector's `verify` check keeps the pass waiting until the endpoint
serves the new certificate or the window ends, and other certificates wait
with it. So:

- For services that take hours or days, leave out `verify`. The target is
  reported as activated but not verified (`activated_unverifiable`), and
  KrakenKey's own endpoint monitoring can watch the endpoint instead.
- For services that poll within minutes (the CSI driver with rotation, the
  VM extension with a short interval), add `verify` with a window a little
  longer than the poll interval, for example `window: 10m` for a 2 minute
  rotation interval.
- To verify a slow service, make it pick up the version in a `then`
  command (for example a change to the Application Gateway, or a sync of
  the App Service certificate), and verify with a short window.

A failed check on this target is reported, not rolled back (see
[Rollback](#rollback)).

### Target permissions

| Call | Key Vault operation | RBAC data action | Access policy |
|---|---|---|---|
| `Validate` (other certificates) | Get the latest version; for a missing certificate, check for a soft-deleted one | `certificates/read` | certificates: Get |
| `Current` | Get the latest version | `certificates/read` | certificates: Get |
| `Stage` | Get the latest version; for an import, read the source secret when given a vault reference | `certificates/read`; `secrets/getSecret/action` on the key store's vault | certificates: Get; secrets: Get on the key store's vault |
| `Activate` | List versions (certificate in place), or import | `certificates/read`, `certificates/import/action` | certificates: Get, List, Import |
| `Rollback` | Get the latest version, read the previous version's secret, import | `certificates/read`, `certificates/import/action`, `secrets/getSecret/action` | certificates: Get, Import; secrets: Get |

For the implicit target alone (no rollback), `certificates/read` is enough;
with access policies, add certificate permission **List**. Without it the
deployment still succeeds, but the plugin cannot tell which version was
live before, so that deployment cannot be rolled back (logged as a
warning). Rollback adds `certificates/import/action` and
`secrets/getSecret/action`.

For other certificates, grant `certificates/read` and
`certificates/import/action` on the destination vault (or scoped to the
certificate once it exists), and `secrets/getSecret/action` on the key
store's vault. With the `local` key store, no secret permission is needed.

A 403 names the operation and the permission to grant, as for the key
store.

## Configuration

Settings go in the certificate's `key_store` block, next to `plugin` and
`key_type`:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `vault` | string | required | Vault name (`kv-prod-tls`, meaning `https://kv-prod-tls.vault.azure.net`) or the vault URL. Use the URL for other clouds, such as `https://kv-prod-tls.vault.azure.cn` or `https://kv-prod-tls.vault.usgovcloudapi.net`. |
| `certificate_name` | string | required | Name of the Key Vault certificate object (letters, digits and hyphens). Use one per KrakenKey certificate. It is created on first issuance. |
| `exportable` | bool | `true` | Whether Key Vault lets the private key be read. See [Exportable keys](#exportable-keys). Applies to keys created after the change. |
| `reuse_key` | bool | `false` | Keep the same key pair for each new version instead of generating a new one. |
| `adopt` | bool | `false` | Let the connector take over a certificate it did not create. See [Ownership](#ownership). |

`key_type` is the connector's own setting:

| `key_type` | Key Vault key |
|---|---|
| `ecdsa-p256` | `EC`, curve `P-256` |
| `ecdsa-p384` | `EC`, curve `P-384` |
| `rsa-2048` | `RSA`, 2048 bits |
| `rsa-3072` | `RSA`, 3072 bits |
| `rsa-4096` | `RSA`, 4096 bits |

Wildcard names (`*.example.com`) are supported. The first name in `names`
of 64 characters or fewer becomes the subject common name; if every name is
longer, the CSR has no common name and lists the names as SANs only (clients
match SANs, not the common name).

### Exportable keys

The default, `exportable: true`, is a trade-off. Application Gateway and App
Service only accept exportable Key Vault certificates, because they read the
key from the certificate's secret themselves, so they need it. It also means
anyone allowed to read the secret (`secrets/getSecret/action`, or secret
permission Get) can take a copy of the private key. With
`exportable: false` the key never leaves Key Vault, but only targets that
use the key inside Azure through a vault reference can work, and Application
Gateway and App Service cannot.

### Example

```yaml
plugins:
  azure-keyvault: {}   # the bundled version; see the connector README

certificates:
  # Key Vault only. App Service and Front Door read the certificate without a
  # version; the connector adds the implicit target "azure-keyvault" and
  # reports it as activated but not verified.
  - id: 1042
    names: [www.example.com]
    key_store:
      plugin: azure-keyvault
      key_type: rsa-2048
      vault: kv-prod-tls
      certificate_name: www-example-com

  # The same, verified: a configured target for the key store's own
  # certificate replaces the implicit one. An AKS cluster reads it through the
  # Secrets Store CSI driver with a 2 minute rotation interval.
  - id: 1043
    names: [api.example.com]
    key_store:
      plugin: azure-keyvault
      key_type: ecdsa-p256
      vault: kv-prod-tls
      certificate_name: api-example-com
    targets:
      - label: azure-keyvault
        plugin: azure-keyvault
        vault: https://kv-prod-tls.vault.azure.net
        certificate_name: api-example-com
        verify: { host: api.example.com, window: 10m }

  # One certificate in several vaults: the key lives in the primary vault
  # (exportable, so it can be copied), and the target imports it into a
  # second region's vault and a vault in another subscription. Application
  # Gateway reads a pinned version from the primary vault.
  - id: 1044
    names: ["*.example.com", example.com]
    key_store:
      plugin: azure-keyvault
      key_type: rsa-2048
      vault: kv-prod-tls
      certificate_name: wildcard-example-com
      exportable: true
    targets:
      - label: kv-westeurope
        plugin: azure-keyvault
        vault: kv-prod-tls-weu
        certificate_name: wildcard-example-com
        tags: { site: westeurope }
      - label: kv-dr
        plugin: azure-keyvault
        vault: kv-dr-tls
        certificate_name: wildcard-example-com
      - label: appgw-prod
        plugin: azure-appgateway
        # target settings: see the azure-appgateway plugin

  # Key on the host (local key store), certificate imported into Key Vault
  # for services there, and written to files for nginx.
  - id: 1045
    names: [internal.example.com]
    targets:
      - label: kv
        plugin: azure-keyvault
        vault: kv-prod-tls
        certificate_name: internal-example-com
      - label: nginx
        plugin: file
        dir: /etc/nginx/tls/internal
        files: { cert: cert.pem, chain: chain.pem, fullchain: fullchain.pem, key: key.pem }
        then: { exec: [systemctl, reload, nginx] }
```

## Credentials

The plugin uses the Azure SDK's
[`DefaultAzureCredential`](https://learn.microsoft.com/azure/developer/go/sdk/authentication/credential-chains#defaultazurecredential-overview),
which tries, in order:

1. Environment: a service principal from `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`
   and `AZURE_CLIENT_SECRET` (or `AZURE_CLIENT_CERTIFICATE_PATH`).
2. Workload identity: `AZURE_FEDERATED_TOKEN_FILE`, as set up by AKS
   workload identity.
3. Managed identity of the VM, container or App Service the connector runs
   on. For a user-assigned identity, set `AZURE_CLIENT_ID` to its client id.
4. Azure CLI and Azure Developer CLI logins, useful on a workstation.

Set `AZURE_TOKEN_CREDENTIALS` to use one of them only. On Azure VMs and
containers with a managed identity, set
`AZURE_TOKEN_CREDENTIALS=ManagedIdentityCredential`: without it, a slow
instance metadata endpoint can make the chain give up and report "no usable
Azure credential". The plugin inherits the connector's environment, so set
these variables on the connector's service (systemd `Environment=`, or the
container's environment). Prefer managed or workload identity: no secret to
store or rotate.

The plugin talks only to the vault URL and to Microsoft Entra ID (or the
managed identity endpoint). It honors `HTTPS_PROXY` and `NO_PROXY`. Private
endpoints work as long as the vault name resolves to the private address.

**Trust note.** These environment variables decide where the plugin sends
credentials and tokens, and which servers it trusts. Anyone who can set the
connector's environment controls them, so treat them like the connector's
configuration:

- `AZURE_AUTHORITY_HOST`: the Entra ID host that receives client secrets and
  assertions.
- `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`,
  `AZURE_CLIENT_CERTIFICATE_PATH`, `AZURE_CLIENT_CERTIFICATE_PASSWORD`,
  `AZURE_FEDERATED_TOKEN_FILE`: the identity used.
- `IDENTITY_ENDPOINT`, `IDENTITY_HEADER`, `MSI_ENDPOINT`, `MSI_SECRET`,
  `IMDS_ENDPOINT`: where managed identity tokens come from.
- `AZURE_TOKEN_CREDENTIALS`: which credentials the chain tries.
- `AZURE_CONFIG_DIR`: the Azure CLI login the CLI credential uses.
- `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`: a proxy sees every connection's
  host name, and its TLS traffic if the proxy is also trusted as a CA.
- `SSL_CERT_FILE`, `SSL_CERT_DIR`: the CA certificates trusted for the vault
  and Entra ID.

## Permissions

With Azure RBAC (the default permission model for new vaults), give the
connector's identity a custom role with only these data actions:

```json
{
  "Name": "KrakenKey connector Key Vault",
  "IsCustom": true,
  "Description": "Create, merge, import and read Key Vault certificates for the KrakenKey connector.",
  "Actions": [],
  "NotActions": [],
  "DataActions": [
    "Microsoft.KeyVault/vaults/certificates/read",
    "Microsoft.KeyVault/vaults/certificates/create/action",
    "Microsoft.KeyVault/vaults/certificates/update/action",
    "Microsoft.KeyVault/vaults/certificates/import/action",
    "Microsoft.KeyVault/vaults/secrets/getSecret/action"
  ],
  "NotDataActions": [],
  "AssignableScopes": ["/subscriptions/<subscription-id>/resourceGroups/<resource-group>"]
}
```

Drop `certificates/import/action` if no target imports certificates (the
implicit target alone does not, unless it rolls back; see
[Target permissions](#target-permissions)). Drop
`secrets/getSecret/action` if no target needs the key as PEM or PFX, nor
imports it into another certificate, nor rolls back;
`vault_ref` targets such as Application Gateway do not (the gateway's own
identity reads the secret instead). Assign the role scoped to the vault, or
narrower: Key Vault RBAC assignments can be scoped to a single certificate
(`<vault resource id>/certificates/<certificate_name>`) and its secret
(`<vault resource id>/secrets/<certificate_name>`) once they exist, so for the
first issuance either scope it to the vault or create the certificate first.

The built-in **Key Vault Certificates Officer** role (plus **Key Vault
Secrets User** for PEM or PFX export) also works, but is much broader: it
allows deleting, purging, importing, backing up and restoring certificates
and managing certificate issuers and contacts.

With vault access policies instead of RBAC: certificate permissions **Get**,
**Create** and **Update** for the key store, plus **List** and **Import** for
the target; secret permission **Get** only for PEM or PFX export, imports
from this vault into another certificate, and rollbacks. Access policies
apply to the whole vault.

| Call | Key Vault operation | RBAC data action | Access policy |
|---|---|---|---|
| `Validate` | Get certificate policy, latest version and pending request; for exportable certificates, get a secret version that does not exist (a 404 or 403 tells whether secrets can be read, without reading one); for a missing certificate, check for a soft-deleted one (skipped without permission) | `certificates/read`, `secrets/getSecret/action` (optional) | certificates: Get, secrets: Get (optional) |
| `CreateCSR` | Get latest version (ownership tag), get and delete pending request, create certificate | `certificates/read`, `certificates/update/action`, `certificates/create/action` | certificates: Get, Update, Create |
| `PublicKey` | Get pending request or certificate | `certificates/read` | certificates: Get |
| `Complete` | Merge certificate (renewal with the same key also reads the policy and creates a version) | `certificates/create/action`, `certificates/read` | certificates: Create, Get |
| `Export` (`vault_ref`) | Get certificate | `certificates/read` | certificates: Get |
| `Export` (`pem`, `pfx`) | Get secret | `secrets/getSecret/action` | secrets: Get |
| `Release` | Get and delete pending request | `certificates/read`, `certificates/update/action` | certificates: Get, Update |

A 403 from Key Vault fails the call with the operation and the permission
to grant, for example `grant the identity
Microsoft.KeyVault/vaults/certificates/create/action on the vault (Azure
RBAC), or certificate permission Create in the vault access policy`.

If the identity cannot read secrets but the certificate is exportable,
`validate` does not fail, because Application Gateway and App Service need
exportable certificates without the connector reading them. The plugin logs
a warning instead, and `Export` as PEM or PFX fails with the permission to
grant.

## Errors

| Key Vault answer | Connector error kind |
|---|---|
| 400, 401, 403, other 4xx; no usable credential; a soft-deleted certificate (`ObjectIsDeletedButRecoverable`); a disabled version (`SecretDisabled`, `CertificateDisabled`) | permanent (`FAILED_PRECONDITION`) |
| 404 | not found |
| 408, other 409, 429, 5xx; network errors and timeouts | unavailable |

The kind tells the connector and the reader what went wrong; it does not stop
retries. The connector retries failed key store and target steps on later
passes with backoff, whatever the kind, so fix the cause (a permission, a
disabled version) and the next pass picks it up.

The Azure SDK already retries throttling and server errors a few times
within a call, honoring `Retry-After`. Every call stops at the connector's
deadline (`call_timeout`; at most one minute for `Validate`, `PublicKey` and
`Release`). If Key Vault has not produced the CSR by then, `CreateCSR`
returns "unavailable" and the next pass starts over.

The plugin never logs keys, PFX data, secret values or tokens, and its error
messages do not include them.

## Limitations

- `Describe` has no certificate settings, so it reports exportable keys.
  The capabilities for each certificate's settings come from `Validate`
  (`exportable: false` reports keys that cannot be exported), so `validate`
  refuses a target that needs the key, such as Application Gateway or
  another Key Vault certificate, for such a certificate.
- Keys are software-protected (`RSA`, `EC`). HSM-backed keys (`RSA-HSM`,
  `EC-HSM`, Premium vaults) are not offered yet. Managed HSM has no
  certificate objects and is not supported.
- Certificates whose policy names a Key Vault issuer (such as DigiCert or
  GlobalSign) are reported by `validate`, because the connector would replace
  that policy with issuer `Unknown`. Use a separate `certificate_name`.
- The ownership tag names the KrakenKey certificate, not the connector
  install, so it cannot tell two connectors managing the same KrakenKey
  certificate apart.
- Changing `exportable` or `key_type` takes effect with the next key the
  connector creates.
- Key Vault's own expiry emails still follow the certificate's contacts and
  lifetime actions. Renewal is done by the connector, not by Key Vault.

## Building

Every connector release includes this plugin, in the container image and as
a release archive; see [Included plugins](../../README.md#included-plugins).
To build it from a clone of the repository instead:

```sh
cd plugins/azure-keyvault
CGO_ENABLED=0 go build -trimpath -o krakenkey-connector-plugin-azure-keyvault \
  ./cmd/krakenkey-connector-plugin-azure-keyvault
sha256sum krakenkey-connector-plugin-azure-keyvault
```

Install it as
`<data_dir>/plugins/azure-keyvault/<version>/krakenkey-connector-plugin-azure-keyvault`
and put the checksum in the `plugins` block, or point `path` at it. See
[External plugins](../../README.md#external-plugins) for the ownership and
permission rules.

## Tests

```sh
cd plugins/azure-keyvault
go test ./... -race
```

The tests run against an in-memory fake of the Key Vault REST API
(`internal/fakevault`) and never contact Azure. One test builds the plugin
binary and drives it through the connector's plugin client over gRPC, with
the fake reached through a local HTTPS proxy and a fake managed identity
endpoint.
