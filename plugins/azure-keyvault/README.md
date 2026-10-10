# azure-keyvault key store plugin

A key store plugin for the KrakenKey connector that keeps private keys and
certificates in [Azure Key Vault](https://learn.microsoft.com/azure/key-vault/certificates/about-certificates).

Key Vault generates the key pair and the CSR. The connector sends the CSR to
KrakenKey, then merges the issued certificate and its chain back into Key
Vault. The private key stays in the vault: the connector only sees it if the
certificate is exportable and a target asks for the key as PEM or PFX.
Targets that read from Key Vault themselves, such as Azure Application
Gateway, get a versioned secret id instead (`vault_ref`).

## How it works

| Connector call | What the plugin does in Key Vault |
|---|---|
| `Validate` | Checks the settings, then reads the certificate's policy. A missing certificate is fine (it is created on first issuance); a 403 fails with the permission to grant. |
| `CreateCSR` | Creates a new version of `certificate_name` with issuer `Unknown`, subject `CN=<first name>`, every name as a DNS SAN, content type `application/x-pkcs12`, and the key type, `exportable` and `reuse_key` settings. Returns the CSR of the pending request. |
| `PublicKey` | Reads the key from the pending request's CSR, or from the certificate of a completed version. |
| `Complete` | Merges the issued leaf and intermediates (x5c, leaf first) into the pending request. The result is a new certificate version. |
| `Export` | `vault_ref`: the versioned secret id `https://<vault>.vault.azure.net/secrets/<name>/<version>`. `pem` and `pfx`: reads that secret (exportable certificates only). |
| `Release` | Deletes a pending request that will not be completed. Completed versions are left alone. |

### Key references

The connector stores an opaque key reference per key. This plugin uses:

- Pending (after `CreateCSR`):
  `https://<vault>/certificates/<name>/pending?spki_sha256=<hex>`. Key Vault
  allows one pending request per certificate; the SHA-256 of the CSR's public
  key tells this request apart from a later one.
- Completed (after `Complete`): the certificate version id,
  `https://<vault>/certificates/<name>/<version>`. The matching secret id,
  which `Export` returns for `vault_ref`, is
  `https://<vault>/secrets/<name>/<version>`.

### Interrupted runs

If the connector stops between `CreateCSR` and saving its state, the request
it started stays pending in Key Vault. The next `CreateCSR` for that
certificate deletes it and starts a new one. The connector records a key
before it sends the CSR to KrakenKey, so a request it never recorded was
never sent; starting over is simpler and safer than checking whether the old
request matches the new names, key type and settings. A pending request with
an issuer other than `Unknown` was not started by the connector: the plugin
leaves it alone and reports an error.

If `Complete` merged the certificate but the connector did not record the
result, the next `Complete` finds the merged version and returns it instead
of failing.

### Renewal with the same key

KrakenKey can renew a certificate from the CSR it already has, so the new
certificate carries the same public key. The connector then calls `Complete`
with the current version. The plugin creates a new version with
`reuse_key: true`, which makes Key Vault sign the CSR with the latest
version's key, and merges the renewed certificate into it. This works for
keys that cannot be exported. If Key Vault does not reuse the key (for
example because the reference is not the latest version), the call fails and
nothing is left pending.

### Old versions

Each issuance adds a certificate version. `Release` does not delete completed
versions: Key Vault keeps every version as history, deletes versions only
together with the whole certificate, and some services may still point at an
older version. If your policy requires it, disable old versions yourself.
Deleting versions is out of scope for the plugin.

## Configuration

Settings go in the certificate's `key_store` block, next to `plugin` and
`key_type`:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `vault` | string | required | Vault name (`kv-prod-tls`, meaning `https://kv-prod-tls.vault.azure.net`) or the vault URL. Use the URL for other clouds, such as `https://kv-prod-tls.vault.azure.cn` or `https://kv-prod-tls.vault.usgovcloudapi.net`. |
| `certificate_name` | string | required | Name of the Key Vault certificate object (letters, digits and hyphens). Use one per KrakenKey certificate. It is created on first issuance. |
| `exportable` | bool | `true` | Whether Key Vault lets the private key be read. Application Gateway and App Service only accept exportable Key Vault certificates, so keep this `true` for them. Set `false` to keep the key in the vault for good; then only `vault_ref` export works. Applies to keys created after the change. |
| `reuse_key` | bool | `false` | Keep the same key pair for each new version instead of generating a new one. |

`key_type` is the connector's own setting:

| `key_type` | Key Vault key |
|---|---|
| `ecdsa-p256` | `EC`, curve `P-256` |
| `ecdsa-p384` | `EC`, curve `P-384` |
| `rsa-2048` | `RSA`, 2048 bits |
| `rsa-3072` | `RSA`, 3072 bits |
| `rsa-4096` | `RSA`, 4096 bits |

Wildcard names (`*.example.com`) are supported. The first name in `names`
becomes the subject common name.

### Example

```yaml
plugins:
  azure-keyvault: { version: 0.1.0, sha256: "<hex>", call_timeout: 5m }

certificates:
  # Key stays in Key Vault; Application Gateway reads it from there.
  - id: 1043
    names: ["*.example.com", example.com]
    key_store:
      plugin: azure-keyvault
      key_type: rsa-2048
      vault: kv-prod-tls
      certificate_name: wildcard-example-com
      exportable: true            # required by Application Gateway
    targets:
      - label: appgw-prod
        plugin: azure-appgateway
        # target settings: see the azure-appgateway plugin

  # Key Vault holds the key and the certificate; nginx gets PEM files.
  - id: 1044
    names: [api.example.com]
    key_store:
      plugin: azure-keyvault
      key_type: ecdsa-p256
      vault: https://kv-prod-tls.vault.azure.net
      certificate_name: api-example-com
    targets:
      - label: nginx
        plugin: file
        dir: /etc/nginx/tls/api
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

Set `AZURE_TOKEN_CREDENTIALS` (for example `ManagedIdentityCredential`) to
use one of them only. The plugin inherits the connector's environment, so
set these variables on the connector's service (systemd `Environment=`, or
the container's environment). Prefer managed or workload identity: no
secret to store or rotate.

The plugin talks only to the vault URL and to Microsoft Entra ID (or the
managed identity endpoint). It honors `HTTPS_PROXY` and `NO_PROXY`. Private
endpoints work as long as the vault name resolves to the private address.

## Permissions

Grant the connector's identity access to the vault. With Azure RBAC (the
default permission model for new vaults):

- **Key Vault Certificates Officer**, scoped to the vault. This covers every
  call except reading the private key.
- **Key Vault Secrets User**, scoped to the vault or to the certificate's
  secret, only if a target needs the key as PEM or PFX. Not needed for
  `vault_ref` targets such as Application Gateway (the gateway's own identity
  needs it instead).

For least privilege, a custom role with only these data actions:

```json
{
  "Name": "KrakenKey connector Key Vault key store",
  "IsCustom": true,
  "Description": "Create Key Vault certificates, merge issued certificates and read them for the KrakenKey connector.",
  "Actions": [],
  "NotActions": [],
  "DataActions": [
    "Microsoft.KeyVault/vaults/certificates/read",
    "Microsoft.KeyVault/vaults/certificates/create/action",
    "Microsoft.KeyVault/vaults/certificates/update/action",
    "Microsoft.KeyVault/vaults/secrets/getSecret/action"
  ],
  "NotDataActions": [],
  "AssignableScopes": ["/subscriptions/<subscription-id>/resourceGroups/<resource-group>"]
}
```

Assign it scoped to the vault. Drop `secrets/getSecret/action` if no target
needs PEM or PFX.

With vault access policies instead of RBAC: certificate permissions **Get**,
**Create** and **Update**; secret permission **Get** only for PEM or PFX
export.

| Call | Key Vault operation | RBAC data action | Access policy |
|---|---|---|---|
| `Validate` | Get certificate policy | `certificates/read` | certificates: Get |
| `CreateCSR` | Get and delete pending request, create certificate | `certificates/read`, `certificates/update/action`, `certificates/create/action` | certificates: Get, Update, Create |
| `PublicKey` | Get pending request or certificate | `certificates/read` | certificates: Get |
| `Complete` | Merge certificate (renewal with the same key also reads the policy and creates a version) | `certificates/create/action`, `certificates/read` | certificates: Create, Get |
| `Export` (`vault_ref`) | Get certificate | `certificates/read` | certificates: Get |
| `Export` (`pem`, `pfx`) | Get secret | `secrets/getSecret/action` | secrets: Get |
| `Release` | Get and delete pending request | `certificates/read`, `certificates/update/action` | certificates: Get, Update |

A 403 from Key Vault fails the call with the operation and the permission
to grant, for example `grant the identity
Microsoft.KeyVault/vaults/certificates/create/action on the vault (Azure
RBAC), or certificate permission Create in the vault access policy`.

## Errors

| Key Vault answer | Connector error kind |
|---|---|
| 400, 401, 403, other 4xx; no usable credential; 409 for a soft-deleted certificate | permanent (`FAILED_PRECONDITION`) |
| 404 | not found |
| 408, other 409, 429, 5xx; network errors and timeouts | unavailable, retried on a later pass |

The Azure SDK already retries throttling and server errors a few times
within a call, honoring `Retry-After`. Every call stops at the connector's
deadline (`call_timeout`; at most one minute for `Validate`, `PublicKey` and
`Release`). If Key Vault has not produced the CSR by then, `CreateCSR`
returns "unavailable" and the next pass starts over.

The plugin never logs keys, PFX data, secret values or tokens, and its error
messages do not include them.

## Limitations

- **Capabilities are per plugin, not per certificate.** The connector asks a
  plugin for its capabilities without any certificate settings, so this
  plugin always reports `exportable: true` and provides `vault_ref`, `pem`
  and `pfx`. For a certificate with `exportable: false`, `validate` cannot
  tell that a target needing PEM or PFX will not work; the first deployment
  fails at `Export` with a clear error. Pair such certificates only with
  targets that accept `vault_ref`.
- Keys are software-protected (`RSA`, `EC`). HSM-backed keys (`RSA-HSM`,
  `EC-HSM`, Premium vaults) are not offered yet. Managed HSM has no
  certificate objects and is not supported.
- Certificates whose policy names a Key Vault issuer (such as DigiCert or
  GlobalSign) are reported by `validate`, because the connector would replace
  that policy with issuer `Unknown`. Use a separate `certificate_name`.
- Changing `exportable` or `key_type` takes effect with the next key the
  connector creates.
- Key Vault's own expiry emails still follow the certificate's contacts and
  lifetime actions. Renewal is done by the connector, not by Key Vault.

## Building

Release archives for plugins are not published yet. To build from a clone of
the repository:

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
