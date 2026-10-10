# KrakenKey Connector

A service you run on your own infrastructure that renews
[KrakenKey](https://krakenkey.io) certificates and deploys them to your
systems: files for nginx or HAProxy, a command of your choice, and through
plugins, places such as key vaults and cloud load balancers.

> **Status:** pre-release (v0). The configuration, the plugin protocol and
> parts of the KrakenKey API it uses are still changing. Expect breaking
> changes before v1.

## How it works

- **Outbound only.** The connector calls the KrakenKey API over HTTPS. Nothing
  connects to it, and it opens no ports.
- **Keys stay with you.** For each renewal the connector's key store creates a
  new private key and a CSR. Only the CSR goes to KrakenKey. The key never
  leaves your machine (or your vault, with a vault key store plugin).
- **Checked before deployed.** When the certificate is issued, the connector
  checks that it carries the key store's public key and exactly the names in
  your config. If not, nothing is deployed.
- **Deployed one target at a time, then verified.** Each target is staged,
  activated, and then verified with a TLS handshake against the endpoint you
  configure: the served leaf must have the new serial number and public key,
  and its chain must validate. If verification fails, that target is rolled
  back to its previous certificate. Other targets are not affected.
- **Old keys are kept until they are no longer needed.** The previous key is
  deleted only after every target serves the new certificate, so a rollback
  always has something to go back to.
- **Plugins.** Key stores and targets are plugins: separate executables that
  the connector runs and talks to over gRPC, using
  [hashicorp/go-plugin](https://github.com/hashicorp/go-plugin), the same model
  Terraform uses for providers. A few common ones are built in.

### Trust boundary

- KrakenKey sees the CSR, the issued certificate and the certificate id. It
  never sees private keys or credentials for your systems.
- The connector holds private keys and the access needed to deploy (file
  permissions, vault credentials). Run it where that access already lives.
- The API key (`KK_API_KEY`) only needs access to the certificates the
  connector manages. It is read from the environment once, removed from the
  environment before any plugin or command starts, and never logged.
- Plugins run with the connector's permissions. Only install plugins you
  trust; pin their checksum with `sha256` in the config.

## Quick start

1. Create an API key in the KrakenKey dashboard.
2. Write `/etc/krakenkey-connector/config.yaml`:

   ```yaml
   krakenkey:
     api_url: https://api.krakenkey.io
   check_interval: 6h
   data_dir: /var/lib/krakenkey-connector
   audit_log: /var/log/krakenkey-connector/audit.jsonl
   certificates:
     - id: 1043                     # KrakenKey certificate id
       names: [api.example.com]     # must match the certificate's names
       key_store: { plugin: local, key_type: ecdsa-p256 }
       targets:
         - label: example-nginx
           plugin: file
           dir: /etc/nginx/tls/api
           files: { cert: cert.pem, chain: chain.pem, fullchain: fullchain.pem, key: key.pem }
           owner: "root:nginx"
           mode: "0640"
           then: { exec: [systemctl, reload, nginx] }
           verify: { host: api.example.com, port: 443, window: 10m }
   ```

3. Check it. `validate` loads the config, starts the plugins, checks that each
   key store and target can work together, asks KrakenKey about each
   certificate, and exits non-zero if anything is wrong:

   ```sh
   export KK_API_KEY=kk_...
   krakenkey-connector validate --config /etc/krakenkey-connector/config.yaml
   ```

4. Run a single pass, for example from cron or a systemd timer:

   ```sh
   krakenkey-connector run --once --config /etc/krakenkey-connector/config.yaml
   ```

   Or keep it running and let it check every `check_interval`:

   ```sh
   krakenkey-connector run --config /etc/krakenkey-connector/config.yaml
   ```

**First run:** a certificate issued before the connector managed it was made
with a key the connector does not have. On its first pass the connector
renews each certificate once so that it holds the key, then deploys it.
After that it renews when KrakenKey says the certificate is due
(`renewAfter`), or 30 days before expiry if the API does not say.

To renew now, regardless of the schedule (for example to test a new target):

```sh
krakenkey-connector run --once --force --cert 1043
```

## Commands

| Command | What it does |
|---------|--------------|
| `run` | Run a pass now, then every `check_interval`, until stopped. |
| `run --once` | Run a single pass and exit. Exit code 0 if every certificate and target succeeded. |
| `run --once --force [--cert ID]` | Renew even if not due; `--cert` limits the pass to one configured certificate. |
| `validate [--offline]` | Check config, plugins, capabilities and (unless `--offline`) the API, then exit. |
| `version` | Print the version. |

Common flags: `--config` (default `/etc/krakenkey-connector/config.yaml`, or
`KK_CONNECTOR_CONFIG`), `--log-format text|json`, `--log-level
debug|info|warn|error`. Logs go to stderr.

Exit codes: `0` success, `1` a certificate or target failed, `2` usage or
config error (including a missing `KK_API_KEY`), `3` the API rejected the key.
After a `401` the connector stops calling the API; a bad key would otherwise
get locked out. On a `429` it waits for `Retry-After` before trying again.

Only one connector process can use a data directory at a time.

## Configuration

| Key | Default | Meaning |
|-----|---------|---------|
| `krakenkey.api_url` | `https://api.krakenkey.io` | API base URL. `KK_API_URL` overrides it. |
| `check_interval` | `6h` | Time between passes in `run` mode (minimum `1m`). |
| `data_dir` | `/var/lib/krakenkey-connector` | Keys, state and plugin binaries. Must be mode `0700`. |
| `audit_log` | `<data_dir>/audit.jsonl` | Audit log, one JSON object per line. |
| `plugins` | | External plugins, by name. See [Plugins](#external-plugins). |
| `certificates[].id` | | KrakenKey certificate id. |
| `certificates[].names` | | DNS names. Must equal the certificate's names. |
| `certificates[].key_store.plugin` | `local` | Key store plugin. |
| `certificates[].key_store.key_type` | `ecdsa-p256` | `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-3072` (and `rsa-4096` for plugins that support it). |
| `certificates[].targets[].label` | | Name for logs and the audit log. Unique per certificate. |
| `certificates[].targets[].plugin` | | `file`, `exec`, or an external plugin. |
| `certificates[].targets[].then.exec` | | Command run after activation and again after a rollback, such as a reload. No shell. |
| `certificates[].targets[].then.timeout` | `2m` | Timeout for the `then` command. |
| `certificates[].targets[].verify` | | How to check the deployment. See below. |

Any other keys in a `key_store` or target block are settings for that plugin.

### Verify

```yaml
verify:
  host: api.example.com      # SNI name, and the name the certificate must be valid for
  address: 127.0.0.1:8443    # where to connect; default host:port
  port: 443                  # used when address is not set
  window: 10m                # how long to keep trying; default from the target, else 10m
  ca_file: /etc/ssl/staging-roots.pem   # trust only these roots for the chain
  skip_chain_validation: false
```

The connector connects to `address` (or `host:port`), sends `host` as SNI, and
keeps trying with growing delays until the endpoint serves a leaf with the
new certificate's serial number and public key, or the window ends. It then
validates the served chain for `host` against the system roots, or only the
roots in `ca_file`. A chain that does not validate fails the deployment at
once.

`skip_chain_validation: true` turns the chain check off (for example with a
test CA whose roots you do not have). The leaf is still compared. The
connector logs a warning on every deployment that skips it, and `validate`
lists it.

A target without a `verify` block is activated without any check. `validate`
warns about it.

### Built-in key store: `local`

Generates keys in process and stores them as PKCS#8 PEM files under
`<data_dir>/keys/<certificate id>/`, files `0600` in `0700` directories. The
connector refuses to start if the data directory, a key directory or a key
file allows access by group or others. It has no settings.

### Built-in target: `file`

```yaml
- label: web
  plugin: file
  dir: /etc/nginx/tls/api            # must exist
  files: { cert: cert.pem, chain: chain.pem, fullchain: fullchain.pem, key: key.pem }
  owner: "root:nginx"                # optional: user, user:group or :group
  mode: "0640"                       # optional key file mode; default 0600
```

`key` is required, and so is `cert` or `fullchain`. Each file is written to a
temporary file in the same directory and renamed into place, so readers never
see a partial file. Before that, the current files are saved in
`<dir>/.krakenkey-previous/` (the last two sets are kept) for rollback.
Certificate files get mode `0644`. The key mode must not give access to other
users. Quote the mode so YAML keeps it as a string.

### Built-in target: `exec`

```yaml
- label: hook
  plugin: exec
  command: [/usr/local/bin/install-cert]   # no shell
  timeout: 5m                              # optional
  env: { SERVICE: api }                    # optional
```

Writes the certificate, chain, full chain and key to a new directory under
`<data_dir>/exec/` and runs the command with `KK_ACTION=deploy`,
`KK_CERT_FILE`, `KK_CHAIN_FILE`, `KK_FULLCHAIN_FILE`, `KK_KEY_FILE`,
`KK_CERT_SERIAL`, `KK_CERT_ID` and `KK_TARGET_LABEL`. A non-zero exit fails
the deployment, and the command is run again with the previous files and
`KK_ACTION=rollback`.

### External plugins

```yaml
plugins:
  azure-keyvault: { version: 0.1.0, sha256: "<hex>" }
```

The connector looks for the plugin at
`<data_dir>/plugins/<name>/<version>/krakenkey-connector-plugin-<name>`, or at
`path` if set. It refuses binaries that group or others can write. With
`sha256`, it checks the binary's checksum before starting it.

### Audit log

Every step that changes something is appended to `audit_log` and synced to
disk before the connector moves on: run id, certificate id, target label,
step, result, old and new serial, error, time, and for `activate`, the
target's reference to what was live before (what a rollback needs). The audit
log never contains key material.

## Docker

```sh
docker build -t krakenkey-connector .
docker run -d --name krakenkey-connector \
  -e KK_API_KEY=kk_... \
  -v /etc/krakenkey-connector:/etc/krakenkey-connector:ro \
  -v krakenkey-connector-data:/var/lib/krakenkey-connector \
  -v /etc/nginx/tls:/etc/nginx/tls \
  krakenkey-connector
```

The image runs as a non-root user (uid 10001). Give that user write access to
the target directories you mount.

## Building from source

Requires Go 1.26.

```sh
go build -o krakenkey-connector ./cmd/krakenkey-connector
```

## Writing a plugin

The protocol is defined in
[`proto/krakenkey/connector/plugin/v1/plugin.proto`](proto/krakenkey/connector/plugin/v1/plugin.proto).
Go plugins use the SDK in [`pkg/plugin`](pkg/plugin):

```go
package main

import "github.com/krakenkey/connector/pkg/plugin"

func main() {
	plugin.Serve(plugin.ServeOpts{Target: &myTarget{}})
}
```

A plugin can be a **key store** (`Describe`, `CreateCSR`, `Complete`,
`Export`, `Release`), a **target** (`Describe`, `Validate`, `Current`,
`Stage`, `Activate`, `Rollback`), or both. Each reports its capabilities, and
the connector checks every key store and target pair before deploying
(`plugin.Match`). For example, a key store that keeps keys non-exportable
cannot feed a target that needs the key as a PEM file, and an ECDSA key
cannot go to a target that only serves RSA.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE)
