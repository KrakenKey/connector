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
  configure: the served leaf must be the issued certificate, byte for byte,
  and its chain must validate. If verification fails, that target is rolled
  back to its previous certificate (unless that one expires within a day),
  and retried later with growing delays. Other targets are not affected.
- **Survives interruptions.** The connector records each step before taking
  it. A renewal that finishes after the connector stopped waiting is picked
  up on the next pass instead of being requested again, and a deployment
  interrupted between activation and verification is finished or rolled
  back to the recorded previous certificate on the next run.
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
- The API key only needs access to the certificates the connector manages.
  Give it to the connector as a file (`KK_API_KEY_FILE`) or a systemd
  credential (`LoadCredential=kk_api_key:/etc/krakenkey-connector/api-key`)
  rather than in the environment: a process's original environment stays
  readable in `/proc/<pid>/environ` for its lifetime. If `KK_API_KEY` is
  used, it is removed from the environment that plugins and commands
  inherit, and on Linux the connector marks itself non-dumpable, so other
  processes running as the same user (plugins and deployment commands
  included) cannot read its environment or memory through `/proc`. Root
  still can. The key is never logged.
- Plugins and deployment commands run with the connector's permissions. Only
  install plugins you trust. Plugins installed by version must have their
  `sha256` pinned in the config.

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
   install -m 0600 /dev/null /etc/krakenkey-connector/api-key   # then paste the kk_... key into it
   export KK_API_KEY_FILE=/etc/krakenkey-connector/api-key
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
(`renewAfter`). If the API does not say, it renews two thirds of the way
through the certificate's lifetime.

If KrakenKey renews a certificate on its own (auto-renewal reuses the CSR,
so the new certificate has the connector's key), the connector deploys that
certificate rather than renewing again. `validate` warns when auto-renewal is
on, because then KrakenKey, not the connector, decides when renewals happen.

To renew now, regardless of the schedule (for example to test a new target):

```sh
krakenkey-connector run --once --force --cert 1043
```

## Commands

| Command | What it does |
|---------|--------------|
| `run` | Run a pass now, then every `check_interval`, until stopped. |
| `run --once` | Run a single pass and exit. Exit code 0 only if every certificate and target succeeded. |
| `run --once --force [--cert ID]` | Renew even if not due, and retry failed targets without waiting; `--cert` limits the pass to one configured certificate. |
| `validate [--offline]` | Check config, plugins, capabilities and (unless `--offline`) the API, then exit. |
| `version` | Print the version. |

Common flags: `--config` (default `/etc/krakenkey-connector/config.yaml`, or
`KK_CONNECTOR_CONFIG`), `--log-format text|json`, `--log-level
debug|info|warn|error`. Logs go to stderr.

Exit codes, so cron and systemd can alert:

| Code | Meaning |
|------|---------|
| `0` | Every certificate and target succeeded. |
| `1` | A certificate or target failed. The log and the audit log say which. |
| `2` | Usage or config error, including a missing API key. |
| `3` | The API rejected the key. The pass stopped. |
| `4` | KrakenKey asked the connector to back off (`429`) for longer than it waits. The pass stopped. |

After a `401` the connector stops calling the API; a bad key would otherwise
get locked out. On a `429` it waits for `Retry-After` (up to 5 minutes) before
trying again, and otherwise stops the pass. `run` mode keeps running after
`1` and `4` and tries again at the next interval; it exits on `3`.

The API key is read from the file named by `KK_API_KEY_FILE`, then from the
systemd credential `kk_api_key` (`$CREDENTIALS_DIRECTORY/kk_api_key`), then
from `KK_API_KEY`. A key file must not be readable by other users.

Only one connector process can use a data directory at a time.

## Configuration

| Key | Default | Meaning |
|-----|---------|---------|
| `krakenkey.api_url` | `https://api.krakenkey.io` | API base URL. `KK_API_URL` overrides it. |
| `check_interval` | `6h` | Time between passes in `run` mode (minimum `1m`). |
| `data_dir` | `/var/lib/krakenkey-connector` | Keys, state and plugin binaries. Must be owned by the connector's user, mode `0700`. |
| `audit_log` | `<data_dir>/audit.jsonl` | Audit log, one JSON object per line. Must be mode `0600`. |
| `plugins` | | External plugins, by name. See [Plugins](#external-plugins). |
| `certificates[].id` | | KrakenKey certificate id. |
| `certificates[].names` | | DNS names. Must equal the certificate's names. |
| `certificates[].key_store.plugin` | `local` | Key store plugin. |
| `certificates[].key_store.key_type` | `ecdsa-p256` | `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-3072` (and `rsa-4096` for plugins that support it). |
| `certificates[].targets[].label` | | Name for logs and the audit log. Unique per certificate. |
| `certificates[].targets[].plugin` | | `file`, `exec`, or an external plugin. |
| `certificates[].targets[].then.exec` | | Command run after activation and again after a rollback, such as a reload. No shell; the program is an absolute path or a name from `PATH`. |
| `certificates[].targets[].then.timeout` | `2m` | Timeout for the `then` command. |
| `certificates[].targets[].verify` | | How to check the deployment. See below. |

Any other keys in a `key_store` or target block are settings for that plugin.

### Verify

```yaml
verify:
  host: api.example.com      # SNI name; must be one of the certificate's names
  address: 127.0.0.1:8443    # where to connect; default host:port
  port: 443                  # used when address is not set
  window: 10m                # how long to keep trying; default from the target, else 10m
  ca_file: /etc/ssl/staging-roots.pem   # trust only these roots for the chain
  skip_chain_validation: false
```

The connector connects to `address` (or `host:port`), sends `host` as SNI, and
keeps trying with growing delays until the endpoint serves exactly the
issued leaf (same bytes, so the same serial number and public key), or the
window ends. It then
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
file is a symlink, belongs to another user, or allows access by group or
others. Keys the connector's state no longer refers to (for example left by
a crash) are deleted at the end of each pass. It has no settings.

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
temporary file in the same directory, with its owner and mode set before it
is closed, and renamed into place, so readers never see a partial file.
Before that, the current files are copied to
`<dir>/.krakenkey-previous/<id>/` for rollback. Certificate files get mode
`0644`. The key mode must not give access to other users. Quote the mode so
YAML keeps it as a string.

All file operations stay inside `dir`: symlinks that point outside it are not
followed. `.krakenkey-previous` must be a real directory owned by the
connector's user with mode `0700`; the connector creates it that way.

Retention: the last two backup sets are kept, and each holds a copy of the
private key that was live before. Temporary files left by an interrupted run
are removed at the next deployment.

When the connector runs as a non-root user (such as the Docker image), it can
only set `owner` to its own user, or a group it belongs to.

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
`KK_ACTION=rollback`. The program is an absolute path or a name looked up in
`PATH`; relative paths are refused. Output from a failing command is kept in
errors and the audit log with private keys and API keys removed.

Retention: the files of the current deployment, and of the previous one until
the next deployment is staged, are kept (each with its private key) for
rollback. Rolling back the very first deployment is not possible: the command
cannot be undone without something to go back to.

### External plugins

```yaml
plugins:
  azure-keyvault: { version: 0.1.0, sha256: "<hex>", call_timeout: 5m }
```

The connector looks for the plugin at
`<data_dir>/plugins/<name>/<version>/krakenkey-connector-plugin-<name>`, or at
`path` if set. `sha256` is required for plugins installed by version and
optional with `path`.

Before starting a plugin, the connector checks that the binary is a regular
file (not a symlink) owned by root or the connector's user and not writable by
group or others, and that every directory above it, up to the data directory
(or `/` for `path`), meets the same rule. Root-owned directories with the
sticky bit, such as `/tmp`, are accepted on the way. It computes the checksum
from the opened file. On Linux it then runs that same open file (through
`/proc/self/fd`), so the binary cannot be swapped between the check and the
start; plugins must therefore be native executables, not scripts. On other
systems the binary is started by path after the check, and the ownership
rules are what keep it from being replaced in between.

Every call to a plugin has a timeout (`call_timeout`, default 5 minutes; at
most 1 minute for quick calls such as `Describe` and `Validate`). A plugin
that exits is started again on the next call.

### Audit log

Every step that changes something is appended to `audit_log` and synced to
disk before the connector moves on: run id, certificate id, target label,
step, result, old and new serial, error, time, and for `activate`, the
target's reference to what was live before (what a rollback needs). The audit
log never contains key material: error text and command output are scrubbed
of private keys and API keys and capped in length. The file must be a regular
file owned by the connector's user with mode `0600`.

## Docker

```sh
docker build -t krakenkey-connector .
docker run -d --name krakenkey-connector \
  -e KK_API_KEY_FILE=/run/secrets/kk_api_key \
  -v /etc/krakenkey-connector/api-key:/run/secrets/kk_api_key:ro \
  -v /etc/krakenkey-connector/config.yaml:/etc/krakenkey-connector/config.yaml:ro \
  -v krakenkey-connector-data:/var/lib/krakenkey-connector \
  -v /srv/tls/api:/srv/tls/api \
  krakenkey-connector
```

The image runs as a non-root user (uid 10001). Give that user write access to
the target directories you mount, and make the key file readable by it (and
not by others). Because it is not root, a `file` target in the container
cannot set `owner` to another user such as `root:nginx`; leave `owner` out, or
use a group uid 10001 belongs to.

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

A plugin can be a **key store** (`Describe`, `Validate`, `CreateCSR`,
`PublicKey`, `Complete`, `Export`, `Release`), a **target** (`Describe`,
`Validate`, `Current`, `Stage`, `Activate`, `Rollback`, `Discard`), or both.
Embed `plugin.UnimplementedKeyStore` or `plugin.UnimplementedTarget` and
override the calls you support. Wrap the error kinds in
[`pkg/plugin/errors.go`](pkg/plugin/errors.go) (`ErrPermanent`, `ErrNotFound`,
`ErrUnavailable`, ...) so the connector knows whether retrying makes sense; the
proto file lists the matching gRPC codes and the contract of each call.

Each plugin reports its capabilities, and the connector checks every key
store and target pair before deploying (`plugin.Match`). For example, a key
store that keeps keys non-exportable cannot feed a target that needs the key
as a PEM file, and an ECDSA key cannot go to a target that only serves RSA.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE)
