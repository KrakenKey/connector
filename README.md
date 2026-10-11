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
  always has something to go back to. Targets that cannot keep the previous
  certificate and key themselves (for example a cloud service that never
  returns an imported private key) are handed them back on rollback.
- **Plugins.** Key stores and targets are plugins: separate executables that
  the connector runs and talks to over gRPC, using
  [hashicorp/go-plugin](https://github.com/hashicorp/go-plugin), the same model
  Terraform uses for providers. A few common ones are built in.

### Trust boundary

- KrakenKey sees the CSR, the issued certificate and the certificate id. It
  never sees private keys or credentials for your systems.
- The connector holds private keys and the access needed to deploy (file
  permissions, vault credentials). Run it where that access already lives.
- An enrolled connector holds no long-lived API key. It has its own
  Ed25519 identity key, created on the machine at enrollment, and trades a
  signed request for an API key that lasts an hour. That key stays in
  memory and is limited to the scopes and certificates set for the
  connector in the dashboard. See [Enrollment](#enrollment).
- Without enrollment, the connector uses an API key, which only needs access
  to the certificates the connector manages. Give it to the connector as a
  file (`KK_API_KEY_FILE`) or a systemd credential
  (`LoadCredential=kk_api_key:/etc/krakenkey-connector/api-key`) rather
  than in the environment: a process's original environment stays readable
  in `/proc/<pid>/environ` for its lifetime. If `KK_API_KEY` is used, it is
  removed from the environment that plugins and commands inherit, and on
  Linux the connector marks itself non-dumpable, so other processes running
  as the same user (plugins and deployment commands included) cannot read
  its environment or memory through `/proc`. Root still can. Keys, tokens
  and the identity key are never logged.
- Plugins and deployment commands run with the connector's permissions. Only
  install plugins you trust. Plugins you install under the data directory
  must have their `sha256` pinned in the config; the plugins in the
  container image and the Linux packages are pinned by their
  `plugins.lock` (see [External plugins](#external-plugins)).
- Plugins get the connector's environment without `KK_API_KEY`,
  `KK_API_KEY_FILE`, `CREDENTIALS_DIRECTORY` and `KK_ENROLLMENT_TOKEN*`.
  Everything else is passed on, because cloud SDKs read their credentials and
  settings from it. Some of those settings decide where a plugin sends
  private keys and cloud tokens, so whoever can set the connector's
  environment or the cloud SDK config files is inside the trust boundary:
  - AWS: `AWS_ENDPOINT_URL`, `AWS_ENDPOINT_URL_<SERVICE>` (for example
    `AWS_ENDPOINT_URL_ACM`), `endpoint_url` in the shared config file
    (`AWS_CONFIG_FILE`, `AWS_PROFILE`), `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS`
    and `AWS_CA_BUNDLE`.
  - Azure: `AZURE_AUTHORITY_HOST`, `IDENTITY_ENDPOINT`, `MSI_ENDPOINT`,
    `IMDS_ENDPOINT` and `AZURE_TOKEN_CREDENTIALS`.
  - Any plugin: `SSL_CERT_FILE`, `SSL_CERT_DIR`, `HTTPS_PROXY`, `HTTP_PROXY`
    and `NO_PROXY`.

## Install

### Debian, Ubuntu, Fedora, RHEL and Amazon Linux

The `krakenkey-connector` package installs the connector, the
[included plugins](#included-plugins) and a systemd service. See
[Running as a service](#running-as-a-service) for what it sets up and how to
start it.

**Debian and Ubuntu** (amd64 and arm64): add the KrakenKey apt repository,
then install and upgrade with apt.

```sh
curl -fsSLo /tmp/krakenkey-archive-keyring.deb https://packages.krakenkey.io/keys/krakenkey-archive-keyring.deb
sudo apt install /tmp/krakenkey-archive-keyring.deb
sudo apt update && sudo apt install krakenkey-connector
```

**Fedora, RHEL, Rocky, Alma, Amazon Linux 2023** (x86_64 and aarch64): add
the KrakenKey rpm repository, then install and upgrade with dnf.

```sh
sudo dnf install https://packages.krakenkey.io/keys/krakenkey-archive-keyring.rpm
sudo dnf install krakenkey-connector
```

`krakenkey-archive-keyring` installs the signing key and the repository
settings (`/etc/apt/sources.list.d/krakenkey.sources`, or
`/etc/yum.repos.d/krakenkey.repo`). It is the same repository as the
KrakenKey CLI's, so skip that step if the CLI is already installed from it.
Supported: Debian 11+, Ubuntu 20.04+, RHEL/Rocky/Alma 8+, Fedora, Amazon
Linux 2023. On older systems, use the [release binaries](#release-binaries).

The repositories are signed with this key. The first time dnf uses it, it
asks you to confirm the key; check the fingerprint:

```text
KrakenKey Packages <packages@krakenkey.io>
386E 2558 2384 DD74 692A  4EE9 F7BA 53A4 E94F A5DA
```

To check it yourself:
`curl -fsSL https://packages.krakenkey.io/keys/krakenkey.asc | gpg --show-keys`.
If you'd rather not add a repository, each
[release](https://github.com/KrakenKey/connector/releases) also has the
`.deb` and `.rpm` files (`krakenkey-connector_<version>_linux_<arch>.deb`
and `.rpm`), covered by the signed `checksums.txt` described below:

```sh
# Debian, Ubuntu
sudo apt install ./krakenkey-connector_*_linux_amd64.deb

# RHEL, Fedora, Amazon Linux
sudo dnf install ./krakenkey-connector_*_linux_amd64.rpm
```

Replace `amd64` with `arm64` on ARM machines.

### Homebrew

On macOS (and Linux):

```sh
brew install krakenkey/tap/krakenkey-connector
```

Update with `brew upgrade krakenkey-connector`. The cask comes from
[KrakenKey/homebrew-tap](https://github.com/KrakenKey/homebrew-tap), is
updated by each release, and checks the download against the release
checksums. It installs the connector only:

- Install the plugins you need from their release archives under the data
  directory, with their `sha256` in the config, as described in
  [On a host](#on-a-host).
- Homebrew does not run the connector as a service. Run
  `krakenkey-connector run` yourself, or `run --once` from launchd or cron.
- Set `data_dir` in the config to a directory you own, since the default,
  `/var/lib/krakenkey-connector`, does not exist on macOS.

On Linux, prefer the packages above: they include the plugins and the
systemd service.

### Release binaries

Each [release](https://github.com/KrakenKey/connector/releases) has archives
for Linux and macOS (amd64 and arm64) of the connector and of each
[included plugin](#included-plugins), a `checksums.txt` covering
them, and `checksums.txt.sigstore.json`, a [Sigstore](https://www.sigstore.dev/)
signature for the checksums made by this repository's release workflow. There
is no long-lived signing key: the signature is tied to the workflow and the
tag it ran for. Verifying needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
v3 or later.

```sh
VERSION=0.1.0   # the release, without the leading v
OS=linux        # linux or darwin
ARCH=amd64      # amd64 or arm64
ARCHIVE="krakenkey-connector_${VERSION}_${OS}_${ARCH}.tar.gz"
BASE="https://github.com/KrakenKey/connector/releases/download/v${VERSION}"
curl -fsSLO "${BASE}/${ARCHIVE}"
curl -fsSLO "${BASE}/checksums.txt"
curl -fsSLO "${BASE}/checksums.txt.sigstore.json"

# 1. checksums.txt was signed by the release workflow for this tag
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/KrakenKey/connector/.github/workflows/release.yaml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# 2. the archive matches checksums.txt (on macOS use: shasum -a 256 -c)
grep " ${ARCHIVE}\$" checksums.txt | sha256sum -c

tar -xzf "${ARCHIVE}" krakenkey-connector
sudo install -m 0755 krakenkey-connector /usr/local/bin/krakenkey-connector
krakenkey-connector version
```

Windows builds are not published yet: the connector's file permission,
plugin ownership and key mode checks are not implemented on Windows.
Building from source for Windows works, but is unsupported.

### Container image

`ghcr.io/krakenkey/connector`, for `linux/amd64` and `linux/arm64`. The image
also carries the [included plugins](#included-plugins), so a container needs
no plugin downloads.

| Tag | Points to |
|-----|-----------|
| `vX.Y.Z` | That release, prereleases included. |
| `X.Y` | The latest patch release of `X.Y`. |
| `latest` | The latest release that is not a prerelease. |

Images are signed the same way. Image signatures are stored in the format
cosign v3 writes, so check them with cosign v3 or later (cosign v2 reports
"no signatures found"). To check one before running it:

```sh
cosign verify ghcr.io/krakenkey/connector:v${VERSION} \
  --certificate-identity "https://github.com/KrakenKey/connector/.github/workflows/release.yaml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

See [Docker](#docker) for how to run it.

## Quick start

With the Linux packages, follow [Running as a service](#running-as-a-service)
instead: it covers the same steps for the systemd service.

1. Create a connector in the KrakenKey dashboard and copy its enrollment
   token (`kkce_...`, shown once, valid for 24 hours). Alternatively, create
   an API key and skip step 3.
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

3. Enroll the connector, as the user it will run as:

   ```sh
   install -m 0600 /dev/null /etc/krakenkey-connector/enrollment-token   # then paste the kkce_... token into it
   KK_ENROLLMENT_TOKEN_FILE=/etc/krakenkey-connector/enrollment-token \
     krakenkey-connector enroll --config /etc/krakenkey-connector/config.yaml
   rm /etc/krakenkey-connector/enrollment-token   # it works only once
   ```

   With an API key instead, put the key in a file and
   `export KK_API_KEY_FILE=/etc/krakenkey-connector/api-key`.

4. Check it. `validate` loads the config, starts the plugins, checks that each
   key store and target can work together, checks the connector's identity
   (or API key), asks KrakenKey about each certificate, and exits non-zero
   if anything is wrong:

   ```sh
   krakenkey-connector validate --config /etc/krakenkey-connector/config.yaml
   ```

5. Run a single pass, for example from cron or a systemd timer:

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

**New certificates:** a certificate can also be created in KrakenKey with
names only, to be issued by the connector (status `awaiting_csr`). Put its
id and exactly those names in the config. On its next pass the connector
creates the key and CSR, has the certificate issued, and deploys it. If the
configured names differ from the ones KrakenKey is waiting for, the
connector refuses with an error and creates nothing. `validate` lists such
certificates as waiting for this connector to issue them.

If KrakenKey renews a certificate on its own (auto-renewal reuses the CSR,
so the new certificate has the connector's key), the connector deploys that
certificate rather than renewing again. `validate` warns when auto-renewal is
on, because then KrakenKey, not the connector, decides when renewals happen.

To renew now, regardless of the schedule (for example to test a new target):

```sh
krakenkey-connector run --once --force --cert 1043
```

## Running as a service

The `.deb` and `.rpm` packages set up the connector to run under systemd:

| Path | What it is |
|------|------------|
| `/usr/bin/krakenkey-connector` | The connector. |
| `/usr/lib/krakenkey-connector/plugins/` | The [included plugins](#included-plugins), `<name>/<version>/krakenkey-connector-plugin-<name>`, with a `plugins.lock`. Owned by root, the same layout as the container image. |
| `/etc/krakenkey-connector/config.yaml` | The config. Mode `0640`, owned by `root:krakenkey-connector`, kept on upgrade. It has no certificates yet, so the connector refuses it until you add one. |
| `/etc/default/krakenkey-connector` (Debian, Ubuntu) or `/etc/sysconfig/krakenkey-connector` (RPM-based) | Environment for the service, such as cloud credentials for the plugins. Same owner and mode as the config. |
| `/var/lib/krakenkey-connector` | The data directory: keys, identity, state and the audit log. Mode `0700`, owned by `krakenkey-connector`. |
| `krakenkey-connector.service` | Runs `krakenkey-connector run` as the `krakenkey-connector` system user. Not enabled or started on install. |

To start it:

1. Edit `/etc/krakenkey-connector/config.yaml` (`sudoedit` works). Declare
   the plugins you use without a version, as shown in
   [In the container image and the Linux packages](#in-the-container-image-and-the-linux-packages),
   so they keep working across package upgrades.
2. Enroll the connector as the service user, so its identity in
   `/var/lib/krakenkey-connector` belongs to that user. The token file must
   be readable by the service user and not by others:

   ```sh
   sudo install -m 0640 -o root -g krakenkey-connector /dev/null /etc/krakenkey-connector/enrollment-token
   sudoedit /etc/krakenkey-connector/enrollment-token   # paste the kkce_... token
   sudo -u krakenkey-connector env KK_ENROLLMENT_TOKEN_FILE=/etc/krakenkey-connector/enrollment-token \
     krakenkey-connector enroll
   sudo rm /etc/krakenkey-connector/enrollment-token    # it works only once
   ```

3. Check the config, the plugins and the API access as the service user:

   ```sh
   sudo -u krakenkey-connector krakenkey-connector validate
   ```

   If the plugins read credentials from the environment file, load it the
   way the service does (on RPM-based systems the file is
   `/etc/sysconfig/krakenkey-connector`):

   ```sh
   sudo -u krakenkey-connector sh -c 'set -a; . /etc/default/krakenkey-connector; exec krakenkey-connector validate'
   ```

4. Enable and start the service, and follow its log:

   ```sh
   sudo systemctl enable --now krakenkey-connector
   journalctl -u krakenkey-connector -f
   ```

The service restarts after a failure, except after exit code `3` (the API
key or enrollment token was rejected) or `5` (KrakenKey refused the
connector's identity), which a restart cannot fix.

**With an API key instead of enrollment**, keep the key in a file only root
can read and hand it to the service as a systemd credential:

```sh
sudo install -m 0600 /dev/null /etc/krakenkey-connector/api-key
sudoedit /etc/krakenkey-connector/api-key           # paste the kk_... key
sudo systemctl edit krakenkey-connector
```

```ini
[Service]
LoadCredential=kk_api_key:/etc/krakenkey-connector/api-key
```

`LoadCredential` needs systemd 247 or later. On older systems (RHEL 8),
make the key file mode `0640` with group `krakenkey-connector` and set
`KK_API_KEY_FILE=/etc/krakenkey-connector/api-key` in the environment file
instead. To validate with the key, run `validate` the way the service gets
it:

```sh
sudo systemd-run --pipe --wait --quiet -p User=krakenkey-connector \
  -p LoadCredential=kk_api_key:/etc/krakenkey-connector/api-key \
  krakenkey-connector validate
```

### Sandbox

The unit runs the connector with most of the file system read-only
(`ProtectSystem=strict`, `ProtectHome=yes`, a private `/tmp`), no
capabilities, `NoNewPrivileges=yes`, and a system call filter. It can
write only to `/var/lib/krakenkey-connector` and its private `/tmp`, where
plugins and the connector talk over Unix sockets. Outbound network access
is not restricted, so the connector reaches the KrakenKey API, and plugins
reach cloud APIs and instance metadata (`169.254.169.254`).

**`file` targets** need a drop-in that lets the service write to their
directories. The directory must also be writable by the
`krakenkey-connector` user, and `owner` can only name that user or a group
it belongs to. For the nginx example in [Quick start](#quick-start), with
`owner: ":nginx"`:

```sh
sudo install -d -m 0750 -o krakenkey-connector -g nginx /etc/nginx/tls/api
sudo usermod -aG nginx krakenkey-connector
sudo systemctl edit krakenkey-connector
```

```ini
[Service]
ReadWritePaths=/etc/nginx/tls/api
```

A target under `/home` also needs `ProtectHome=no` there.

**Reload commands** such as `then: { exec: [systemctl, reload, nginx] }` run
as the `krakenkey-connector` user, and `NoNewPrivileges` rules out `sudo`.
Allow the reload with a polkit rule instead (polkit 0.106 or later; install
`polkitd` on Debian and Ubuntu if it is missing):

```js
// /etc/polkit-1/rules.d/50-krakenkey-connector.rules
polkit.addRule(function (action, subject) {
  if (action.id == "org.freedesktop.systemd1.manage-units" &&
      subject.user == "krakenkey-connector" &&
      action.lookup("unit") == "nginx.service" &&
      action.lookup("verb") == "reload") {
    return polkit.Result.YES;
  }
});
```

Use absolute paths in `then.exec`, `exec` targets and plugin settings that
point at files, and check the result with `validate` after adding a
drop-in.

### Upgrades and removal

An upgrade replaces the included plugins with the new version and restarts
a running service. Plugins declared without a version pick up the new ones
on their own.

If the config pins a plugin to a version the upgrade removed, the package
does not restart the service, which keeps running with the plugins it
already started, and prints the plugins to fix. Remove their `version`, or
set it to the new one (`krakenkey-connector version`), then run
`sudo systemctl restart krakenkey-connector`. Plugins you installed under
the data directory with `version` and `sha256` are not affected by
upgrades.

Removing the package (`apt remove`, `dnf remove`) stops and disables the
service, and keeps the config, the data directory and the
`krakenkey-connector` user, so a reinstall picks up where it left off. `dnf
remove` saves an edited config as `config.yaml.rpmsave`. `apt purge` also
deletes the config files the package installed and
`/var/lib/krakenkey-connector`, including the connector's identity and
private keys. Files you added to `/etc/krakenkey-connector` and the user
are kept.

## Commands

| Command | What it does |
|---------|--------------|
| `enroll [--force]` | Enroll with a one-time token. See [Enrollment](#enrollment). |
| `rotate-identity` | Replace the connector's identity key. |
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
| `2` | Usage or config error, including missing credentials, or `enroll` on an enrolled connector without `--force`. |
| `3` | The API rejected the API key, or `enroll` was given a token KrakenKey refused. The pass stopped. |
| `4` | KrakenKey asked the connector to back off (`429`) for longer than it waits. The pass stopped. |
| `5` | KrakenKey refused the connector's identity: the connector was revoked, its identity key is not the one KrakenKey has, or the clock is more than five minutes off. The pass stopped. |

After a `401` the connector stops calling the API; a bad key would otherwise
get locked out. On a `429` it waits for `Retry-After` (up to 5 minutes) before
trying again, and otherwise stops the pass. `run` mode keeps running after
`1` and `4` and tries again at the next interval; it exits on `3` and `5`.

The API key is read from the file named by `KK_API_KEY_FILE`, then from the
systemd credential `kk_api_key` (`$CREDENTIALS_DIRECTORY/kk_api_key`), then
from `KK_API_KEY`. A key file must not be readable by other users. An
enrolled connector ignores the API key and logs a warning if one is set.

Only one connector process can use a data directory at a time.

## Enrollment

Enrollment gives the connector its own identity, so that no long-lived API
key has to be stored on the machine.

1. In the dashboard, create a connector: give it a name, the scopes it
   needs (`certs:read`, and `certs:renew` to renew), and the certificates or
   domains it may manage. You get an enrollment token (`kkce_...`). It is
   shown once, works once, and expires after 24 hours.
2. Run `krakenkey-connector enroll`. The token is read from the file named
   by `KK_ENROLLMENT_TOKEN_FILE`, then from the systemd credential
   `kk_enrollment_token`, then from `KK_ENROLLMENT_TOKEN`, with the same rules
   as the API key. The connector creates an Ed25519 key pair, sends the
   public key with the token, and stores the private key and the connector
   id it gets back in `<data_dir>/identity/` (files `0600` in a `0700`
   directory, checked like the key store's files).

On each pass, the connector signs a request with its identity key and gets
an API key that is valid for an hour. It keeps that key in memory, never on
disk, and gets a new one five minutes before it expires. The signed request
carries the current time, so the machine's clock must be within five
minutes of KrakenKey's.

If KrakenKey refuses the identity (the connector was revoked in the
dashboard, for example), the pass stops at once with exit code `5`, and the
connector does not retry. To bring it back, create a new connector or
enrollment token and run `enroll --force`.

`enroll` refuses to run when the connector is already enrolled. With
`--force` it enrolls again and keeps the old identity files next to the new
ones with a `.bak-<time>` suffix; delete them once you no longer need them.

`rotate-identity` replaces the identity key. The new key is written to
`identity.key.next` first and becomes `identity.key` only after KrakenKey
has accepted it. If the connector stops in between, the next run tries the
current key, then the new one, and keeps whichever KrakenKey accepts.

`validate` shows whether the connector is enrolled, its id, and whether a
token exchange works.

### Status reporting

After every pass, failed ones included, an enrolled connector tells
KrakenKey what is deployed where, so the dashboard can show it and alert on
failures. The report covers the certificates the pass processed (all of
them, or the one given with `--cert`). For each of their targets it sends:

- the state: `pending` (nothing deployed yet, or a newer certificate is
  waiting to be deployed), `staged`, `activated` (not verified yet),
  `verified`, `activated_unverifiable` (no `verify` block, or a target that
  propagates on its own schedule), `failed` or `rolled_back`;
- the serial number of the certificate the target has;
- for failures, a short error message: private keys, API keys and
  enrollment tokens removed, paths under the data directory shortened, at
  most 200 characters;
- when that state was recorded.

When something on the connector's side keeps a certificate from being
renewed or deployed (a key store error, a config problem, an issued
certificate that fails the connector's checks), every target of that
certificate is reported as `failed`, so KrakenKey alerts. When the problem
is on KrakenKey's side, such as an issuance that failed because of a
missing DNS record, the targets stay `pending` with the error: KrakenKey
alerts on those itself.

The report comes from the connector's state files. It carries no key
material and nothing about your systems beyond target labels. If KrakenKey
skips certificates the connector is not allowed to manage, the connector
logs a warning with their ids: check the ids in the config and the
connector's restrictions in the dashboard. A report that cannot be sent is
logged as a warning; it never changes the outcome or exit code of a pass.
When the pass stopped because KrakenKey refused the credentials or asked
the connector to back off, no report is sent.

Connectors that use an API key instead of enrollment do not report.

## Configuration

| Key | Default | Meaning |
|-----|---------|---------|
| `krakenkey.api_url` | `https://api.krakenkey.io` | API base URL. `KK_API_URL` overrides it. |
| `check_interval` | `6h` | Time between passes in `run` mode (minimum `1m`). |
| `data_dir` | `/var/lib/krakenkey-connector` | Keys, identity, state and plugin binaries. Must be owned by the connector's user, mode `0700`. |
| `plugin_dir` | `/usr/lib/krakenkey-connector/plugins` | System plugin directory, read-only and owned by root, with a `plugins.lock`. `KK_PLUGIN_DIR` overrides it. See [External plugins](#external-plugins). |
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
  aws-acm: {}   # the bundled version, see below
```

The connector finds a plugin's binary, `krakenkey-connector-plugin-<name>`,
in the first of these places that applies:

1. `path`, if set. `sha256` is optional; without it the binary is not
   pinned, and `validate` says so.
2. `<data_dir>/plugins/<name>/<version>/`, if the binary is there. `sha256`
   is required.
3. `<plugin_dir>/<name>/<version>/`, the system plugin directory (default
   `/usr/lib/krakenkey-connector/plugins`). This is where the
   [container image](#container-image) and the
   [Linux packages](#debian-ubuntu-fedora-rhel-and-amazon-linux) keep the
   [included plugins](#included-plugins). `sha256` is optional here: the
   binary must match its line in `<plugin_dir>/plugins.lock`, and also the
   `sha256` setting if there is one.

Without `version` and `path`, the connector uses the bundled plugin: the
only version of it under `<plugin_dir>/<name>/`, checked against
`plugins.lock` like any plugin there. This is how the
[container image](#container-image) is meant to be used: the plugins it
ships carry the connector's version, so a config without versions keeps
working when you move to a new image. If the system plugin directory has no
version of the plugin, or more than one, the connector refuses to start it
and says so; set `version` to choose. A plugin without `version` is never
taken from `<data_dir>/plugins`, where a plugin always needs `version` and
`sha256`. `validate` shows the version it used:

```text
  azure-keyvault 0.2.0 (bundled, version not set): /usr/lib/krakenkey-connector/plugins/azure-keyvault/0.2.0/krakenkey-connector-plugin-azure-keyvault (system plugin dir)
```

`plugins.lock` lists one binary per line in `sha256sum` format:

```text
<sha256>  azure-keyvault/0.1.0/krakenkey-connector-plugin-azure-keyvault
```

It may list plugins that are not installed. If it is missing, has a line the
connector does not understand, or fails the ownership checks below, the
connector refuses every plugin in the system plugin directory, and
`validate` says why. A version installed in the data directory always wins
over the system plugin directory, and then needs its own `sha256`.

Before starting a plugin, the connector checks that the binary is a regular
file (not a symlink) owned by root or the connector's user and not writable by
group or others, and that every directory above it, up to the data directory
(or `/` for `path`), meets the same rule. In the system plugin directory the
binaries, `plugins.lock` and every directory up to `/` must be owned by root,
so the connector's own user cannot change them. Root-owned directories with the
sticky bit, such as `/tmp`, are accepted on the way. It computes the checksum
from the opened file. On Linux it then runs that same open file (through
`/proc/self/fd`), so the binary cannot be swapped between the check and the
start; plugins must therefore be native executables, not scripts. On other
systems the binary is started by path after the check, and the ownership
rules are what keep it from being replaced in between.

`validate` starts every declared plugin and shows where it was found and
which checksum it matched:

```text
Plugins
  azure-keyvault 0.1.0: /usr/lib/krakenkey-connector/plugins/azure-keyvault/0.1.0/krakenkey-connector-plugin-azure-keyvault (system plugin dir)
    sha256 6125080b70a3914640985d62df1862b3e29cb536fed660a0c919569eb01da51d, matches plugins.lock
```

Every call to a plugin has a timeout (`call_timeout`, default 5 minutes; at
most 1 minute for quick calls such as `Describe` and `Validate`). A rollback
gets the longer of `call_timeout` and 5 minutes. A plugin that exits is
started again on the next call.

The plugins maintained in this repository are listed under
[Included plugins](#included-plugins).

### Audit log

Every step that changes something is appended to `audit_log` and synced to
disk before the connector moves on: run id, certificate id, target label,
step, result, old and new serial, error, time, and for `activate`, the
target's reference to what was live before (what a rollback needs). The audit
log never contains key material: error text and command output are scrubbed
of private keys and API keys and capped in length. The file must be a regular
file owned by the connector's user with mode `0600`.

## Included plugins

These plugins are maintained in this repository, each its own Go module
under [`plugins/`](plugins). They are released with the connector and carry
its version: release `v0.1.0` ships version `0.1.0` of each.

| Plugin | Kind | What it does |
|--------|------|--------------|
| [`aws-acm`](plugins/aws-acm/README.md) | target | Re-imports certificates into an existing AWS Certificate Manager certificate, keeping its ARN, so load balancers, CloudFront and API Gateway pick up the new certificate. |
| [`azure-keyvault`](plugins/azure-keyvault/README.md) | key store | Keeps keys and certificates in Azure Key Vault: the vault creates the key and the CSR, and the key leaves it only for exportable certificates whose targets need PEM or PFX. |
| [`azure-appgateway`](plugins/azure-appgateway/README.md) | target | Points an Azure Application Gateway v2 SSL certificate at a specific Key Vault secret version, and rolls back by restoring the previous version. |

Each plugin's README covers its settings, credentials and the permissions it
needs.

### In the container image and the Linux packages

The image and the `.deb` and `.rpm` packages have the plugins in the
system plugin directory,
`/usr/lib/krakenkey-connector/plugins/<name>/<version>/`, owned by root and
read-only for the connector's user, with a `plugins.lock` written when the
release was built. Declare the plugins you use without a version, and the
connector uses the ones installed with it:

```yaml
plugins:
  azure-keyvault: {}
  azure-appgateway: { call_timeout: 15m }
```

The config then keeps working when you upgrade the image or the package.
To pin a plugin instead, set `version` to the connector's version (what
`krakenkey-connector version` prints, without the leading `v`), and change
it whenever you upgrade. An image built from source with `docker build`
uses the `VERSION` build argument (default `dev`) as the plugins' version.

### On a host

With the Linux packages, the plugins are already installed (see above).
Elsewhere, for example on macOS or with the release binaries, download the
plugin's archive from the same release as the connector,
verify it like the connector's archive (see
[Release binaries](#release-binaries)), and install the binary under the
data directory with its checksum in the config:

```sh
VERSION=0.1.0
OS=linux
ARCH=amd64
PLUGIN=azure-keyvault
ARCHIVE="krakenkey-connector-plugin-${PLUGIN}_${VERSION}_${OS}_${ARCH}.tar.gz"
BASE="https://github.com/KrakenKey/connector/releases/download/v${VERSION}"
curl -fsSLO "${BASE}/${ARCHIVE}"
curl -fsSLO "${BASE}/checksums.txt"
curl -fsSLO "${BASE}/checksums.txt.sigstore.json"

cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/KrakenKey/connector/.github/workflows/release.yaml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
grep " ${ARCHIVE}\$" checksums.txt | sha256sum -c

tar -xzf "${ARCHIVE}" "krakenkey-connector-plugin-${PLUGIN}"
DEST="/var/lib/krakenkey-connector/plugins/${PLUGIN}/${VERSION}"   # <data_dir>/plugins/...
sudo install -d -m 0755 "${DEST}"
sudo install -m 0755 "krakenkey-connector-plugin-${PLUGIN}" "${DEST}/"
sha256sum "${DEST}/krakenkey-connector-plugin-${PLUGIN}"
```

Then put the checksum in the config:

```yaml
plugins:
  azure-keyvault: { version: 0.1.0, sha256: "<sha256 printed above>" }
```

To keep plugins out of the connector user's reach, install them as root
under the system plugin directory instead (for example
`/usr/lib/krakenkey-connector/plugins/azure-keyvault/0.1.0/`) and write its
`plugins.lock` with `sha256sum */*/krakenkey-connector-plugin-* > plugins.lock`
run in that directory, or install them anywhere root owns and set `path` and
`sha256`.

## Docker

```sh
docker run -d --name krakenkey-connector \
  -e KK_API_KEY_FILE=/run/secrets/kk_api_key \
  -v /etc/krakenkey-connector/api-key:/run/secrets/kk_api_key:ro \
  -v /etc/krakenkey-connector/config.yaml:/etc/krakenkey-connector/config.yaml:ro \
  -v krakenkey-connector-data:/var/lib/krakenkey-connector \
  -v /srv/tls/api:/srv/tls/api \
  ghcr.io/krakenkey/connector:v${VERSION}
```

Pin a version tag (or `X.Y`) rather than `latest`, so an upgrade happens when
you choose. To build the image from source instead, run
`docker build -t krakenkey-connector .` and use `krakenkey-connector` as the
image name.

To enroll the container's connector, run `enroll` once with the same config
and data volume:

```sh
docker run --rm \
  -e KK_ENROLLMENT_TOKEN_FILE=/run/secrets/kk_enrollment_token \
  -v /etc/krakenkey-connector/enrollment-token:/run/secrets/kk_enrollment_token:ro \
  -v /etc/krakenkey-connector/config.yaml:/etc/krakenkey-connector/config.yaml:ro \
  -v krakenkey-connector-data:/var/lib/krakenkey-connector \
  ghcr.io/krakenkey/connector:v${VERSION} enroll --config /etc/krakenkey-connector/config.yaml
```

and then start it as above without the API key.

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

A target that cannot keep what was live before (for example a service that
never returns an imported private key) sets `RollbackNeedsMaterial`. On
rollback the connector then fills `RollbackRequest.PreviousCertPEM`,
`PreviousChainPEM`, `PreviousFullChainPEM`, `PreviousKey` and
`PreviousSerial` with the certificate it last deployed to that target and
its key, exported in the same format as for `Stage`. They are empty when the
connector has nothing to hand back (the first deployment to the target, an
expired certificate, or a key the key store no longer holds); the target then
returns `ErrPermanent`. If the target's key format carries key bytes and the
key store does not allow export, rollback is unavailable for such a target and
`validate` warns about it.

The connector sends the optional protocol features it supports with every
`Describe` call (`plugin.CoreFeaturesFrom(ctx)`, for example
`plugin.FeatureRollbackMaterial`), so a plugin that depends on one can refuse
to run with an older connector instead of misbehaving.

Calls that create, change or check resources carry the connector's install
id (`plugin.InstallIDFrom(ctx)`): an opaque id that stays the same across
restarts, so a plugin can tag the resources it creates and recognize its own.
It is the connector's id in KrakenKey once enrolled, and before that a random
id the first run stores in `<data_dir>/install_id` (mode `0600`), so it
changes once when an installation enrolls.

A key store whose capabilities depend on its settings (for example keys that
are exportable or not per vault) implements
`plugin.KeyStoreCapabilityValidator`. The connector then matches each
certificate's targets against the capabilities for that certificate's
settings, so `validate` catches a pair that cannot work.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE)
