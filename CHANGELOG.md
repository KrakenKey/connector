# Changelog

Notable changes to the KrakenKey Connector. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until v1, minor
versions may include breaking changes to the configuration, the plugin
protocol and the KrakenKey API the connector uses.

## [Unreleased]

### Added

- A plugin declared without `version` (and without `path`) uses the bundled
  plugin: the only version of it in the system plugin directory, checked
  against `plugins.lock`. Configs for the container image no longer need a
  plugin version change on every upgrade. With no version or several
  versions there, the connector refuses with an error that says so, and it
  never takes an unpinned plugin from `<data_dir>/plugins`. `validate`
  shows the version it used. An explicit `version` works as before.

## [v0.1.0] - 2026-10-10

First release: the connector, its plugin protocol and Go SDK, and three
plugins (`aws-acm`, `azure-keyvault` and `azure-appgateway`), released
together under one version.

### Added

- The `krakenkey-connector` command: `run`, `run --once`, `run --once
  --force [--cert ID]`, `validate [--offline]` and `version`, with exit codes
  for cron and systemd. The API key is read from `KK_API_KEY_FILE`, the
  systemd credential `kk_api_key`, or `KK_API_KEY`. (#2)
- Core runtime: renews each certificate with a key the connector holds,
  checks the issued certificate against the CSR key and the configured
  names, then deploys, verifies (TLS handshake against the configured
  endpoint) and rolls back each target on its own. Every step is recorded
  before it runs, so an interrupted pass is resumed or rolled back on the
  next run, and each change is written to an append-only audit log with key
  material removed. (#2) In detail:
  - A pass cancelled partway through keeps the deployment state of the
    targets it had not reached yet.
  - After an Activate that reported an error, or a Rollback that failed, the
    connector asks the target what it serves. If the target already serves
    the new certificate, the connector records that (and verifies it after a
    lost Activate answer), so the next deployment's previous state is right.
  - A certificate the connector keeps after a failed check records that
    certificate's expiry, not the newest one's.
  - A rollback gets the longer of the plugin's `call_timeout` and 5 minutes.
  - A pending key from an earlier renewal is resolved before adopting a
    certificate KrakenKey renewed with the current key, so key stores that
    refuse to complete one while a request of their own is open do not
    stall every pass.
  - When the key store permanently refuses a certificate KrakenKey renewed
    with the connector's key, the connector renews with a new key instead of
    retrying the same step on every pass.
- `krakenkey-connector enroll` and `rotate-identity`: the connector enrolls
  once with a one-time token from the KrakenKey dashboard, keeps an Ed25519
  identity key in `<data_dir>/identity/`, and exchanges a signed assertion
  for a one-hour API key on each pass, so no long-lived key is stored. The
  API key settings stay as a fallback for connectors that are not enrolled.
  Exit code 5 means KrakenKey refused the connector's identity (for example
  after it was revoked). (#3)
- Deployment status reporting: after every pass an enrolled connector sends
  KrakenKey each target's state (`pending` through `verified`, `failed` or
  `rolled_back`), the serial it serves and a short redacted error, so the
  dashboard shows what is deployed where and KrakenKey alerts on failures.
  Failures on the connector's side are reported as `failed`. Reporting never
  changes the outcome or exit code of a pass. (#4)
- Pending certificates: a certificate created in KrakenKey with names only
  (status `awaiting_csr`) is issued by the connector on its next pass, after
  checking that the configured names match the requested names. (#5)
- Built-in `local` key store: PKCS#8 keys under `<data_dir>/keys/`, `0600`
  files in `0700` directories, with symlink and ownership checks. (#2)
- Built-in `file` target (atomic writes confined to the target directory,
  owner and mode settings, backups for rollback) and `exec` target (runs a
  command with the certificate, chain, full chain and key files, and again
  with `KK_ACTION=rollback` on failure). (#2)
- Plugin protocol (`krakenkey.connector.plugin.v1`) and Go SDK in
  `pkg/plugin`. Key stores and targets are separate executables run over
  gRPC with hashicorp/go-plugin. The protocol defines error kinds mapped to
  gRPC codes, embeddable `UnimplementedKeyStore` and `UnimplementedTarget`
  types, and capability matching so a key store and target that cannot work
  together fail with a clear reason before anything is deployed. (#1)
- Rollback material for targets that cannot keep the previous certificate
  and key themselves, such as a cloud service that never returns an
  imported private key. A target sets `rollback_needs_material`, and the
  connector hands back the certificate it last deployed there and its key
  in `RollbackRequest` (`previous_cert_pem`, `previous_chain_pem`,
  `previous_fullchain_pem`, `previous_key`, `previous_serial`). The state
  records earlier certificates while a target still serves them, so this
  also works after a restart and when an interrupted deployment is rolled
  back. `validate` warns when such a target is paired with a key store that
  does not allow export. Before Activate the connector asks such a target
  what it serves, so the material matches what was really live. (#8)
- Core features: the connector sends the optional protocol features it
  supports (`core_features`) with every `Describe` call, so plugins can
  refuse to run with a connector that lacks one they need.
- Install id: requests that create, change or check resources carry an
  opaque, stable `install_id` (the enrolled connector's id, or a random id
  kept in `<data_dir>/install_id`) so plugins can tag resources they own.
- Key stores can return capabilities for a certificate's settings from
  `Validate` (`KeyStoreCapabilityValidator`), and the connector matches
  targets against those.
- External plugins are checked for ownership, permissions and a pinned
  `sha256` before they start, and on Linux the checked file itself is
  executed. (#2)
- System plugin directory (`plugin_dir`, default
  `/usr/lib/krakenkey-connector/plugins`, or `KK_PLUGIN_DIR`): a plugin
  declared by version that is not installed under `<data_dir>/plugins` is
  taken from there, pinned by the directory's root-owned `plugins.lock`
  instead of a `sha256` in the config. A missing, malformed or writable lock
  file means no plugin is taken from the directory. `validate` starts every
  declared plugin and shows where it was found and which checksum it
  matched.
- `aws-acm` target plugin (`plugins/aws-acm`): re-imports certificates into
  an existing imported ACM certificate, so load balancers, CloudFront and
  API Gateway keep using the same ARN. It checks the replacement before
  changing anything (key type, key usages, names), and rolls back by
  re-importing the previous certificate and key the connector hands back.
  It accepts both spellings ACM uses for EC key algorithms
  (`EC-prime256v1` and `EC_prime256v1`), and explains when ACM would refuse
  a reimport because the existing certificate allows any key usage (`ANY`);
  the README's placeholder recipe sets `keyUsage` and `extendedKeyUsage` to
  match KrakenKey certificates so that does not happen. Needs
  `acm:DescribeCertificate` and `acm:ImportCertificate`, and a connector
  with the `rollback_material` core feature. (#11, #12)
- `azure-keyvault` key store plugin (`plugins/azure-keyvault`): Azure Key
  Vault creates the key and the CSR and keeps the issued certificate, so the
  key leaves the vault only for exportable certificates whose targets need
  PEM or PFX. Targets such as Application Gateway get the versioned secret
  id. (#9)
- `azure-appgateway` target plugin (`plugins/azure-appgateway`): points an
  Application Gateway v2 SSL certificate at a specific Key Vault secret
  version, so the gateway serves the new certificate as soon as the update
  finishes, and rolls back by restoring the previous version. Updates use
  ETag checks so a concurrent change is never overwritten, and rollback
  refuses when it could not truly restore the earlier state (a versionless
  secret on the same name, a replaced uploaded certificate, or an entry
  someone changed since). It accepts the gateway's managed identity type in
  any case (`userAssigned` from the Azure CLI, `UserAssigned` from
  templates). (#10, #14)
- Release pipeline: archives for Linux and macOS (amd64 and arm64) of the
  connector and of each plugin, a `checksums.txt` covering all of them signed
  with Sigstore, and a signed multi-arch container image at
  `ghcr.io/krakenkey/connector` that carries the three plugins in its system
  plugin directory with a `plugins.lock` written at build time. No Windows
  builds yet. (#6)

### Security

- Plugins do not inherit the connector's `KK_API_KEY`, `KK_API_KEY_FILE`,
  `CREDENTIALS_DIRECTORY` or `KK_ENROLLMENT_TOKEN*` environment variables.
  The README lists the cloud SDK variables that decide where plugins send
  keys and tokens.

[Unreleased]: https://github.com/KrakenKey/connector/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/KrakenKey/connector/releases/tag/v0.1.0
