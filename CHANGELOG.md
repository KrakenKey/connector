# Changelog

Notable changes to the KrakenKey Connector. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until v1, minor
versions may include breaking changes to the configuration, the plugin
protocol and the KrakenKey API the connector uses.

## [Unreleased]

### Added

- An enrolled connector sends KrakenKey a read-only summary of its config
  after passes, so the dashboard can show the certificates, key stores,
  targets (implicit ones included) and plugin versions. Settings come from
  an allowlist: commands, file owners and modes, tags, cloud account ids,
  ARNs, plugin paths and anything from the environment are never sent. The
  summary is sent when it changes and at least once a day; KrakenKey
  versions without the route are skipped quietly. Set
  `krakenkey.share_config: false` to turn it off, which also deletes a
  summary sent before. See "Config summary" in the README.

## [v0.2.0] - 2026-10-11

Linux packages and a Homebrew cask, bundled plugin versions, and Key Vault as
a deployment target, including implicit targets for key stores whose
certificate is itself the deployment.

### Upgrading from v0.1.0

- Plugins that ship with the container image or the packages can be
  declared without `version`; the connector uses the bundled one. Pinned
  versions keep working, but must be changed on every upgrade.
- A certificate with the `azure-keyvault` key store gets an implicit target
  labeled `azure-keyvault`. If one of its configured targets already uses
  that label for another place, the implicit target is skipped and
  `validate` warns; rename that target to get it.
- Key Vault certificates the connector manages now get the tag
  `krakenkey-connector-previous-version`, which leaves 13 of Key Vault's 15
  tags for your own.

### Added

- A plugin declared without `version` (and without `path`) uses the bundled
  plugin: the only version of it in the system plugin directory, checked
  against `plugins.lock`. Configs for the container image no longer need a
  plugin version change on every upgrade. With no version or several
  versions there, the connector refuses with an error that says so, and it
  never takes an unpinned plugin from `<data_dir>/plugins`. `validate`
  shows the version it used. An explicit `version` works as before.
- `.deb` and `.rpm` packages for Linux amd64 and arm64, published to the
  signed apt and dnf repositories at packages.krakenkey.io and attached to
  each release. They install the connector, the included plugins in the
  system plugin directory with their `plugins.lock` (the same binaries and
  layout as the container image), an example config, and a hardened
  systemd unit, `krakenkey-connector.service`, that runs as a dedicated
  system user. The service is not enabled or started on install. An
  upgrade restarts a running service, unless the config pins a plugin
  version the upgrade removed: then it says which, and leaves the service
  running.
- A Homebrew cask, `krakenkey/tap/krakenkey-connector`, for macOS and Linux.
  It installs the connector only.
- Implicit targets: a key store whose certificate is itself a deployment
  (such as a Key Vault certificate that services read without a version)
  adds a target by itself, labeled with the key store plugin's name. A
  certificate with such a key store needs no configured targets, and is
  still deployed, reported to KrakenKey and alerted on, and verified when
  configured. A configured target of the same plugin that deploys to the
  same place replaces the implicit one, for example to add a `verify` block
  or a `then` command (a failing `then` rolls it back). `validate` marks the
  implicit target. If a configured target already uses the implicit
  target's label (the key store plugin's name) and deploys somewhere else,
  the implicit target is not added and `validate` warns.
- Plugin protocol: `KeyStoreCapabilities.implicit_target` (from the key
  store's `Validate`), `TargetServiceValidateRequest.key_store_deployment_id`
  and `TargetServiceValidateResponse.deployment_id`, and the core feature
  `implicit_target`. In the Go SDK: `plugin.ImplicitTarget`,
  `plugin.TargetDeploymentValidator`, `plugin.ValidateTarget`,
  `plugin.MatchKeyStoreDeployment` and
  `plugin.KeyStoreDeploymentRollbackUnavailable`. Older plugins and
  connectors ignore the new fields and keep today's behavior.
- `azure-keyvault` target: deploys certificates to Key Vault certificates
  as new versions, for services that read them without a version (App
  Service, Container Apps, API Management, Front Door, the AKS Secrets
  Store CSI driver, the VM Key Vault extension). With the `azure-keyvault`
  key store, the key store's own certificate is the implicit target
  `azure-keyvault`: it finds the merged version in place and imports
  nothing. Other vaults or certificate names get the certificate, chain and
  key imported as PKCS#12, with the same ownership rules and `adopt` setting
  as the key store, and optional `tags`. Rollback imports the previous
  certificate and key again as the latest version, and is refused when the
  key cannot be exported. Verification failures are reported as failed and
  checked again on later passes, not rolled back, since services pick up
  new versions on their own schedule. Versions the plugin creates (merged
  by the key store or imported by the target) name the version they
  replaced in the tag `krakenkey-connector-previous-version`, so a rollback
  does not depend on creation times, which Key Vault keeps to the second.

### Changed

- `azure-keyvault`: errors keep Key Vault's HTTP status and error codes but
  no longer its message, which names the caller's application and object
  ids and tenant; ids and token issuer URLs are also removed from
  credential errors. A 403 names the permission Key Vault says is missing
  when it says so. Reading a pending request is documented as needing
  certificate permission Create in vaults that use access policies.
- `azure-keyvault` key store: `validate` uses the capabilities for each
  certificate's settings, so a certificate with `exportable: false` is
  refused for targets that need the key (such as Application Gateway)
  instead of failing at the first deployment.
- A certificate whose key store is an external plugin may list no
  targets; the connector reports it as a problem when the key store adds no
  target by itself. Certificates with the built-in `local` key store still
  need at least one target.
- `validate` reports two targets of one certificate that deploy to the same
  place (same plugin and deployment id) as a problem, and warns when two
  plugin names run the same executable and deploy to the same place.
- A target that picks up changes on its own schedule (`propagates_async`)
  and fails its check is reported as `failed` instead of
  `activated_unverifiable`, with an error saying it was not rolled back,
  and later passes check it again until the check passes or a newer
  certificate replaces it. A target's failure is no longer copied onto the
  certificate's other targets that are still waiting in the status report.
- A deployment of an older certificate that was interrupted after Activate
  is no longer rolled back when the target already serves the current
  certificate.
- When a step before Activate fails on the key store's own deployment but
  the target serves the new certificate, the target is checked as
  activated instead of recorded as failed on the old certificate.
- The error after a rollback whose `then` command failed says "rolled back,
  but then.exec failed afterwards" (it said "files rolled back"), since
  not every target has files.
- `azure-appgateway`: errors keep the HTTP status, Azure's error code and
  the denied action, but no longer Azure's message, which names the
  caller's application and object ids, its tenant and the subscription.
  Token errors keep the HTTP status and the `AADSTS` code; ids and token
  issuer URLs are removed from other Azure SDK error text.

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

[Unreleased]: https://github.com/KrakenKey/connector/compare/v0.2.0...HEAD
[v0.2.0]: https://github.com/KrakenKey/connector/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/KrakenKey/connector/releases/tag/v0.1.0
