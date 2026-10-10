# Changelog

Notable changes to the KrakenKey Connector. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until v1, minor
versions may include breaking changes to the configuration, the plugin
protocol and the KrakenKey API the connector uses.

## [Unreleased]

### Added

- `aws-acm` target plugin (`plugins/aws-acm`, its own Go module): re-imports
  certificates into an existing imported ACM certificate, so load balancers,
  CloudFront and API Gateway keep using the same ARN. It checks the
  replacement before changing anything (key type, key usages, names), and
  rolls back by re-importing the previous certificate and key the connector
  hands back. Needs `acm:DescribeCertificate` and `acm:ImportCertificate`.

- Rollback material for targets that cannot keep the previous certificate
  and key themselves, such as a cloud service that never returns an
  imported private key. A target sets `rollback_needs_material`, and the
  connector hands back the certificate it last deployed there and its key
  in `RollbackRequest` (`previous_cert_pem`, `previous_chain_pem`,
  `previous_fullchain_pem`, `previous_key`, `previous_serial`). The state
  now records earlier certificates while a target still serves them, so
  this also works after a restart and when an interrupted deployment is
  rolled back. `validate` warns when such a target is paired with a key
  store that does not allow export.

### Fixed

- A pass cancelled partway through no longer forgets the deployment state
  of the targets it had not reached yet.

## [v0.1.0] - 2026-10-10

First release.

### Added

- Deployment status reporting: after every pass an enrolled connector sends
  KrakenKey each target's state (`pending` through `verified`, `failed` or
  `rolled_back`), the serial it serves and a short redacted error, so the
  dashboard shows what is deployed where and KrakenKey alerts on failures.
  Failures on the connector's side are reported as `failed`. Reporting never
  changes the outcome or exit code of a pass. (#4)
- `krakenkey-connector enroll` and `rotate-identity`: the connector enrolls
  once with a one-time token from the KrakenKey dashboard, keeps an Ed25519
  identity key in `<data_dir>/identity/`, and exchanges a signed assertion
  for a one-hour API key on each pass, so no long-lived key is stored. The
  API key settings stay as a fallback for connectors that are not enrolled.
  Exit code 5 means KrakenKey refused the connector's identity (for example
  after it was revoked). (#3)
- Plugin protocol (`krakenkey.connector.plugin.v1`) and Go SDK in
  `pkg/plugin`. Key stores and targets are separate executables run over
  gRPC with hashicorp/go-plugin. The protocol defines error kinds mapped to
  gRPC codes, embeddable `UnimplementedKeyStore` and `UnimplementedTarget`
  types, and capability matching so a key store and target that cannot work
  together fail with a clear reason before anything is deployed. (#1)
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
  material removed. External plugins are checked for ownership, permissions
  and a pinned `sha256` before they start. (#2)
- Built-in `local` key store: PKCS#8 keys under `<data_dir>/keys/`, `0600`
  files in `0700` directories, with symlink and ownership checks. (#2)
- Built-in `file` target (atomic writes confined to the target directory,
  owner and mode settings, backups for rollback) and `exec` target (runs a
  command with the certificate, chain, full chain and key files, and again
  with `KK_ACTION=rollback` on failure). (#2)
- Pending certificates: a certificate created in KrakenKey with names only
  (status `awaiting_csr`) is issued by the connector on its next pass, after
  checking that the configured names match the requested names. (#5)
- Release pipeline: archives for Linux and macOS (amd64 and arm64), a
  `checksums.txt` signed with Sigstore, and a signed multi-arch container
  image at `ghcr.io/krakenkey/connector`. No Windows builds yet.

[Unreleased]: https://github.com/KrakenKey/connector/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/KrakenKey/connector/releases/tag/v0.1.0
