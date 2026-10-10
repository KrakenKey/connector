# Changelog

Notable changes to the KrakenKey Connector. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until v1, minor
versions may include breaking changes to the configuration, the plugin
protocol and the KrakenKey API the connector uses.

## [Unreleased]

First release. Enrollment with a one-time token (short-lived keys instead
of a stored API key) and reporting deployment status to KrakenKey are in
progress and will follow in a later release.

### Added

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
