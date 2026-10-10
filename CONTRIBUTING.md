# Contributing

Thanks for helping out. Bug reports and pull requests are welcome.

## Requirements

- Go 1.26
- [golangci-lint](https://golangci-lint.run/) v2.13.2 for linting

## Checks

Run these before opening a pull request. CI runs the same ones.

```sh
go test ./... -race
golangci-lint run
```

## Commit messages

Commits and pull request titles follow [Conventional Commits](https://www.conventionalcommits.org/):
`type(scope): summary`, for example `feat(target): add a rollback check`.
Pull requests are squash-merged, so the title becomes the commit on `main`.

## Plugin protocol

The gRPC services that plugins implement are defined in
[`proto/krakenkey/connector/plugin/v1/plugin.proto`](proto/krakenkey/connector/plugin/v1/plugin.proto).
The generated Go code next to it is committed, so building the connector or a
plugin does not need any protobuf tooling.

After changing the `.proto` file, regenerate and commit the result:

```sh
make proto
```

This runs [`scripts/protogen.sh`](scripts/protogen.sh), which installs pinned
versions of `buf`, `protoc-gen-go` and `protoc-gen-go-grpc` into `.bin/`
(ignored by git), lints the proto file with `buf lint`, and runs
`buf generate`. CI fails if the committed code differs from what the script
produces.

Within `v1`, only make backward compatible changes: add fields and RPCs, never
renumber, rename or remove them. A change that breaks existing plugins needs a
new package version (`v2`) and a new `ProtocolVersion` in `pkg/plugin`.
