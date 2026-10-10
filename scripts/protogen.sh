#!/bin/sh
# Regenerates the Go code for the plugin protocol from proto/.
# Tools are installed at pinned versions into .bin/ so the output does not
# depend on whatever happens to be on PATH.
set -eu

BUF_VERSION=v1.73.0
PROTOC_GEN_GO_VERSION=v1.36.12
PROTOC_GEN_GO_GRPC_VERSION=v1.6.2

root=$(cd "$(dirname "$0")/.." && pwd)
bin="$root/.bin"
mkdir -p "$bin"

GOBIN="$bin" go install "github.com/bufbuild/buf/cmd/buf@$BUF_VERSION"
GOBIN="$bin" go install "google.golang.org/protobuf/cmd/protoc-gen-go@$PROTOC_GEN_GO_VERSION"
GOBIN="$bin" go install "google.golang.org/grpc/cmd/protoc-gen-go-grpc@$PROTOC_GEN_GO_GRPC_VERSION"

cd "$root"
PATH="$bin:$PATH" buf lint
PATH="$bin:$PATH" buf generate
