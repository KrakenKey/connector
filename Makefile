.PHONY: build test lint proto

build:
	CGO_ENABLED=0 go build -o krakenkey-connector ./cmd/krakenkey-connector

test:
	go test ./... -race

lint:
	golangci-lint run

# Regenerate the protobuf and gRPC code. Commit the result.
proto:
	./scripts/protogen.sh
