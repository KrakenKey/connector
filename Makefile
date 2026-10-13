.PHONY: build test lint proto azure-template azure-template-check azure-test azure-package

build:
	CGO_ENABLED=0 go build -o krakenkey-connector ./cmd/krakenkey-connector

test:
	go test ./... -race

lint:
	golangci-lint run

# Regenerate the protobuf and gRPC code. Commit the result.
proto:
	./scripts/protogen.sh

# Compile deploy/azure/main.bicep into mainTemplate.json. Commit the result.
azure-template:
	deploy/azure/build.sh

# Check that deploy/azure/mainTemplate.json matches main.bicep.
azure-template-check:
	deploy/azure/build.sh --check

# Run the ARM template test toolkit and the cloud-init schema check.
azure-test:
	deploy/azure/test.sh

# Build the Microsoft Marketplace zip in dist/azure/.
azure-package:
	deploy/azure/package.sh
