# KrakenKey Connector

A service you run on your own infrastructure that renews
[KrakenKey](https://krakenkey.io) certificates and deploys them to your
systems. KrakenKey coordinates issuance; the connector holds the private keys
and the access to your servers, and only makes outbound connections.

> **Status:** pre-release (v0). The plugin protocol and configuration may
> still change.

## Plugins

Integrations are plugins: separate executables that the connector starts and
talks to over gRPC, using
[hashicorp/go-plugin](https://github.com/hashicorp/go-plugin) (the same model
Terraform uses for providers). A plugin plays one or both of two roles:

- **Key store**: decides where the private key lives and produces the CSR.
- **Target**: installs an issued certificate, can report what is installed,
  and can roll back.

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

Before deploying, the connector checks that each key store and target can
work together (`plugin.Match`). For example, a key store that keeps keys
non-exportable cannot feed a target that needs the key as a PEM file, and an
ECDSA key cannot go to a target that only serves RSA.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE)
