// Command krakenkey-connector-plugin-azure-keyvault is a KrakenKey
// connector key store plugin that keeps keys and certificates in Azure Key
// Vault. The connector starts it; running it by hand prints a notice and
// exits.
package main

import (
	"os"

	"github.com/hashicorp/go-hclog"

	"github.com/krakenkey/connector/pkg/plugin"
	"github.com/krakenkey/connector/plugins/azure-keyvault/internal/keyvault"
)

func main() {
	// go-plugin forwards these stderr lines into the connector's log.
	logger := hclog.New(&hclog.LoggerOptions{
		Name:       "azure-keyvault",
		Output:     os.Stderr,
		Level:      hclog.Info,
		JSONFormat: true,
	})
	plugin.Serve(plugin.ServeOpts{
		KeyStore: keyvault.New(keyvault.Options{Logger: logger}),
		Logger:   logger,
	})
}
