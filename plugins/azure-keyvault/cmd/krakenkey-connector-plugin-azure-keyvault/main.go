// Command krakenkey-connector-plugin-azure-keyvault is a KrakenKey
// connector plugin for Azure Key Vault: a key store that keeps keys and
// certificates in Key Vault, and a target that deploys certificates to Key
// Vault certificates. The connector starts it; running it by hand prints a
// notice and exits.
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
	ks := keyvault.New(keyvault.Options{Logger: logger})
	plugin.Serve(plugin.ServeOpts{
		KeyStore: ks,
		Target:   keyvault.NewTarget(ks),
		Logger:   logger,
	})
}
