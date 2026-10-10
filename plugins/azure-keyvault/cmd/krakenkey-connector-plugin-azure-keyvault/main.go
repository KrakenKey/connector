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
	plugin.Serve(plugin.ServeOpts{
		KeyStore: keyvault.New(keyvault.Options{}),
		Logger: hclog.New(&hclog.LoggerOptions{
			Name:       "azure-keyvault",
			Output:     os.Stderr,
			Level:      hclog.Info,
			JSONFormat: true,
		}),
	})
}
