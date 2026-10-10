// Command krakenkey-connector-plugin-azure-appgateway is a KrakenKey
// connector target plugin that points an Azure Application Gateway v2 SSL
// certificate at a specific Key Vault secret version.
//
// The connector starts it; running it by hand prints a short notice and
// exits.
package main

import (
	"github.com/krakenkey/connector/pkg/plugin"

	"github.com/krakenkey/connector/plugins/azure-appgateway/internal/appgw"
)

func main() {
	plugin.Serve(plugin.ServeOpts{Target: appgw.New(options())})
}
