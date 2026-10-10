// Command krakenkey-connector-plugin-azure-appgateway is a KrakenKey
// connector target plugin that points an Azure Application Gateway v2 SSL
// certificate at a specific Key Vault secret version.
//
// The connector starts it; running it by hand prints a short notice and
// exits.
package main

import (
	"os"

	"github.com/hashicorp/go-hclog"

	"github.com/krakenkey/connector/pkg/plugin"

	"github.com/krakenkey/connector/plugins/azure-appgateway/internal/appgw"
)

func main() {
	opts := options()
	// go-plugin reads JSON log lines from stderr into the connector's log.
	opts.Logger = hclog.New(&hclog.LoggerOptions{Name: "azure-appgateway", Output: os.Stderr, JSONFormat: true, Level: hclog.Info})
	plugin.Serve(plugin.ServeOpts{Target: appgw.New(opts)})
}
