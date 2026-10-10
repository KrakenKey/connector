// Command krakenkey-connector-plugin-aws-acm is a KrakenKey connector target
// plugin that re-imports certificates into AWS Certificate Manager.
package main

import (
	"github.com/krakenkey/connector/pkg/plugin"
	"github.com/krakenkey/connector/plugins/aws-acm/internal/acmtarget"
)

func main() {
	plugin.Serve(plugin.ServeOpts{Target: acmtarget.New()})
}
