//go:build !fakeazure

package main

import "github.com/krakenkey/connector/plugins/azure-appgateway/internal/appgw"

// options returns the production settings: DefaultAzureCredential against
// Azure's public cloud.
func options() appgw.Options { return appgw.Options{} }
