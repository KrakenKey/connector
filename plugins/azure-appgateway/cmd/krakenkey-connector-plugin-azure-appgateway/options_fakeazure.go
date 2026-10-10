//go:build fakeazure

package main

import (
	"context"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/krakenkey/connector/plugins/azure-appgateway/internal/appgw"
)

// This file is compiled only with -tags fakeazure, for the go-plugin
// harness test. Release builds must never use that tag (a test checks the
// release configs). As a second guard, a fakeazure build only talks to a
// loopback address and refuses to start otherwise.

// FakeEndpointEnv names the fake ARM endpoint for test builds.
const FakeEndpointEnv = "KRAKENKEY_AGW_FAKE_ARM_ENDPOINT"

type staticToken struct{}

func (staticToken) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "fake-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func options() appgw.Options {
	endpoint := os.Getenv(FakeEndpointEnv)
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || !isLoopback(u.Hostname()) {
		panic("fakeazure build: " + FakeEndpointEnv + " must be an http:// loopback URL")
	}
	return appgw.Options{
		Credential: staticToken{},
		ClientOptions: &arm.ClientOptions{ClientOptions: policy.ClientOptions{
			Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
				cloud.ResourceManager: {Endpoint: endpoint, Audience: "https://management.core.windows.net/"},
			}},
			InsecureAllowCredentialWithHTTP: true,
			Retry:                           policy.RetryOptions{MaxRetries: -1},
		}},
		PollFrequency: 20 * time.Millisecond,
		ReportReserve: 500 * time.Millisecond,
	}
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
