//go:build fakeazure

package main

import (
	"context"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/krakenkey/connector/plugins/azure-appgateway/internal/appgw"
)

// FakeEndpointEnv names the fake ARM endpoint for test builds. Built only
// with -tags fakeazure, for the go-plugin harness test; release builds
// never contain this file.
const FakeEndpointEnv = "KRAKENKEY_AGW_FAKE_ARM_ENDPOINT"

type staticToken struct{}

func (staticToken) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "fake-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func options() appgw.Options {
	endpoint := os.Getenv(FakeEndpointEnv)
	if endpoint == "" {
		panic(FakeEndpointEnv + " must be set in a fakeazure build")
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
