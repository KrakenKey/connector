package appgw

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/krakenkey/connector/plugins/azure-appgateway/internal/fakearm"
)

const (
	sub      = "00000000-0000-0000-0000-000000000001"
	rg       = "rg-edge"
	gwName   = "agw-prod"
	certName = "app-cert"
)

var (
	verOld = strings.Repeat("a", 32)
	verNew = strings.Repeat("b", 32)
)

func secret(version string) string {
	return "https://kv-test.vault.azure.net/secrets/app-cert/" + version
}

type fakeCred struct{}

func (fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// fixture is a fake ARM server with one v2 gateway whose app-cert entry
// points at the old version, and a target wired to it.
type fixture struct {
	srv *fakearm.Server
	tg  *Target
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	srv := fakearm.New()
	t.Cleanup(srv.Close)
	srv.Certs[secret(verOld)] = [][]byte{fakearm.TestCert(0x0a01)}
	srv.Certs[secret(verNew)] = [][]byte{fakearm.TestCert(0x0b02)}
	srv.PutGateway(sub, rg, gwName, fakearm.V2Gateway(sub, rg, gwName, certName, secret(verOld)))
	return &fixture{srv: srv, tg: newTarget(srv)}
}

func newTarget(srv *fakearm.Server) *Target {
	return New(Options{
		Credential: fakeCred{},
		ClientOptions: &arm.ClientOptions{ClientOptions: policy.ClientOptions{
			Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
				cloud.ResourceManager: {Endpoint: srv.URL, Audience: "https://management.core.windows.net/"},
			}},
			InsecureAllowCredentialWithHTTP: true,
			Retry:                           policy.RetryOptions{MaxRetries: -1},
		}},
		PollFrequency: time.Millisecond,
		ReportReserve: 200 * time.Millisecond,
	})
}

func (f *fixture) gateway() map[string]any { return f.srv.Gateway(sub, rg, gwName) }

func (f *fixture) setGateway(g map[string]any) { f.srv.PutGateway(sub, rg, gwName, g) }

func (f *fixture) secretID(t *testing.T) string {
	t.Helper()
	id, ok := f.srv.SecretID(sub, rg, gwName, certName)
	if !ok {
		t.Fatalf("gateway has no %s entry", certName)
	}
	return id
}

func cfg(extra map[string]any) json.RawMessage {
	m := map[string]any{
		"subscription_id": sub,
		"resource_group":  rg,
		"gateway":         gwName,
		"ssl_certificate": certName,
	}
	for k, v := range extra {
		if v == nil {
			delete(m, k)
			continue
		}
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// props returns the properties map of a gateway body.
func props(g map[string]any) map[string]any {
	p, _ := g["properties"].(map[string]any)
	return p
}
