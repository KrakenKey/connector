package appgw

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/krakenkey/connector/pkg/plugin"
	"github.com/krakenkey/connector/plugins/azure-appgateway/internal/fakearm"
)

// Ids in the Azure-shaped answers below. None may appear in an error.
var leaks = []string{
	"11111111-2222-3333-4444-555555555555", // application (client) id
	"66666666-7777-8888-9999-000000000000", // object id
	"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", // tenant id
	"12345678-1234-1234-1234-123456789012", // subscription in a scope
	"sts.windows.net",
}

func checkNoLeaks(t *testing.T, err error) {
	t.Helper()
	for _, l := range leaks {
		if strings.Contains(err.Error(), l) {
			t.Errorf("error leaks %q: %v", l, err)
		}
	}
}

const (
	authorizationFailed = "The client '11111111-2222-3333-4444-555555555555' with object id '66666666-7777-8888-9999-000000000000' " +
		"does not have authorization to perform action 'Microsoft.Network/applicationGateways/write' over scope " +
		"'/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/rg-edge/providers/Microsoft.Network/applicationGateways/agw-prod' " +
		"or the scope is invalid. If access was recently granted, please refresh your credentials."
	linkedAuthorizationFailed = "The client '11111111-2222-3333-4444-555555555555' with object id '66666666-7777-8888-9999-000000000000' " +
		"has permission to perform action 'Microsoft.Network/applicationGateways/write' on scope " +
		"'/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/rg-edge/providers/Microsoft.Network/applicationGateways/agw-prod'; " +
		"however, it does not have permission to perform action 'Microsoft.ManagedIdentity/userAssignedIdentities/assign/action' " +
		"on the linked scope(s) '/subscriptions/12345678-1234-1234-1234-123456789012/resourcegroups/rg-edge/providers/Microsoft.ManagedIdentity/userAssignedIdentities/agw-id' " +
		"or the linked scope(s) are invalid."
)

func TestARMErrorsKeepCodesNotMessages(t *testing.T) {
	cases := []struct {
		name  string
		fault fakearm.Fault
		want  []string
	}{
		{"authorization failed", fakearm.Fault{Method: http.MethodPut, Status: 403, Code: "AuthorizationFailed", Message: authorizationFailed},
			[]string{"HTTP 403 AuthorizationFailed, denied action Microsoft.Network/applicationGateways/write", "applicationGateways/write on the gateway"}},
		{"linked authorization failed", fakearm.Fault{Method: http.MethodPut, Status: 403, Code: "LinkedAuthorizationFailed", Message: linkedAuthorizationFailed},
			[]string{"HTTP 403 LinkedAuthorizationFailed, denied action Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"}},
		{"bad request", fakearm.Fault{Method: http.MethodPut, Status: 400, Code: "ApplicationGatewayKeyVaultSecretException",
			Message: "Problem occured while accessing and validating KeyVault Secrets for subscription 12345678-1234-1234-1234-123456789012 by identity 66666666-7777-8888-9999-000000000000."},
			[]string{"HTTP 400 ApplicationGatewayKeyVaultSecretException"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.srv.AddFault(tc.fault)
			_, err := activate(t, f, nil, verNew)
			if !errors.Is(err, plugin.ErrPermanent) {
				t.Fatalf("err = %v", err)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("err %q does not mention %q", err, w)
				}
			}
			if strings.Contains(err.Error(), "refresh your credentials") || strings.Contains(err.Error(), "occured") {
				t.Errorf("err includes Azure's message: %v", err)
			}
			checkNoLeaks(t, err)
		})
	}

	// A failed long-running operation: only the code.
	f := newFixture(t)
	f.srv.NextOpFailure = &fakearm.OpFailure{Code: "ApplicationGatewayKeyVaultSecretException",
		Message: "Access denied for identity 66666666-7777-8888-9999-000000000000 in tenant aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Keep: true}
	_, err := activate(t, f, nil, verNew)
	if err == nil || !strings.Contains(err.Error(), "ApplicationGatewayKeyVaultSecretException") || strings.Contains(err.Error(), "Access denied for identity") {
		t.Errorf("operation failure: %v", err)
	}
	checkNoLeaks(t, err)
}

// failingCred fails every token request with err.
type failingCred struct{ err error }

func (c failingCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, c.err
}

func TestCredentialErrorsKeepStatusAndCode(t *testing.T) {
	entraAnswer := func(status int) *http.Response {
		body := `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID, for a secret added to app '11111111-2222-3333-4444-555555555555'. Trace ID: 66666666-7777-8888-9999-000000000000 Correlation ID: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee Timestamp: 2026-10-11 12:00:00Z","error_codes":[7000215],"trace_id":"66666666-7777-8888-9999-000000000000"}`
		req, _ := http.NewRequest(http.MethodPost, "https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/oauth2/v2.0/token", nil)
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(strings.NewReader(body)), Request: req, Header: http.Header{}}
	}
	cases := []struct {
		name string
		err  error
		kind error
		want string
	}{
		{"rejected", &azidentity.AuthenticationFailedError{RawResponse: entraAnswer(http.StatusUnauthorized)}, plugin.ErrPermanent, "Azure rejected the credential (HTTP 401, AADSTS7000215)"},
		{"entra down", &azidentity.AuthenticationFailedError{RawResponse: entraAnswer(http.StatusServiceUnavailable)}, plugin.ErrUnavailable, "getting an Azure token failed (HTTP 503, AADSTS7000215)"},
		{"other", errors.New("ManagedIdentityCredential: no identity with client ID 11111111-2222-3333-4444-555555555555 at https://sts.windows.net/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/"), plugin.ErrUnavailable, "client ID <id> at <issuer>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tg := newTarget(f.srv)
			tg.opts.Credential = failingCred{tc.err}
			_, err := tg.Current(ctxT(t), plugin.CurrentRequest{Config: cfg(nil)})
			if !errors.Is(err, tc.kind) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %v mentioning %q", err, tc.kind, tc.want)
			}
			if strings.Contains(err.Error(), "Invalid client secret") {
				t.Errorf("err includes Entra's description: %v", err)
			}
			checkNoLeaks(t, err)
		})
	}
}
