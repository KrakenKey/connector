package appgw

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/krakenkey/connector/pkg/plugin"
	"github.com/krakenkey/connector/plugins/azure-appgateway/internal/fakearm"
)

func TestDescribe(t *testing.T) {
	caps, err := New(Options{}).Describe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(caps.Accepts) != 1 || caps.Accepts[0] != plugin.KeyFormatVaultRef {
		t.Errorf("accepts %v", caps.Accepts)
	}
	if !caps.NeedsExportableKey || !caps.SupportsRollback || caps.PropagatesAsync {
		t.Errorf("caps %+v", caps)
	}
	if caps.DefaultVerifyWindow != 10*time.Minute {
		t.Errorf("verify window %s", caps.DefaultVerifyWindow)
	}
	for _, k := range caps.KeyTypes {
		if !k.IsRSA() {
			t.Errorf("key type %s listed", k)
		}
	}
	// A key store that provides vault refs of exportable RSA keys matches.
	ks := plugin.KeyStoreCapabilities{Provides: []plugin.KeyFormat{plugin.KeyFormatVaultRef}, Exportable: true, KeyTypes: []plugin.KeyType{plugin.KeyTypeRSA2048}}
	if f, err := plugin.Match(ks, caps, plugin.KeyTypeRSA2048); err != nil || f != plugin.KeyFormatVaultRef {
		t.Errorf("Match = %s, %v", f, err)
	}
	ks.Exportable = false
	if _, err := plugin.Match(ks, caps, plugin.KeyTypeRSA2048); err == nil {
		t.Error("a non-exportable key store should not match")
	}
}

func TestValidate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		f := newFixture(t)
		problems, err := f.tg.Validate(ctxT(t), plugin.TargetValidateRequest{Config: cfg(nil)})
		if err != nil || len(problems) != 0 {
			t.Fatalf("problems %v, err %v", problems, err)
		}
	})
	t.Run("bad config", func(t *testing.T) {
		f := newFixture(t)
		problems, err := f.tg.Validate(ctxT(t), plugin.TargetValidateRequest{Config: cfg(map[string]any{"gateway": nil})})
		if err != nil || len(problems) != 1 || !strings.Contains(problems[0], "gateway is required") {
			t.Fatalf("problems %v, err %v", problems, err)
		}
		if strings.HasPrefix(problems[0], "permanent failure") {
			t.Errorf("problem carries the error kind prefix: %q", problems[0])
		}
	})
	t.Run("v1 sku and no identity", func(t *testing.T) {
		f := newFixture(t)
		g := f.gateway()
		props(g)["sku"] = map[string]any{"name": "Standard_Medium", "tier": "Standard"}
		delete(g, "identity")
		f.setGateway(g)
		problems, err := f.tg.Validate(ctxT(t), plugin.TargetValidateRequest{Config: cfg(nil)})
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(problems, "\n")
		if len(problems) != 2 || !strings.Contains(joined, "SKU is Standard") || !strings.Contains(joined, "user-assigned managed identity") {
			t.Fatalf("problems %v", problems)
		}
	})
	t.Run("system-assigned identity only", func(t *testing.T) {
		f := newFixture(t)
		g := f.gateway()
		g["identity"] = map[string]any{"type": "SystemAssigned"}
		f.setGateway(g)
		problems, _ := f.tg.Validate(ctxT(t), plugin.TargetValidateRequest{Config: cfg(nil)})
		if len(problems) != 1 || !strings.Contains(problems[0], "user-assigned") {
			t.Fatalf("problems %v", problems)
		}
	})
	t.Run("missing entry", func(t *testing.T) {
		f := newFixture(t)
		problems, err := f.tg.Validate(ctxT(t), plugin.TargetValidateRequest{Config: cfg(map[string]any{"ssl_certificate": "other"})})
		if err != nil || len(problems) != 1 || !strings.Contains(problems[0], `no ssl certificate named "other"`) {
			t.Fatalf("problems %v, err %v", problems, err)
		}
	})
	t.Run("uploaded certificate", func(t *testing.T) {
		f := newFixture(t)
		f.setGateway(uploadedGateway())
		problems, err := f.tg.Validate(ctxT(t), plugin.TargetValidateRequest{Config: cfg(nil)})
		if err != nil || len(problems) != 1 || !strings.Contains(problems[0], "replace_uploaded_certificate") {
			t.Fatalf("problems %v, err %v", problems, err)
		}
		problems, err = f.tg.Validate(ctxT(t), plugin.TargetValidateRequest{Config: cfg(map[string]any{"replace_uploaded_certificate": true})})
		if err != nil || len(problems) != 0 {
			t.Fatalf("with replace_uploaded_certificate: problems %v, err %v", problems, err)
		}
	})
	t.Run("versionless entry is not a problem", func(t *testing.T) {
		f := newFixture(t)
		f.setGateway(fakearm.V2Gateway(sub, rg, gwName, certName, "https://kv-test.vault.azure.net/secrets/app-cert/"))
		problems, err := f.tg.Validate(ctxT(t), plugin.TargetValidateRequest{Config: cfg(nil)})
		if err != nil || len(problems) != 0 {
			t.Fatalf("problems %v, err %v", problems, err)
		}
	})
	t.Run("gateway not found", func(t *testing.T) {
		f := newFixture(t)
		problems, err := f.tg.Validate(ctxT(t), plugin.TargetValidateRequest{Config: cfg(map[string]any{"gateway": "nope"})})
		if err != nil || len(problems) != 1 || !strings.Contains(problems[0], "not found") {
			t.Fatalf("problems %v, err %v", problems, err)
		}
	})
	t.Run("forbidden", func(t *testing.T) {
		f := newFixture(t)
		f.srv.AddFault(fakearm.Fault{Method: http.MethodGet, Status: http.StatusForbidden, Code: "AuthorizationFailed",
			Message: "The client does not have authorization to perform action 'Microsoft.Network/applicationGateways/read'."})
		_, err := f.tg.Validate(ctxT(t), plugin.TargetValidateRequest{Config: cfg(nil)})
		if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "Microsoft.Network/applicationGateways/read") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestCurrent(t *testing.T) {
	f := newFixture(t)
	got, err := f.tg.Current(ctxT(t), plugin.CurrentRequest{Config: cfg(nil)})
	if err != nil || got != "a01" {
		t.Fatalf("Current = %q, %v; want a01", got, err)
	}

	// Versionless, or a secret the gateway reports no certificate data for.
	g := fakearm.V2Gateway(sub, rg, gwName, certName, "https://kv-test.vault.azure.net/secrets/app-cert/")
	f.setGateway(g)
	if got, err := f.tg.Current(ctxT(t), plugin.CurrentRequest{Config: cfg(nil)}); err != nil || got != "" {
		t.Errorf("no publicCertData: Current = %q, %v", got, err)
	}
	if got, err := f.tg.Current(ctxT(t), plugin.CurrentRequest{Config: cfg(map[string]any{"ssl_certificate": "other"})}); err != nil || got != "" {
		t.Errorf("missing entry: Current = %q, %v", got, err)
	}
	f.srv.AddFault(fakearm.Fault{Method: http.MethodGet, Status: http.StatusTooManyRequests, Code: "TooManyRequests"})
	if _, err := f.tg.Current(ctxT(t), plugin.CurrentRequest{Config: cfg(nil)}); !errors.Is(err, plugin.ErrUnavailable) {
		t.Errorf("429: err = %v", err)
	}
}

func TestStage(t *testing.T) {
	tg := New(Options{})
	ctx := context.Background()
	key := plugin.KeyMaterial{Format: plugin.KeyFormatVaultRef, Ref: "https://KV-TEST.vault.azure.net/secrets/app-cert/" + strings.ToUpper(verNew)}
	ref, err := tg.Stage(ctx, plugin.StageRequest{Config: cfg(nil), Key: key})
	if err != nil || ref != secret(verNew) {
		t.Fatalf("Stage = %q, %v", ref, err)
	}

	bad := map[string]plugin.StageRequest{
		"pem key":     {Config: cfg(nil), Key: plugin.KeyMaterial{Format: plugin.KeyFormatPEM, Data: []byte("x")}},
		"versionless": {Config: cfg(nil), Key: plugin.KeyMaterial{Format: plugin.KeyFormatVaultRef, Ref: "https://kv-test.vault.azure.net/secrets/app-cert/"}},
		"not a vault": {Config: cfg(nil), Key: plugin.KeyMaterial{Format: plugin.KeyFormatVaultRef, Ref: "https://example.com/x"}},
		"bad config":  {Config: cfg(map[string]any{"subscription_id": nil}), Key: key},
	}
	for name, req := range bad {
		if _, err := tg.Stage(ctx, req); !errors.Is(err, plugin.ErrPermanent) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestDiscard(t *testing.T) {
	tg := New(Options{})
	for _, ref := range []string{"", secret(verNew), "garbage"} {
		if err := tg.Discard(context.Background(), plugin.DiscardRequest{Config: cfg(nil), StagedRef: ref}); err != nil {
			t.Errorf("Discard(%q) = %v", ref, err)
		}
	}
}

func activate(t *testing.T, f *fixture, extra map[string]any, version string) (string, error) {
	t.Helper()
	return f.tg.Activate(ctxT(t), plugin.ActivateRequest{Config: cfg(extra), StagedRef: secret(version)})
}

func decodeRef(t *testing.T, ref string) previousRef {
	t.Helper()
	var p previousRef
	if err := json.Unmarshal([]byte(ref), &p); err != nil {
		t.Fatalf("previous ref %q is not JSON: %v", ref, err)
	}
	return p
}

func rollback(t *testing.T, f *fixture, ref string) error {
	t.Helper()
	return f.tg.Rollback(ctxT(t), plugin.RollbackRequest{Config: cfg(nil), PreviousRef: ref})
}

// uploadedGateway has the app-cert entry holding an uploaded PFX.
func uploadedGateway() map[string]any {
	g := fakearm.V2Gateway(sub, rg, gwName, certName, "")
	props(g)["sslCertificates"] = []any{map[string]any{"name": certName, "properties": map[string]any{"publicCertData": "AAAA"}}}
	return g
}

func TestActivateAndRollback(t *testing.T) {
	f := newFixture(t)
	// A second, uploaded certificate on the gateway must survive the PUT.
	g := f.gateway()
	props(g)["sslCertificates"] = append(props(g)["sslCertificates"].([]any), map[string]any{
		"name": "legacy", "properties": map[string]any{"publicCertData": "AAAA"},
	})
	f.setGateway(g)
	etag := f.gateway()["etag"].(string)

	prev, err := activate(t, f, nil, verNew)
	if err != nil {
		t.Fatal(err)
	}
	if p := decodeRef(t, prev); p.Restore != secret(verOld) || p.Over != secret(verNew) || p.Unrestorable != "" {
		t.Errorf("previous ref %+v", p)
	}
	if got := f.secretID(t); got != secret(verNew) {
		t.Errorf("gateway points at %s", got)
	}
	var put *fakearm.Request
	for _, r := range f.srv.Requests() {
		if r.Method == http.MethodPut {
			put = &r
		}
	}
	if put == nil || put.IfMatch != etag {
		t.Fatalf("PUT If-Match = %+v, want %s", put, etag)
	}
	for _, c := range props(put.Body)["sslCertificates"].([]any) {
		cm := c.(map[string]any)
		cp := cm["properties"].(map[string]any)
		switch cm["name"] {
		case certName:
			if _, ok := cp["data"]; ok {
				t.Error("PUT carried PFX data for the Key Vault entry")
			}
			if _, ok := cp["password"]; ok {
				t.Error("PUT carried a password for the Key Vault entry")
			}
		case "legacy":
			if cp["publicCertData"] != "AAAA" {
				t.Errorf("legacy entry changed: %v", cp)
			}
		}
	}
	if p := props(f.gateway())["provisioningState"]; p != "Succeeded" {
		t.Errorf("provisioning state %v", p)
	}
	if s, _ := f.tg.Current(ctxT(t), plugin.CurrentRequest{Config: cfg(nil)}); s != "b02" {
		t.Errorf("Current after activate = %q", s)
	}

	if err := rollback(t, f, prev); err != nil {
		t.Fatal(err)
	}
	if got := f.secretID(t); got != secret(verOld) {
		t.Errorf("after rollback the gateway points at %s", got)
	}
	// Rolling back again finds the old version in place and changes nothing.
	puts := f.srv.Count(http.MethodPut)
	if err := rollback(t, f, prev); err != nil || f.srv.Count(http.MethodPut) != puts {
		t.Errorf("second rollback: err %v, PUTs %d -> %d", err, puts, f.srv.Count(http.MethodPut))
	}
}

// Activating a version the gateway already shows must not record it as the
// previous state: a rollback would then write the new version back and
// report success.
func TestActivateWhenAlreadyActiveCannotBeRolledBack(t *testing.T) {
	f := newFixture(t)
	f.srv.SetSecretID(sub, rg, gwName, certName, secret(verNew))
	prev, err := activate(t, f, nil, verNew)
	if err != nil {
		t.Fatal(err)
	}
	if f.srv.Count(http.MethodPut) != 0 {
		t.Error("activating the version already in place wrote to the gateway")
	}
	if p := decodeRef(t, prev); p.Unrestorable != reasonAlreadyActive || p.Restore != "" {
		t.Fatalf("previous ref %+v", p)
	}
	if err := rollback(t, f, prev); !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("rollback err = %v", err)
	}
}

// lossyTransport forwards the first PUT to the server, then answers 502 as
// if the response was lost at the ARM front door.
type lossyTransport struct {
	mu   sync.Mutex
	done bool
}

func (l *lossyTransport) Do(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultClient.Do(req)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err == nil && req.Method == http.MethodPut && !l.done {
		l.done = true
		_ = resp.Body.Close()
		return &http.Response{StatusCode: http.StatusBadGateway, Header: http.Header{},
			Body: io.NopCloser(strings.NewReader(`{"error":{"code":"BadGateway","message":"lost"}}`)), Request: req}, nil
	}
	return resp, err
}

// Regression: with SDK retries on, a PUT whose response was lost was
// retried with the old If-Match, got 412, and the re-read then reported
// the new secret as the previous state.
func TestActivateLostPutResponse(t *testing.T) {
	f := newFixture(t)
	f.srv.HangOps = true // the accepted update is still running when we look
	tg := New(Options{
		Credential: fakeCred{},
		ClientOptions: &arm.ClientOptions{ClientOptions: policy.ClientOptions{
			Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
				cloud.ResourceManager: {Endpoint: f.srv.URL, Audience: "https://management.core.windows.net/"},
			}},
			InsecureAllowCredentialWithHTTP: true,
			// SDK retries on, as in production: the plugin must turn them
			// off for the PUT.
			Retry:     policy.RetryOptions{RetryDelay: time.Millisecond, MaxRetryDelay: time.Millisecond},
			Transport: &lossyTransport{},
		}},
		PollFrequency: time.Millisecond, ReportReserve: 200 * time.Millisecond,
	})
	prev, err := tg.Activate(ctxT(t), plugin.ActivateRequest{Config: cfg(nil), StagedRef: secret(verNew)})
	if err == nil {
		t.Fatalf("Activate succeeded with previous ref %q after a lost response", prev)
	}
	if !errors.Is(err, plugin.ErrUnavailable) || !strings.Contains(err.Error(), "no clear answer") || !strings.Contains(err.Error(), "Updating") {
		t.Errorf("err = %v", err)
	}
	if n := f.srv.Count(http.MethodPut); n != 1 {
		t.Errorf("%d PUTs; the PUT must not be retried by the SDK", n)
	}

	// The update finishes later. Activating again must not claim the new
	// version was live before.
	f.srv.HangOps = false
	g := f.gateway()
	props(g)["provisioningState"] = "Succeeded"
	f.setGateway(g)
	prev, err = tg.Activate(ctxT(t), plugin.ActivateRequest{Config: cfg(nil), StagedRef: secret(verNew)})
	if err != nil {
		t.Fatal(err)
	}
	if p := decodeRef(t, prev); p.Restore == secret(verNew) || p.Unrestorable != reasonAlreadyActive {
		t.Errorf("previous ref %+v", p)
	}
	if err := tg.Rollback(ctxT(t), plugin.RollbackRequest{Config: cfg(nil), PreviousRef: prev}); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("rollback err = %v", err)
	}
}

// Regression: retrying after an activation that timed out but finished in
// Azure returned the new secret as the previous ref.
func TestActivateAgainAfterStillRunning(t *testing.T) {
	f := newFixture(t)
	f.srv.HangOps = true
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := f.tg.Activate(ctx, plugin.ActivateRequest{Config: cfg(nil), StagedRef: secret(verNew)}); !errors.Is(err, plugin.ErrUnavailable) {
		t.Fatalf("first activate err = %v", err)
	}
	f.srv.HangOps = false
	g := f.gateway()
	props(g)["provisioningState"] = "Succeeded"
	f.setGateway(g)
	prev, err := activate(t, f, nil, verNew)
	if err != nil {
		t.Fatal(err)
	}
	if p := decodeRef(t, prev); p.Restore == secret(verNew) || p.Unrestorable != reasonAlreadyActive {
		t.Errorf("previous ref %+v", p)
	}
	if err := rollback(t, f, prev); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("rollback err = %v", err)
	}
	if got := f.secretID(t); got != secret(verNew) {
		t.Errorf("refused rollback changed the gateway to %s", got)
	}
}

func TestRollbackRefusesWhenChangedSinceActivation(t *testing.T) {
	f := newFixture(t)
	prev, err := activate(t, f, nil, verNew)
	if err != nil {
		t.Fatal(err)
	}
	other := secret(strings.Repeat("c", 32))
	f.srv.SetSecretID(sub, rg, gwName, certName, other) // an operator's change
	puts := f.srv.Count(http.MethodPut)
	err = rollback(t, f, prev)
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "changed since") {
		t.Fatalf("err = %v", err)
	}
	if got := f.secretID(t); got != other || f.srv.Count(http.MethodPut) != puts {
		t.Errorf("rollback overwrote the operator's change: %s", got)
	}
}

func TestRollbackRestoresVersionlessIDOfAnotherSecret(t *testing.T) {
	f := newFixture(t)
	versionless := "https://KV-Test.vault.azure.net/secrets/old-cert"
	f.setGateway(fakearm.V2Gateway(sub, rg, gwName, certName, versionless))
	prev, err := activate(t, f, nil, verNew)
	if err != nil {
		t.Fatal(err)
	}
	if p := decodeRef(t, prev); p.Restore != versionless {
		t.Fatalf("previous ref %+v", p)
	}
	if err := rollback(t, f, prev); err != nil {
		t.Fatal(err)
	}
	if got := f.secretID(t); got != versionless {
		t.Errorf("restored %q, want %q", got, versionless)
	}
}

// A versionless ID of the secret the key store writes to already resolves
// to the new version, so putting it back would change nothing.
func TestRollbackRefusesVersionlessIDOfTheSameSecret(t *testing.T) {
	f := newFixture(t)
	f.setGateway(fakearm.V2Gateway(sub, rg, gwName, certName, "https://KV-Test.vault.azure.net/secrets/App-Cert/"))
	prev, err := activate(t, f, nil, verNew)
	if err != nil {
		t.Fatal(err)
	}
	if p := decodeRef(t, prev); p.Unrestorable != reasonVersionlessSameSecret || p.Restore != "" {
		t.Fatalf("previous ref %+v", p)
	}
	if err := rollback(t, f, prev); !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "versionless") {
		t.Fatalf("rollback err = %v", err)
	}
}

func TestRollbackRefs(t *testing.T) {
	f := newFixture(t)
	over := secret(verNew)
	cases := map[string]error{
		"": plugin.ErrPermanent,
		previousRef{V: 1, Unrestorable: reasonUploaded, Over: over}.encode(): plugin.ErrPermanent,
		"garbage":               plugin.ErrNotFound,
		"https://example.com/x": plugin.ErrNotFound,
		secret(verOld):          plugin.ErrNotFound, // the old plain form
		`{"v":2,"restore":"x","over":"` + over + `"}`:           plugin.ErrNotFound,
		`{"v":1,"restore":"x"}`:                                 plugin.ErrNotFound,
		`{"v":1,"over":"` + over + `"}`:                         plugin.ErrNotFound,
		`{"v":1,"restore":"x","over":"` + over + `","extra":1}`: plugin.ErrNotFound,
	}
	for ref, want := range cases {
		if err := rollback(t, f, ref); !errors.Is(err, want) {
			t.Errorf("Rollback(%q) = %v, want %v", ref, err, want)
		}
	}
	if f.srv.Count(http.MethodPut) != 0 {
		t.Error("a refused rollback wrote to the gateway")
	}
}

func TestActivateMissingEntry(t *testing.T) {
	f := newFixture(t)
	g := fakearm.V2Gateway(sub, rg, gwName, certName, "")
	props(g)["httpListeners"] = []any{}
	f.setGateway(g)
	if _, err := activate(t, f, nil, verNew); !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "no ssl certificate named") {
		t.Fatalf("err = %v", err)
	}
	if f.srv.Count(http.MethodPut) != 0 {
		t.Error("wrote to the gateway")
	}
}

func TestActivateOverUploadedCertificate(t *testing.T) {
	f := newFixture(t)
	f.setGateway(uploadedGateway())
	_, err := activate(t, f, nil, verNew)
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "replace_uploaded_certificate") {
		t.Fatalf("without replace_uploaded_certificate: %v", err)
	}
	if f.srv.Count(http.MethodPut) != 0 {
		t.Fatal("replaced the uploaded certificate without replace_uploaded_certificate")
	}

	prev, err := activate(t, f, map[string]any{"replace_uploaded_certificate": true}, verNew)
	if err != nil {
		t.Fatal(err)
	}
	if p := decodeRef(t, prev); p.Unrestorable != reasonUploaded {
		t.Fatalf("previous ref %+v", p)
	}
	if got := f.secretID(t); got != secret(verNew) {
		t.Errorf("gateway points at %s", got)
	}
	if err := rollback(t, f, prev); !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "uploaded") {
		t.Fatalf("rollback err = %v", err)
	}
}

func TestActivateRejectsBadGateways(t *testing.T) {
	t.Run("v1 sku", func(t *testing.T) {
		f := newFixture(t)
		g := f.gateway()
		props(g)["sku"] = map[string]any{"name": "WAF_Large", "tier": "WAF"}
		f.setGateway(g)
		if _, err := activate(t, f, nil, verNew); !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "v2") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no identity", func(t *testing.T) {
		f := newFixture(t)
		g := f.gateway()
		delete(g, "identity")
		f.setGateway(g)
		if _, err := activate(t, f, nil, verNew); !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "managed identity") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bad staged ref", func(t *testing.T) {
		f := newFixture(t)
		for _, ref := range []string{"", "garbage", "https://kv-test.vault.azure.net/secrets/app-cert/"} {
			if _, err := f.tg.Activate(ctxT(t), plugin.ActivateRequest{Config: cfg(nil), StagedRef: ref}); !errors.Is(err, plugin.ErrInvalid) {
				t.Errorf("staged ref %q: err = %v", ref, err)
			}
		}
	})
	t.Run("gateway gone", func(t *testing.T) {
		f := newFixture(t)
		if _, err := activate(t, f, map[string]any{"gateway": "gone"}, verNew); !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestActivateRetriesOnPreconditionFailed(t *testing.T) {
	f := newFixture(t)
	f.srv.ConcurrentWrites = 2
	if _, err := activate(t, f, nil, verNew); err != nil {
		t.Fatal(err)
	}
	if n := f.srv.Count(http.MethodPut); n != 3 {
		t.Errorf("%d PUTs, want 3", n)
	}
	if n := f.srv.Count(http.MethodGet); n != 4 { // 3 reads + the final GET after the operation
		t.Errorf("%d GETs, want 4", n)
	}
	if got := f.secretID(t); got != secret(verNew) {
		t.Errorf("gateway points at %s", got)
	}
}

func TestActivateGivesUpAfterRepeatedPreconditionFailures(t *testing.T) {
	f := newFixture(t)
	f.srv.ConcurrentWrites = 100
	_, err := activate(t, f, nil, verNew)
	if !errors.Is(err, plugin.ErrUnavailable) || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("err = %v", err)
	}
	if n := f.srv.Count(http.MethodPut); n != DefaultMaxAttempts {
		t.Errorf("%d PUTs, want %d", n, DefaultMaxAttempts)
	}
	if got := f.secretID(t); got != secret(verOld) {
		t.Errorf("gateway points at %s", got)
	}
}

// If the concurrent writer already set the staged version, the previous
// state is still the one first read, not the staged version.
func TestActivateRetryFindsStagedVersion(t *testing.T) {
	f := newFixture(t)
	f.srv.ConcurrentWrites = 1
	f.srv.OnConcurrentWrite = func(g map[string]any) { fakearm.SetEntrySecretID(g, certName, secret(verNew)) }
	prev, err := activate(t, f, nil, verNew)
	if err != nil {
		t.Fatal(err)
	}
	if p := decodeRef(t, prev); p.Restore != secret(verOld) {
		t.Errorf("previous ref %+v, want restore %s", p, secret(verOld))
	}
}

func TestActivateRetryFindsEntryChanged(t *testing.T) {
	f := newFixture(t)
	other := secret(strings.Repeat("c", 32))
	f.srv.ConcurrentWrites = 1
	f.srv.OnConcurrentWrite = func(g map[string]any) { fakearm.SetEntrySecretID(g, certName, other) }
	_, err := activate(t, f, nil, verNew)
	if !errors.Is(err, plugin.ErrUnavailable) || !strings.Contains(err.Error(), "changed from") {
		t.Fatalf("err = %v", err)
	}
	if got := f.secretID(t); got != other {
		t.Errorf("gateway points at %s", got)
	}
}

func TestActivateOperationFailsAndIsUndone(t *testing.T) {
	f := newFixture(t)
	f.srv.NextOpFailure = &fakearm.OpFailure{Code: "ApplicationGatewayKeyVaultSecretException", Message: "Access denied to the secret", Keep: true}
	_, err := activate(t, f, nil, verNew)
	if !errors.Is(err, plugin.ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{"ApplicationGatewayKeyVaultSecretException", "restored Key Vault secret " + secret(verOld)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err %q does not mention %q", err, want)
		}
	}
	if got := f.secretID(t); got != secret(verOld) {
		t.Errorf("gateway points at %s after the failed activation", got)
	}
	if p := props(f.gateway())["provisioningState"]; p != "Succeeded" {
		t.Errorf("provisioning state %v", p)
	}
}

func TestActivateOperationFailsWithoutChange(t *testing.T) {
	f := newFixture(t)
	f.srv.NextOpFailure = &fakearm.OpFailure{Code: "InternalServerError", Message: "boom"}
	_, err := activate(t, f, nil, verNew)
	if !errors.Is(err, plugin.ErrUnavailable) || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("err = %v", err)
	}
	if n := f.srv.Count(http.MethodPut); n != 1 {
		t.Errorf("%d PUTs, want 1 (no revert needed)", n)
	}
}

func TestActivateTimesOutWhileOperationRuns(t *testing.T) {
	f := newFixture(t)
	f.srv.HangOps = true
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := f.tg.Activate(ctx, plugin.ActivateRequest{Config: cfg(nil), StagedRef: secret(verNew)})
	if !errors.Is(err, plugin.ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Error("a timeout must map to ErrUnavailable, not the core's own deadline")
	}
	if !strings.Contains(err.Error(), "still running") || !strings.Contains(err.Error(), "Updating") {
		t.Errorf("err %q should say the update is still running and report the state", err)
	}
	if ctx.Err() != nil {
		t.Error("Activate used the whole deadline; it should keep time to report")
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		name    string
		fault   fakearm.Fault
		want    error
		mention string
	}{
		{"read 403", fakearm.Fault{Method: http.MethodGet, Status: 403, Code: "AuthorizationFailed", Message: "no read"}, plugin.ErrPermanent, "applicationGateways/read"},
		{"write 403", fakearm.Fault{Method: http.MethodPut, Status: 403, Code: "LinkedAuthorizationFailed",
			Message: "does not have permission to perform action 'Microsoft.ManagedIdentity/userAssignedIdentities/assign/action'"}, plugin.ErrPermanent, "userAssignedIdentities/assign/action"},
		{"read 404", fakearm.Fault{Method: http.MethodGet, Status: 404, Code: "ResourceGroupNotFound"}, plugin.ErrPermanent, "not found"},
		{"read 429", fakearm.Fault{Method: http.MethodGet, Status: 429, Code: "TooManyRequests"}, plugin.ErrUnavailable, "429"},
		{"write 429", fakearm.Fault{Method: http.MethodPut, Status: 429, Code: "TooManyRequests"}, plugin.ErrUnavailable, "429"},
		{"write 409", fakearm.Fault{Method: http.MethodPut, Status: 409, Code: "AnotherOperationInProgress"}, plugin.ErrUnavailable, "AnotherOperationInProgress"},
		{"write 400", fakearm.Fault{Method: http.MethodPut, Status: 400, Code: "ApplicationGatewaySslCertificateInvalidKeyVaultSecretId"}, plugin.ErrPermanent, "InvalidKeyVaultSecretId"},
		{"write 502", fakearm.Fault{Method: http.MethodPut, Status: 502, Code: "BadGateway"}, plugin.ErrUnavailable, "nothing was changed"},
		{"write 408", fakearm.Fault{Method: http.MethodPut, Status: 408, Code: "RequestTimeout"}, plugin.ErrUnavailable, "no clear answer"},
		{"read 500", fakearm.Fault{Method: http.MethodGet, Status: 500, Code: "InternalServerError"}, plugin.ErrUnavailable, "500"},
		{"read 401", fakearm.Fault{Method: http.MethodGet, Status: 401, Code: "InvalidAuthenticationToken"}, plugin.ErrPermanent, "credential"},
		{"poll 500", fakearm.Fault{Method: http.MethodGet, PathContains: "/operations/", Status: 500, Code: "InternalServerError", Times: maxPollErrors}, plugin.ErrUnavailable, "status failed: HTTP 500"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.srv.AddFault(tc.fault)
			_, err := activate(t, f, nil, verNew)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if !strings.Contains(err.Error(), tc.mention) {
				t.Errorf("err %q does not mention %q", err, tc.mention)
			}
			if strings.Contains(err.Error(), "test-token") {
				t.Error("error leaks the bearer token")
			}
		})
	}
}

func TestCanceledContext(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.tg.Activate(ctx, plugin.ActivateRequest{Config: cfg(nil), StagedRef: secret(verNew)})
	if !errors.Is(err, plugin.ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if got := f.secretID(t); got != secret(verOld) {
		t.Errorf("gateway changed: %s", got)
	}
}

func TestActivateToleratesAFailedStatusPoll(t *testing.T) {
	f := newFixture(t)
	f.srv.AddFault(fakearm.Fault{Method: http.MethodGet, PathContains: "/operations/", Status: 503, Code: "ServiceUnavailable", Times: maxPollErrors - 1})
	if _, err := activate(t, f, nil, verNew); err != nil {
		t.Fatal(err)
	}
	if got := f.secretID(t); got != secret(verNew) {
		t.Errorf("gateway points at %s", got)
	}
}
