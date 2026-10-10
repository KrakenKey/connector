package appgw

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

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
		problems, err = f.tg.Validate(ctxT(t), plugin.TargetValidateRequest{Config: cfg(map[string]any{"ssl_certificate": "other", "create_if_missing": true})})
		if err != nil || len(problems) != 0 {
			t.Fatalf("with create_if_missing: problems %v, err %v", problems, err)
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
	if prev != secret(verOld) {
		t.Errorf("previous ref %q, want %q", prev, secret(verOld))
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

	// Activating the same version again changes nothing.
	puts := f.srv.Count(http.MethodPut)
	prev2, err := activate(t, f, nil, verNew)
	if err != nil || prev2 != secret(verNew) || f.srv.Count(http.MethodPut) != puts {
		t.Errorf("re-activate: prev %q err %v puts %d->%d", prev2, err, puts, f.srv.Count(http.MethodPut))
	}

	if err := f.tg.Rollback(ctxT(t), plugin.RollbackRequest{Config: cfg(nil), PreviousRef: prev}); err != nil {
		t.Fatal(err)
	}
	if got := f.secretID(t); got != secret(verOld) {
		t.Errorf("after rollback the gateway points at %s", got)
	}
}

func TestRollbackRestoresVersionlessIDExactly(t *testing.T) {
	f := newFixture(t)
	versionless := "https://KV-Test.vault.azure.net/secrets/app-cert"
	f.setGateway(fakearm.V2Gateway(sub, rg, gwName, certName, versionless))
	prev, err := activate(t, f, nil, verNew)
	if err != nil || prev != versionless {
		t.Fatalf("prev %q, err %v", prev, err)
	}
	if err := f.tg.Rollback(ctxT(t), plugin.RollbackRequest{Config: cfg(nil), PreviousRef: prev}); err != nil {
		t.Fatal(err)
	}
	if got := f.secretID(t); got != versionless {
		t.Errorf("restored %q, want %q", got, versionless)
	}
}

func TestRollbackRefs(t *testing.T) {
	f := newFixture(t)
	cases := map[string]error{
		"":                      plugin.ErrPermanent,
		"inline":                plugin.ErrPermanent,
		"garbage":               plugin.ErrNotFound,
		"https://example.com/x": plugin.ErrNotFound,
	}
	for ref, want := range cases {
		err := f.tg.Rollback(ctxT(t), plugin.RollbackRequest{Config: cfg(nil), PreviousRef: ref})
		if !errors.Is(err, want) {
			t.Errorf("Rollback(%q) = %v, want %v", ref, err, want)
		}
	}
	if f.srv.Count(http.MethodPut) != 0 {
		t.Error("a refused rollback wrote to the gateway")
	}
}

func TestActivateCreateIfMissing(t *testing.T) {
	f := newFixture(t)
	g := fakearm.V2Gateway(sub, rg, gwName, certName, "")
	props(g)["httpListeners"] = []any{}
	f.setGateway(g)

	if _, err := activate(t, f, nil, verNew); !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "create_if_missing") {
		t.Fatalf("without create_if_missing: %v", err)
	}
	prev, err := activate(t, f, map[string]any{"create_if_missing": true}, verNew)
	if err != nil || prev != "absent" {
		t.Fatalf("prev %q, err %v", prev, err)
	}
	if got := f.secretID(t); got != secret(verNew) {
		t.Errorf("created entry points at %s", got)
	}
	if err := f.tg.Rollback(ctxT(t), plugin.RollbackRequest{Config: cfg(nil), PreviousRef: prev}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.srv.SecretID(sub, rg, gwName, certName); ok {
		t.Error("rollback left the created entry in place")
	}
	// Removing it again is a no-op.
	if err := f.tg.Rollback(ctxT(t), plugin.RollbackRequest{Config: cfg(nil), PreviousRef: prev}); err != nil {
		t.Errorf("second rollback: %v", err)
	}
}

func TestRollbackAbsentRefusesWhenInUse(t *testing.T) {
	f := newFixture(t) // the listener uses app-cert
	err := f.tg.Rollback(ctxT(t), plugin.RollbackRequest{Config: cfg(nil), PreviousRef: "absent"})
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "listener https") {
		t.Fatalf("err = %v", err)
	}
}

func TestActivateOverUploadedCertificate(t *testing.T) {
	f := newFixture(t)
	g := fakearm.V2Gateway(sub, rg, gwName, certName, "")
	props(g)["sslCertificates"] = []any{map[string]any{"name": certName, "properties": map[string]any{"publicCertData": "AAAA"}}}
	f.setGateway(g)
	prev, err := activate(t, f, nil, verNew)
	if err != nil || prev != "inline" {
		t.Fatalf("prev %q, err %v", prev, err)
	}
	err = f.tg.Rollback(ctxT(t), plugin.RollbackRequest{Config: cfg(nil), PreviousRef: prev})
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "cannot be restored") {
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
