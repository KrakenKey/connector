package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"

	"github.com/krakenkey/connector/pkg/plugin"
	"github.com/krakenkey/connector/plugins/azure-appgateway/internal/fakearm"
)

// fakeEndpointEnv matches FakeEndpointEnv in options_fakeazure.go, which
// this (untagged) test build does not compile.
const fakeEndpointEnv = "KRAKENKEY_AGW_FAKE_ARM_ENDPOINT"

// TestPluginOverGRPC builds the plugin with the fakeazure tag, starts it
// the way the connector does (go-plugin, gRPC, AutoMTLS) and drives a full
// deployment against a fake ARM endpoint.
func TestPluginOverGRPC(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the plugin binary")
	}
	bin := filepath.Join(t.TempDir(), "krakenkey-connector-plugin-azure-appgateway")
	build := exec.Command("go", "build", "-tags", "fakeazure", "-o", bin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build: %v", err)
	}

	const (
		sub  = "00000000-0000-0000-0000-000000000001"
		rg   = "rg-edge"
		gw   = "agw-prod"
		cert = "app-cert"
	)
	oldID := "https://kv-test.vault.azure.net/secrets/app-cert/" + strings.Repeat("a", 32)
	newID := "https://kv-test.vault.azure.net/secrets/app-cert/" + strings.Repeat("b", 32)
	srv := fakearm.New()
	defer srv.Close()
	srv.Certs[oldID] = [][]byte{fakearm.TestCert(0x0a01)}
	srv.Certs[newID] = [][]byte{fakearm.TestCert(0x0b02)}
	srv.PutGateway(sub, rg, gw, fakearm.V2Gateway(sub, rg, gw, cert, oldID))

	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), fakeEndpointEnv+"="+srv.URL)
	client := goplugin.NewClient(plugin.ClientConfig(cmd, hclog.NewNullLogger()))
	defer client.Kill()
	rpc, err := client.Client()
	if err != nil {
		t.Fatalf("start plugin: %v", err)
	}
	tg, err := plugin.DispenseTarget(rpc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if ks, err := plugin.DispenseKeyStore(rpc); err == nil {
		if _, err := ks.Describe(ctx); !errors.Is(err, plugin.ErrUnsupported) {
			t.Errorf("the plugin should not serve a key store: %v", err)
		}
	}
	settings, _ := json.Marshal(map[string]any{"subscription_id": sub, "resource_group": rg, "gateway": gw, "ssl_certificate": cert})

	caps, err := tg.Describe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ks := plugin.KeyStoreCapabilities{Provides: []plugin.KeyFormat{plugin.KeyFormatVaultRef}, Exportable: true, KeyTypes: []plugin.KeyType{plugin.KeyTypeRSA2048}}
	if f, err := plugin.Match(ks, caps, plugin.KeyTypeRSA2048); err != nil || f != plugin.KeyFormatVaultRef {
		t.Fatalf("Match = %s, %v", f, err)
	}
	if caps.DefaultVerifyWindow != 10*time.Minute || !caps.SupportsRollback {
		t.Errorf("caps %+v", caps)
	}

	if problems, err := tg.Validate(ctx, plugin.TargetValidateRequest{Config: settings}); err != nil || len(problems) > 0 {
		t.Fatalf("Validate: %v %v", problems, err)
	}
	if cur, err := tg.Current(ctx, plugin.CurrentRequest{Config: settings}); err != nil || cur != "a01" {
		t.Fatalf("Current = %q, %v", cur, err)
	}

	// Error kinds survive the gRPC round trip.
	_, err = tg.Stage(ctx, plugin.StageRequest{Config: settings,
		Key: plugin.KeyMaterial{Format: plugin.KeyFormatVaultRef, Ref: "https://kv-test.vault.azure.net/secrets/app-cert/"}})
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "no secret version") {
		t.Errorf("versionless Stage: %v", err)
	}
	if _, err := tg.Activate(ctx, plugin.ActivateRequest{Config: settings, StagedRef: "garbage"}); !errors.Is(err, plugin.ErrInvalid) {
		t.Errorf("bad staged ref: %v", err)
	}
	if err := tg.Rollback(ctx, plugin.RollbackRequest{Config: settings, PreviousRef: "garbage"}); !errors.Is(err, plugin.ErrNotFound) {
		t.Errorf("unknown previous ref: %v", err)
	}

	staged, err := tg.Stage(ctx, plugin.StageRequest{Config: settings, Serial: "b02",
		Key: plugin.KeyMaterial{Format: plugin.KeyFormatVaultRef, Ref: newID}})
	if err != nil {
		t.Fatal(err)
	}
	prev, err := tg.Activate(ctx, plugin.ActivateRequest{Config: settings, StagedRef: staged})
	if err != nil {
		t.Fatal(err)
	}
	if prev != oldID {
		t.Errorf("previous ref %q", prev)
	}
	if err := tg.Discard(ctx, plugin.DiscardRequest{Config: settings, StagedRef: staged}); err != nil {
		t.Errorf("Discard after Activate: %v", err)
	}
	if cur, _ := tg.Current(ctx, plugin.CurrentRequest{Config: settings}); cur != "b02" {
		t.Errorf("Current after Activate = %q", cur)
	}
	if id, _ := srv.SecretID(sub, rg, gw, cert); id != newID {
		t.Errorf("gateway points at %s", id)
	}

	if err := tg.Rollback(ctx, plugin.RollbackRequest{Config: settings, PreviousRef: prev}); err != nil {
		t.Fatal(err)
	}
	if id, _ := srv.SecretID(sub, rg, gw, cert); id != oldID {
		t.Errorf("after Rollback the gateway points at %s", id)
	}
	if cur, _ := tg.Current(ctx, plugin.CurrentRequest{Config: settings}); cur != "a01" {
		t.Errorf("Current after Rollback = %q", cur)
	}

	// A 412 race is retried inside the plugin; a long-running failure is
	// reported as unavailable with the gateway left as it was.
	srv.ConcurrentWrites = 1
	if _, err := tg.Activate(ctx, plugin.ActivateRequest{Config: settings, StagedRef: staged}); err != nil {
		t.Fatalf("Activate after a concurrent change: %v", err)
	}
	srv.NextOpFailure = &fakearm.OpFailure{Code: "ApplicationGatewayKeyVaultSecretException", Message: "denied", Keep: true}
	err = tg.Rollback(ctx, plugin.RollbackRequest{Config: settings, PreviousRef: prev})
	if !errors.Is(err, plugin.ErrUnavailable) || !strings.Contains(err.Error(), "ApplicationGatewayKeyVaultSecretException") {
		t.Errorf("failed rollback: %v", err)
	}
}
