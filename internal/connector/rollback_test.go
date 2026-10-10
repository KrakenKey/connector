package connector

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/testplugin"
	"github.com/krakenkey/connector/pkg/plugin"
)

// capsResolver serves the in-memory key store and a target with fixed
// capabilities.
type capsResolver struct {
	ks   plugin.KeyStoreCapabilities
	caps plugin.TargetCapabilities
	// effective, when set, is what the key store reports for the
	// certificate's settings (ValidateCapabilities).
	effective *plugin.KeyStoreCapabilities
}

type capsKeyStore struct {
	*testplugin.KeyStore
	caps      plugin.KeyStoreCapabilities
	effective *plugin.KeyStoreCapabilities
}

func (k capsKeyStore) Describe(context.Context) (plugin.KeyStoreCapabilities, error) {
	return k.caps, nil
}

func (k capsKeyStore) ValidateCapabilities(context.Context, plugin.KeyStoreValidateRequest) (plugin.KeyStoreValidation, error) {
	return plugin.KeyStoreValidation{Capabilities: k.effective}, nil
}

type capsTarget struct {
	plugin.UnimplementedTarget
	caps plugin.TargetCapabilities
}

func (t capsTarget) Describe(context.Context) (plugin.TargetCapabilities, error) { return t.caps, nil }
func (t capsTarget) Validate(context.Context, plugin.TargetValidateRequest) ([]string, error) {
	return nil, nil
}

func (r capsResolver) KeyStore(string) (plugin.KeyStore, error) {
	return capsKeyStore{KeyStore: testplugin.NewKeyStore(), caps: r.ks, effective: r.effective}, nil
}

func (r capsResolver) Target(name string) (plugin.Target, error) {
	if name != "mat" {
		return nil, errors.New("unknown target")
	}
	return capsTarget{caps: r.caps}, nil
}

func TestRollbackMaterialReport(t *testing.T) {
	cert := config.Certificate{
		ID: 7, Names: []string{"api.example.com"},
		KeyStore: config.KeyStore{Plugin: "vault", KeyType: plugin.KeyTypeECDSAP256},
		Targets:  []config.Target{{Label: "lb", Plugin: "mat"}},
	}
	cfg := &config.Config{Certificates: []config.Certificate{cert}}
	vaultTarget := plugin.TargetCapabilities{
		Accepts: []plugin.KeyFormat{plugin.KeyFormatVaultRef}, SupportsRollback: true, RollbackNeedsMaterial: true,
	}
	lockedVault := plugin.KeyStoreCapabilities{
		Provides: []plugin.KeyFormat{plugin.KeyFormatVaultRef}, KeyTypes: []plugin.KeyType{plugin.KeyTypeECDSAP256},
	}

	// A vault reference can be handed back for the previous key, so a
	// locked vault still allows rollback.
	job, rep := BuildJob(context.Background(), cert, capsResolver{ks: lockedVault, caps: vaultTarget})
	if !rep.OK() || len(rep.Targets[0].Warnings) != 0 || job.Targets[0].RollbackUnavailable != "" || rep.Targets[0].RollbackUnavailable != "" {
		t.Fatalf("vault ref pair: problems %v warnings %v reason %q", rep.Targets[0].Problems, rep.Targets[0].Warnings, job.Targets[0].RollbackUnavailable)
	}
	var out bytes.Buffer
	if n := Validate(context.Background(), cfg, capsResolver{ks: lockedVault, caps: vaultTarget}, nil, &out); n != 0 ||
		!strings.Contains(out.String(), "rollback supported (with the previous certificate and key from the connector)") {
		t.Errorf("validate report (%d problems):\n%s", n, out.String())
	}
}

func TestKeyStoreCapabilitiesPerCertificate(t *testing.T) {
	// The key store is exportable in general, but not with this
	// certificate's settings; a PEM target must be refused by validate.
	cert := config.Certificate{
		ID: 7, Names: []string{"api.example.com"},
		KeyStore: config.KeyStore{Plugin: "vault", KeyType: plugin.KeyTypeECDSAP256},
		Targets:  []config.Target{{Label: "lb", Plugin: "mat"}},
	}
	pemTarget := plugin.TargetCapabilities{Accepts: []plugin.KeyFormat{plugin.KeyFormatPEM}, NeedsExportableKey: true, SupportsRollback: true}
	general := plugin.KeyStoreCapabilities{
		Provides: []plugin.KeyFormat{plugin.KeyFormatPEM, plugin.KeyFormatVaultRef}, Exportable: true,
		KeyTypes: []plugin.KeyType{plugin.KeyTypeECDSAP256},
	}
	locked := general
	locked.Exportable = false

	_, rep := BuildJob(context.Background(), cert, capsResolver{ks: general, caps: pemTarget})
	if !rep.OK() {
		t.Fatalf("without per-certificate capabilities: %+v", rep.Targets)
	}
	_, rep = BuildJob(context.Background(), cert, capsResolver{ks: general, caps: pemTarget, effective: &locked})
	if rep.OK() || rep.KeyStoreCaps == nil || rep.KeyStoreCaps.Exportable {
		t.Fatalf("per-certificate capabilities ignored: %+v %+v", rep.KeyStoreCaps, rep.Targets)
	}
	var out bytes.Buffer
	cfg := &config.Config{Certificates: []config.Certificate{cert}}
	if n := Validate(context.Background(), cfg, capsResolver{ks: general, caps: pemTarget, effective: &locked}, nil, &out); n == 0 ||
		!strings.Contains(out.String(), "exportable false") || !strings.Contains(out.String(), "does not allow export") {
		t.Errorf("validate report (%d problems):\n%s", n, out.String())
	}
}
