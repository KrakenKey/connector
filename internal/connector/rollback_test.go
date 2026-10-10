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
}

type capsKeyStore struct {
	*testplugin.KeyStore
	caps plugin.KeyStoreCapabilities
}

func (k capsKeyStore) Describe(context.Context) (plugin.KeyStoreCapabilities, error) { return k.caps, nil }

type capsTarget struct {
	plugin.UnimplementedTarget
	caps plugin.TargetCapabilities
}

func (t capsTarget) Describe(context.Context) (plugin.TargetCapabilities, error) { return t.caps, nil }
func (t capsTarget) Validate(context.Context, plugin.TargetValidateRequest) ([]string, error) {
	return nil, nil
}

func (r capsResolver) KeyStore(string) (plugin.KeyStore, error) {
	return capsKeyStore{KeyStore: testplugin.NewKeyStore(), caps: r.ks}, nil
}

func (r capsResolver) Target(name string) (plugin.Target, error) {
	if name != "mat" {
		return nil, errors.New("unknown target")
	}
	return capsTarget{caps: r.caps}, nil
}

func TestRollbackMaterialWarning(t *testing.T) {
	cert := config.Certificate{
		ID: 7, Names: []string{"api.example.com"},
		KeyStore: config.KeyStore{Plugin: "vault", KeyType: plugin.KeyTypeECDSAP256},
		Targets:  []config.Target{{Label: "lb", Plugin: "mat"}},
	}
	target := plugin.TargetCapabilities{
		Accepts: []plugin.KeyFormat{plugin.KeyFormatVaultRef}, SupportsRollback: true, RollbackNeedsMaterial: true,
	}
	locked := plugin.KeyStoreCapabilities{
		Provides: []plugin.KeyFormat{plugin.KeyFormatVaultRef}, KeyTypes: []plugin.KeyType{plugin.KeyTypeECDSAP256},
	}
	exportable := locked
	exportable.Exportable = true

	job, rep := BuildJob(context.Background(), cert, capsResolver{ks: locked, caps: target})
	if !rep.OK() {
		t.Fatalf("pair refused instead of warned: %+v", rep.Targets)
	}
	if len(rep.Targets[0].Warnings) != 1 || !strings.Contains(rep.Targets[0].Warnings[0], "rollback is unavailable") ||
		!strings.Contains(job.Targets[0].RollbackUnavailable, "does not allow export") {
		t.Errorf("warnings = %v, job reason = %q", rep.Targets[0].Warnings, job.Targets[0].RollbackUnavailable)
	}

	cfg := &config.Config{Certificates: []config.Certificate{cert}}
	var out bytes.Buffer
	if n := Validate(context.Background(), cfg, capsResolver{ks: locked, caps: target}, nil, &out); n != 0 {
		t.Errorf("problems = %d\n%s", n, out.String())
	}
	if !strings.Contains(out.String(), "rollback unavailable") || !strings.Contains(out.String(), "WARNING: rollback is unavailable") ||
		!strings.Contains(out.String(), "0 problem(s), 2 warning(s)") {
		t.Errorf("validate report:\n%s", out.String())
	}

	job, rep = BuildJob(context.Background(), cert, capsResolver{ks: exportable, caps: target})
	if len(rep.Targets[0].Warnings) != 0 || job.Targets[0].RollbackUnavailable != "" {
		t.Errorf("exportable key store: warnings %v", rep.Targets[0].Warnings)
	}
	out.Reset()
	Validate(context.Background(), cfg, capsResolver{ks: exportable, caps: target}, nil, &out)
	if !strings.Contains(out.String(), "rollback supported (with the previous certificate and key from the connector)") {
		t.Errorf("validate report:\n%s", out.String())
	}
}
