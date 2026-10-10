package plugin_test

import (
	"context"
	"slices"
	"testing"

	goplugin "github.com/hashicorp/go-plugin"

	"github.com/krakenkey/connector/internal/testplugin"
	"github.com/krakenkey/connector/pkg/plugin"
)

// featureTarget records the core features it sees in Describe.
type featureTarget struct {
	plugin.UnimplementedTarget
	seen chan []string
}

func (f featureTarget) Describe(ctx context.Context) (plugin.TargetCapabilities, error) {
	f.seen <- plugin.CoreFeaturesFrom(ctx)
	return plugin.TargetCapabilities{}, nil
}

// featureKeyStore records core features and reports per-settings
// capabilities.
type featureKeyStore struct {
	*testplugin.KeyStore
	seen chan []string
	caps *plugin.KeyStoreCapabilities
}

func (f featureKeyStore) Describe(ctx context.Context) (plugin.KeyStoreCapabilities, error) {
	f.seen <- plugin.CoreFeaturesFrom(ctx)
	return f.KeyStore.Describe(ctx)
}

func (f featureKeyStore) ValidateCapabilities(_ context.Context, req plugin.KeyStoreValidateRequest) (plugin.KeyStoreValidation, error) {
	return plugin.KeyStoreValidation{Problems: []string{"p:" + req.CertificateID}, Capabilities: f.caps}, nil
}

func TestCoreFeaturesCrossTheWire(t *testing.T) {
	ft := featureTarget{seen: make(chan []string, 1)}
	fk := featureKeyStore{KeyStore: testplugin.NewKeyStore(), seen: make(chan []string, 1)}
	client, _ := goplugin.TestPluginGRPCConn(t, false, plugin.ServeOpts{Target: ft, KeyStore: fk}.PluginSet())
	defer func() { _ = client.Close() }()
	tg, _ := plugin.DispenseTarget(client)
	ks, _ := plugin.DispenseKeyStore(client)
	ctx := context.Background()

	if _, err := tg.Describe(ctx); err != nil {
		t.Fatal(err)
	}
	if got := <-ft.seen; !slices.Equal(got, plugin.CoreFeatures) || !slices.Contains(got, plugin.FeatureRollbackMaterial) {
		t.Errorf("target saw features %v, want %v", got, plugin.CoreFeatures)
	}
	if _, err := ks.Describe(ctx); err != nil {
		t.Fatal(err)
	}
	if got := <-fk.seen; !slices.Equal(got, plugin.CoreFeatures) {
		t.Errorf("key store saw features %v", got)
	}

	// In process, or from a connector that predates features: none.
	if plugin.HasCoreFeature(ctx, plugin.FeatureRollbackMaterial) {
		t.Error("plain context reports a feature")
	}
	if !plugin.HasCoreFeature(plugin.WithCoreFeatures(ctx, plugin.FeatureRollbackMaterial), plugin.FeatureRollbackMaterial) {
		t.Error("WithCoreFeatures lost the feature")
	}
}

func TestKeyStoreCapabilitiesForSettingsCrossTheWire(t *testing.T) {
	locked := plugin.KeyStoreCapabilities{Provides: []plugin.KeyFormat{plugin.KeyFormatVaultRef}, KeyTypes: []plugin.KeyType{plugin.KeyTypeRSA2048}}
	for _, caps := range []*plugin.KeyStoreCapabilities{&locked, nil} {
		fk := featureKeyStore{KeyStore: testplugin.NewKeyStore(), seen: make(chan []string, 1), caps: caps}
		client, _ := goplugin.TestPluginGRPCConn(t, false, plugin.ServeOpts{KeyStore: fk}.PluginSet())
		ks, _ := plugin.DispenseKeyStore(client)
		v, err := plugin.ValidateKeyStore(context.Background(), ks, plugin.KeyStoreValidateRequest{CertificateID: "9"})
		if err != nil || !slices.Equal(v.Problems, []string{"p:9"}) {
			t.Fatalf("ValidateKeyStore = %+v, %v", v, err)
		}
		switch {
		case caps == nil && v.Capabilities != nil:
			t.Errorf("capabilities appeared from nowhere: %+v", v.Capabilities)
		case caps != nil && (v.Capabilities == nil || v.Capabilities.Exportable || !slices.Equal(v.Capabilities.Provides, locked.Provides)):
			t.Errorf("capabilities = %+v, want %+v", v.Capabilities, locked)
		}
		// Plain Validate still returns the problems.
		if p, err := ks.Validate(context.Background(), plugin.KeyStoreValidateRequest{CertificateID: "9"}); err != nil || len(p) != 1 {
			t.Errorf("Validate = %v, %v", p, err)
		}
		_ = client.Close()
	}
	// A key store without ValidateCapabilities gives no capabilities.
	client, _ := goplugin.TestPluginGRPCConn(t, false, plugin.ServeOpts{KeyStore: testplugin.NewKeyStore()}.PluginSet())
	defer func() { _ = client.Close() }()
	ks, _ := plugin.DispenseKeyStore(client)
	if v, err := plugin.ValidateKeyStore(context.Background(), ks, plugin.KeyStoreValidateRequest{Config: []byte(`{}`)}); err != nil || v.Capabilities != nil {
		t.Errorf("plain key store: %+v, %v", v, err)
	}
}
