package plugin_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	goplugin "github.com/hashicorp/go-plugin"

	"github.com/krakenkey/connector/internal/testplugin"
	"github.com/krakenkey/connector/pkg/plugin"
)

const testPluginEnv = "KRAKENKEY_CONNECTOR_TESTPLUGIN"

// TestMain lets the test binary act as a plugin when started by
// TestSubprocessPlugin.
func TestMain(m *testing.M) {
	switch os.Getenv(testPluginEnv) {
	case "both":
		plugin.Serve(plugin.ServeOpts{KeyStore: testplugin.NewKeyStore(), Target: testplugin.NewTarget()})
		os.Exit(0)
	case "target-only":
		plugin.Serve(plugin.ServeOpts{Target: testplugin.NewTarget()})
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func inProcess(t *testing.T) (plugin.KeyStore, plugin.Target) {
	t.Helper()
	opts := plugin.ServeOpts{KeyStore: testplugin.NewKeyStore(), Target: testplugin.NewTarget()}
	client, _ := goplugin.TestPluginGRPCConn(t, false, opts.PluginSet())
	t.Cleanup(func() { _ = client.Close() })

	ks, err := plugin.DispenseKeyStore(client)
	if err != nil {
		t.Fatalf("dispense key store: %v", err)
	}
	tg, err := plugin.DispenseTarget(client)
	if err != nil {
		t.Fatalf("dispense target: %v", err)
	}
	return ks, tg
}

func TestKeyStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	ks, _ := inProcess(t)

	caps, err := ks.Describe(ctx)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if !caps.Exportable || len(caps.Provides) != 1 || caps.Provides[0] != plugin.KeyFormatPEM ||
		len(caps.KeyTypes) != 1 || caps.KeyTypes[0] != plugin.KeyTypeECDSAP256 {
		t.Fatalf("unexpected capabilities: %+v", caps)
	}

	csr, err := ks.CreateCSR(ctx, plugin.CSRRequest{
		Config:        json.RawMessage(`{}`),
		CertificateID: "1043",
		Names:         []string{"api.example.com", "www.example.com"},
		KeyType:       plugin.KeyTypeECDSAP256,
	})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	if !strings.HasPrefix(csr.KeyRef, "1043/") {
		t.Errorf("key ref %q does not carry the certificate id", csr.KeyRef)
	}
	block, _ := pem.Decode([]byte(csr.PEM))
	if block == nil {
		t.Fatal("CSR is not PEM")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if got := strings.Join(req.DNSNames, ","); got != "api.example.com,www.example.com" {
		t.Errorf("CSR names = %s", got)
	}

	ref, err := ks.Complete(ctx, plugin.CompleteRequest{KeyRef: csr.KeyRef, CertPEM: "leaf", ChainPEM: "chain"})
	if err != nil || ref != csr.KeyRef {
		t.Fatalf("Complete = %q, %v", ref, err)
	}

	key, err := ks.Export(ctx, plugin.ExportRequest{KeyRef: ref, Format: plugin.KeyFormatPEM})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if key.Format != plugin.KeyFormatPEM {
		t.Errorf("export format = %q", key.Format)
	}
	kb, _ := pem.Decode(key.Data)
	if kb == nil {
		t.Fatal("exported key is not PEM")
	}
	priv, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	if !priv.(*ecdsa.PrivateKey).PublicKey.Equal(req.PublicKey) {
		t.Error("exported key does not match the CSR public key")
	}

	if err := ks.Release(ctx, plugin.ReleaseRequest{KeyRef: ref}); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := ks.Export(ctx, plugin.ExportRequest{KeyRef: ref, Format: plugin.KeyFormatPEM}); err == nil {
		t.Error("Export after Release succeeded")
	}
}

func TestKeyStoreErrorsCarryPluginMessage(t *testing.T) {
	ks, _ := inProcess(t)
	_, err := ks.CreateCSR(context.Background(), plugin.CSRRequest{Names: []string{"a.example.com"}, KeyType: plugin.KeyTypeRSA2048})
	if err == nil {
		t.Fatal("expected an error")
	}
	want := `key store create CSR: unsupported key type "rsa-2048"`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
}

func TestTargetRoundTrip(t *testing.T) {
	ctx := context.Background()
	_, tg := inProcess(t)

	caps, err := tg.Describe(ctx)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if !caps.SupportsRollback || !caps.NeedsExportableKey || len(caps.KeyTypes) != 2 {
		t.Fatalf("unexpected capabilities: %+v", caps)
	}

	problems, err := tg.Validate(ctx, json.RawMessage(`{}`))
	if err != nil || len(problems) != 1 || problems[0] != "name is required" {
		t.Fatalf("Validate = %v, %v", problems, err)
	}
	cfg := json.RawMessage(`{"name":"x"}`)
	if problems, err := tg.Validate(ctx, cfg); err != nil || len(problems) != 0 {
		t.Fatalf("Validate = %v, %v", problems, err)
	}

	stage := func(serial string) string {
		t.Helper()
		ref, err := tg.Stage(ctx, plugin.StageRequest{
			Config: cfg, CertificateID: "1", Label: "l",
			CertPEM: "leaf", ChainPEM: "chain", FullChainPEM: "leaf\nchain",
			Key:    plugin.KeyMaterial{Format: plugin.KeyFormatPEM, Data: []byte("key")},
			Serial: serial,
		})
		if err != nil {
			t.Fatalf("Stage: %v", err)
		}
		return ref
	}

	if _, err := tg.Activate(ctx, cfg, stage("01")); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	prev, err := tg.Activate(ctx, cfg, stage("02"))
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if s, _ := tg.Current(ctx, cfg); s != "02" {
		t.Fatalf("Current = %q, want 02", s)
	}
	if err := tg.Rollback(ctx, cfg, prev); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if s, _ := tg.Current(ctx, cfg); s != "01" {
		t.Fatalf("Current after rollback = %q, want 01", s)
	}

	_, err = tg.Stage(ctx, plugin.StageRequest{Key: plugin.KeyMaterial{Format: plugin.KeyFormatVaultRef, Ref: "v"}})
	if err == nil || err.Error() != "target stage: PEM key material required" {
		t.Errorf("Stage error = %v", err)
	}
}

func TestCapabilitiesSurviveTheWire(t *testing.T) {
	// Every field of TargetCapabilities must round-trip; a target that
	// forgets one would break matching in the core.
	want := plugin.TargetCapabilities{
		Accepts:             []plugin.KeyFormat{plugin.KeyFormatVaultRef, plugin.KeyFormatPFX},
		NeedsExportableKey:  true,
		SupportsRollback:    true,
		KeyTypes:            []plugin.KeyType{plugin.KeyTypeRSA3072, plugin.KeyTypeECDSAP384},
		DefaultVerifyWindow: 45 * time.Minute,
		PropagatesAsync:     true,
	}
	client, _ := goplugin.TestPluginGRPCConn(t, false, plugin.ServeOpts{Target: fixedTarget{caps: want}}.PluginSet())
	defer func() { _ = client.Close() }()
	tg, err := plugin.DispenseTarget(client)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tg.Describe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%+v", got) != fmt.Sprintf("%+v", want) {
		t.Errorf("capabilities = %+v, want %+v", got, want)
	}
}

type fixedTarget struct {
	plugin.Target
	caps plugin.TargetCapabilities
}

func (f fixedTarget) Describe(context.Context) (plugin.TargetCapabilities, error) { return f.caps, nil }

func TestKeyMaterialIsNotPrinted(t *testing.T) {
	k := plugin.KeyMaterial{Format: plugin.KeyFormatPEM, Data: []byte("-----BEGIN PRIVATE KEY-----secret"), Password: "hunter2"}
	var logged strings.Builder
	slog.New(slog.NewTextHandler(&logged, nil)).Info("x", "key", k)
	for _, s := range []string{fmt.Sprint(k), fmt.Sprintf("%v %+v %#v", k, k, k), logged.String()} {
		if strings.Contains(s, "secret") || strings.Contains(s, "hunter2") {
			t.Errorf("key material leaked: %s", s)
		}
	}
}

func TestSubprocessPlugin(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a subprocess")
	}
	ctx := context.Background()

	start := func(mode string) goplugin.ClientProtocol {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^$")
		cmd.Env = append(os.Environ(), testPluginEnv+"="+mode)
		client := goplugin.NewClient(plugin.ClientConfig(cmd, nil))
		t.Cleanup(client.Kill)
		rpc, err := client.Client()
		if err != nil {
			t.Fatalf("start plugin: %v", err)
		}
		return rpc
	}

	rpc := start("both")
	ks, err := plugin.DispenseKeyStore(rpc)
	if err != nil {
		t.Fatal(err)
	}
	tg, err := plugin.DispenseTarget(rpc)
	if err != nil {
		t.Fatal(err)
	}
	ksCaps, err := ks.Describe(ctx)
	if err != nil {
		t.Fatalf("key store Describe over subprocess: %v", err)
	}
	tCaps, err := tg.Describe(ctx)
	if err != nil {
		t.Fatalf("target Describe over subprocess: %v", err)
	}
	if f, err := plugin.Match(ksCaps, tCaps, plugin.KeyTypeECDSAP256); err != nil || f != plugin.KeyFormatPEM {
		t.Errorf("Match = %q, %v", f, err)
	}

	// A plugin that only serves a target gives a clear error when asked
	// for a key store.
	rpc = start("target-only")
	ks, err = plugin.DispenseKeyStore(rpc)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ks.Describe(ctx)
	if err == nil || !strings.Contains(err.Error(), "plugin does not implement this call") {
		t.Errorf("Describe on missing service: %v", err)
	}
}

// selfSigned returns a throwaway certificate, used to check that PEM data
// passes through Stage untouched.
func selfSigned(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "x"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}, &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "x"}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestStagePassesPEMThrough(t *testing.T) {
	rec := &recordingTarget{}
	client, _ := goplugin.TestPluginGRPCConn(t, false, plugin.ServeOpts{Target: rec}.PluginSet())
	defer func() { _ = client.Close() }()
	tg, err := plugin.DispenseTarget(client)
	if err != nil {
		t.Fatal(err)
	}
	leaf := selfSigned(t)
	want := plugin.StageRequest{
		Config: json.RawMessage(`{"a":1}`), CertificateID: "7", Label: "web",
		CertPEM: leaf, ChainPEM: "chain", FullChainPEM: leaf + "chain",
		Key:    plugin.KeyMaterial{Format: plugin.KeyFormatPFX, Data: []byte{0, 1, 2}, Password: "pw"},
		Serial: "2a",
	}
	if _, err := tg.Stage(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got := rec.got
	if string(got.Config) != string(want.Config) || got.CertificateID != want.CertificateID ||
		got.Label != want.Label || got.CertPEM != want.CertPEM || got.ChainPEM != want.ChainPEM ||
		got.FullChainPEM != want.FullChainPEM || got.Serial != want.Serial ||
		got.Key.Format != want.Key.Format || string(got.Key.Data) != string(want.Key.Data) ||
		got.Key.Password != want.Key.Password {
		t.Errorf("Stage request changed in transit:\n got %+v\nwant %+v", got, want)
	}
}

type recordingTarget struct {
	plugin.Target
	got plugin.StageRequest
}

func (r *recordingTarget) Stage(_ context.Context, req plugin.StageRequest) (string, error) {
	r.got = req
	return "ok", nil
}
