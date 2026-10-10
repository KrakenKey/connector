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
	"errors"
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

	if problems, err := ks.Validate(ctx, plugin.KeyStoreValidateRequest{Config: json.RawMessage(`{"x":1}`)}); err != nil || len(problems) != 1 {
		t.Errorf("Validate = %v, %v", problems, err)
	}
	spki, err := ks.PublicKey(ctx, plugin.PublicKeyRequest{KeyRef: csr.KeyRef})
	if err != nil || string(spki) != string(req.RawSubjectPublicKeyInfo) {
		t.Errorf("PublicKey = %x, %v; want the CSR's SPKI", spki, err)
	}
	if _, err := ks.PublicKey(ctx, plugin.PublicKeyRequest{KeyRef: "nope"}); !errors.Is(err, plugin.ErrNotFound) {
		t.Errorf("PublicKey of an unknown key: %v, want ErrNotFound", err)
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
	want := `key store create CSR: permanent failure: unsupported key type "rsa-2048"`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
	if !plugin.IsPermanent(err) {
		t.Error("error kind lost on the wire")
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

	problems, err := tg.Validate(ctx, plugin.TargetValidateRequest{Config: json.RawMessage(`{}`)})
	if err != nil || len(problems) != 1 || problems[0] != "name is required" {
		t.Fatalf("Validate = %v, %v", problems, err)
	}
	cfg := json.RawMessage(`{"name":"x"}`)
	if problems, err := tg.Validate(ctx, plugin.TargetValidateRequest{Config: cfg}); err != nil || len(problems) != 0 {
		t.Fatalf("Validate = %v, %v", problems, err)
	}
	current := func() string {
		s, _ := tg.Current(ctx, plugin.CurrentRequest{Config: cfg})
		return s
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

	activate := func(ref string) (string, error) {
		return tg.Activate(ctx, plugin.ActivateRequest{Config: cfg, StagedRef: ref, CertificateID: "1", Label: "l"})
	}
	if _, err := activate(stage("01")); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	prev, err := activate(stage("02"))
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if s := current(); s != "02" {
		t.Fatalf("Current = %q, want 02", s)
	}
	if err := tg.Rollback(ctx, plugin.RollbackRequest{Config: cfg, PreviousRef: prev}); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if s := current(); s != "01" {
		t.Fatalf("Current after rollback = %q, want 01", s)
	}
	if err := tg.Rollback(ctx, plugin.RollbackRequest{Config: cfg, PreviousRef: "nope"}); !errors.Is(err, plugin.ErrNotFound) {
		t.Errorf("Rollback of unknown ref: %v, want ErrNotFound", err)
	}

	staged := stage("03")
	if err := tg.Discard(ctx, plugin.DiscardRequest{Config: cfg, StagedRef: staged}); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	if err := tg.Discard(ctx, plugin.DiscardRequest{Config: cfg, StagedRef: staged}); err != nil {
		t.Fatalf("second Discard: %v", err)
	}
	if _, err := activate(staged); !errors.Is(err, plugin.ErrNotFound) {
		t.Errorf("Activate of a discarded ref: %v", err)
	}

	_, err = tg.Stage(ctx, plugin.StageRequest{Key: plugin.KeyMaterial{Format: plugin.KeyFormatVaultRef, Ref: "v"}})
	if err == nil || err.Error() != "target stage: permanent failure: PEM key material required" {
		t.Errorf("Stage error = %v", err)
	}
}

func TestCapabilitiesSurviveTheWire(t *testing.T) {
	// Every field of TargetCapabilities must round-trip; a target that
	// forgets one would break matching in the core.
	want := plugin.TargetCapabilities{
		Accepts:               []plugin.KeyFormat{plugin.KeyFormatVaultRef, plugin.KeyFormatPFX},
		NeedsExportableKey:    true,
		SupportsRollback:      true,
		KeyTypes:              []plugin.KeyType{plugin.KeyTypeRSA3072, plugin.KeyTypeECDSAP384},
		DefaultVerifyWindow:   45 * time.Minute,
		PropagatesAsync:       true,
		RollbackNeedsMaterial: true,
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
	req := plugin.StageRequest{CertificateID: "1", Label: "web", Serial: "0a", Key: k}
	var logged strings.Builder
	l := slog.New(slog.NewTextHandler(&logged, nil))
	l.Info("x", "key", k, "req", req)
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("x", "key", k, "req", req)
	kj, _ := json.Marshal(k)
	rj, _ := json.Marshal(req)
	for _, s := range []string{
		fmt.Sprint(k), fmt.Sprintf("%v %+v %#v", k, k, k), fmt.Sprintf("%v %+v", req, req),
		logged.String(), string(kj), string(rj),
	} {
		if strings.Contains(s, "secret") || strings.Contains(s, "hunter2") {
			t.Errorf("key material leaked: %s", s)
		}
	}
	if !strings.Contains(logged.String(), "req.serial=0a") {
		t.Errorf("StageRequest log value missing fields: %s", logged.String())
	}

	rb := plugin.RollbackRequest{
		CertificateID: "1", Label: "web", PreviousRef: "arn:prev", PreviousSerial: "0b",
		PreviousCertPEM: "LEAF", PreviousChainPEM: "CHAIN", PreviousFullChainPEM: "LEAF\nCHAIN", PreviousKey: k,
	}
	logged.Reset()
	slog.New(slog.NewTextHandler(&logged, nil)).Info("x", "req", rb)
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("x", "req", rb)
	rbj, _ := json.Marshal(rb)
	for _, s := range []string{
		fmt.Sprintf("%v %+v %#v %s", rb, rb, rb, rb), logged.String(), string(rbj),
	} {
		for _, secret := range []string{"secret", "hunter2", "LEAF", "CHAIN"} {
			if strings.Contains(s, secret) {
				t.Errorf("RollbackRequest output contains %q: %s", secret, s)
			}
		}
	}
	if !strings.Contains(logged.String(), "req.previous_serial=0b") || !strings.Contains(string(rbj), `"previous_ref":"arn:prev"`) {
		t.Errorf("RollbackRequest output missing fields: %s %s", logged.String(), rbj)
	}
}

// rollbackRecorder passes Rollback requests to a channel.
type rollbackRecorder struct {
	plugin.UnimplementedTarget
	got chan plugin.RollbackRequest
}

func (r rollbackRecorder) Rollback(_ context.Context, req plugin.RollbackRequest) error {
	r.got <- req
	return nil
}

func TestRollbackMaterialCrossesTheWire(t *testing.T) {
	rt := rollbackRecorder{got: make(chan plugin.RollbackRequest, 2)}
	client, _ := goplugin.TestPluginGRPCConn(t, false, plugin.ServeOpts{Target: rt}.PluginSet())
	defer func() { _ = client.Close() }()
	tg, err := plugin.DispenseTarget(client)
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSigned(t)
	want := plugin.RollbackRequest{
		Config: json.RawMessage(`{"a":1}`), PreviousRef: "p1", CertificateID: "7", Label: "acm",
		PreviousCertPEM: cert, PreviousChainPEM: "chain", PreviousFullChainPEM: cert + "chain",
		PreviousKey:    plugin.KeyMaterial{Format: plugin.KeyFormatPFX, Data: []byte{0, 1, 2}, Password: "pw"},
		PreviousSerial: "2a",
	}
	if err := tg.Rollback(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got := <-rt.got
	if string(got.Config) != string(want.Config) || got.PreviousRef != want.PreviousRef || got.CertificateID != want.CertificateID ||
		got.Label != want.Label || got.PreviousCertPEM != want.PreviousCertPEM || got.PreviousChainPEM != want.PreviousChainPEM ||
		got.PreviousFullChainPEM != want.PreviousFullChainPEM || got.PreviousSerial != want.PreviousSerial ||
		got.PreviousKey.Format != plugin.KeyFormatPFX || string(got.PreviousKey.Data) != "\x00\x01\x02" || got.PreviousKey.Password != "pw" ||
		!got.HasPreviousMaterial() {
		t.Errorf("rollback request changed on the wire: %+v", got)
	}

	// Without material, the target sees empty fields.
	if err := tg.Rollback(context.Background(), plugin.RollbackRequest{PreviousRef: "p2"}); err != nil {
		t.Fatal(err)
	}
	if got := <-rt.got; got.HasPreviousMaterial() || got.PreviousKey.Format != "" || got.PreviousSerial != "" {
		t.Errorf("rollback without material = %+v", got)
	}
}

func TestErrorKindsCrossTheWire(t *testing.T) {
	kinds := []error{plugin.ErrPermanent, plugin.ErrInvalid, plugin.ErrNotFound, plugin.ErrUnavailable, plugin.ErrUnsupported}
	for _, kind := range kinds {
		client, _ := goplugin.TestPluginGRPCConn(t, false, plugin.ServeOpts{Target: failingTarget{err: fmt.Errorf("%w: details", kind)}}.PluginSet())
		tg, _ := plugin.DispenseTarget(client)
		err := tg.Rollback(context.Background(), plugin.RollbackRequest{PreviousRef: "x"})
		if !errors.Is(err, kind) {
			t.Errorf("%v: got %v", kind, err)
		}
		if !strings.Contains(err.Error(), "details") {
			t.Errorf("message lost: %v", err)
		}
		_ = client.Close()
	}
	// Plain errors are transient, not permanent.
	client, _ := goplugin.TestPluginGRPCConn(t, false, plugin.ServeOpts{Target: failingTarget{err: errors.New("boom")}}.PluginSet())
	defer func() { _ = client.Close() }()
	tg, _ := plugin.DispenseTarget(client)
	err := tg.Rollback(context.Background(), plugin.RollbackRequest{})
	if err == nil || plugin.IsPermanent(err) || plugin.IsUnsupported(err) || err.Error() != "target rollback: boom" {
		t.Errorf("plain error = %v", err)
	}
}

type failingTarget struct {
	plugin.UnimplementedTarget
	err error
}

func (f failingTarget) Rollback(context.Context, plugin.RollbackRequest) error { return f.err }

func TestUnimplementedEmbedding(t *testing.T) {
	// A target that implements only Describe still serves every call; the
	// rest report ErrUnsupported on the host side.
	client, _ := goplugin.TestPluginGRPCConn(t, false, plugin.ServeOpts{Target: describeOnly{}, KeyStore: plugin.UnimplementedKeyStore{}}.PluginSet())
	defer func() { _ = client.Close() }()
	tg, _ := plugin.DispenseTarget(client)
	ks, _ := plugin.DispenseKeyStore(client)
	ctx := context.Background()
	if _, err := tg.Describe(ctx); err != nil {
		t.Fatal(err)
	}
	if err := tg.Discard(ctx, plugin.DiscardRequest{}); !plugin.IsUnsupported(err) {
		t.Errorf("Discard: %v", err)
	}
	if _, err := tg.Current(ctx, plugin.CurrentRequest{}); !plugin.IsUnsupported(err) {
		t.Errorf("Current: %v", err)
	}
	if _, err := ks.Validate(ctx, plugin.KeyStoreValidateRequest{}); !plugin.IsUnsupported(err) {
		t.Errorf("key store Validate: %v", err)
	}
	if _, err := ks.PublicKey(ctx, plugin.PublicKeyRequest{}); !plugin.IsUnsupported(err) {
		t.Errorf("PublicKey: %v", err)
	}
}

type describeOnly struct{ plugin.UnimplementedTarget }

func (describeOnly) Describe(context.Context) (plugin.TargetCapabilities, error) {
	return plugin.TargetCapabilities{Accepts: []plugin.KeyFormat{plugin.KeyFormatPEM}}, nil
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
	if err == nil || !strings.Contains(err.Error(), "plugin does not implement this call") || !plugin.IsUnsupported(err) {
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
