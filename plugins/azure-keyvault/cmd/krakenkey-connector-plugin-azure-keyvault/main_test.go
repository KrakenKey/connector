package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"

	"github.com/krakenkey/connector/pkg/plugin"
	"github.com/krakenkey/connector/plugins/azure-keyvault/internal/fakevault"
)

const (
	vaultHost     = "kv.vault.test"
	identityToken = "test-identity-header"
)

// TestPluginOverGRPC builds the plugin binary and drives it the way the
// connector does: go-plugin over gRPC with mutual TLS, through the
// pkg/plugin client. The binary runs unchanged. It finds the fake vault at
// https://kv.vault.test through an HTTPS proxy, trusts the fake's CA via
// SSL_CERT_FILE, and gets its token from DefaultAzureCredential's managed
// identity support (the App Service variant, IDENTITY_ENDPOINT), served by
// a local fake. Nothing leaves the machine.
func TestPluginOverGRPC(t *testing.T) {
	ks, _, vault, tokens := startPlugin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	caps, err := ks.Describe(ctx)
	if err != nil || !caps.Exportable || len(caps.Provides) != 3 || len(caps.KeyTypes) != len(plugin.AllKeyTypes) {
		t.Fatalf("Describe = %+v, %v", caps, err)
	}

	config := json.RawMessage(`{"vault":"https://` + vaultHost + `","certificate_name":"web"}`)
	locked := json.RawMessage(`{"vault":"https://` + vaultHost + `","certificate_name":"web","exportable":false}`)

	problems, err := ks.Validate(ctx, plugin.KeyStoreValidateRequest{Config: json.RawMessage(`{"vault":"bad name!"}`)})
	if err != nil || len(problems) != 2 {
		t.Errorf("Validate(bad) = %q, %v", problems, err)
	}
	if problems, err := ks.Validate(ctx, plugin.KeyStoreValidateRequest{Config: config}); err != nil || len(problems) != 0 {
		t.Fatalf("Validate = %q, %v", problems, err)
	}

	names := []string{"*.example.com", "example.com"}
	csr, err := ks.CreateCSR(ctx, plugin.CSRRequest{Config: config, CertificateID: "7", Names: names, KeyType: plugin.KeyTypeECDSAP256})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	if !strings.HasPrefix(csr.KeyRef, "https://"+vaultHost+"/certificates/web/pending?certificate_id=7&spki_sha256=") {
		t.Errorf("key ref = %s", csr.KeyRef)
	}
	b, _ := pem.Decode([]byte(csr.PEM))
	req, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil || req.Subject.CommonName != names[0] || strings.Join(req.DNSNames, ",") != strings.Join(names, ",") {
		t.Fatalf("CSR = %v, %v", req, err)
	}
	spki, err := ks.PublicKey(ctx, plugin.PublicKeyRequest{Config: config, KeyRef: csr.KeyRef})
	if err != nil || !bytes.Equal(spki, req.RawSubjectPublicKeyInfo) {
		t.Fatalf("PublicKey = %v", err)
	}

	leaf, chain, err := fakevault.Sign(csr.PEM)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := ks.Complete(ctx, plugin.CompleteRequest{Config: config, KeyRef: csr.KeyRef, CertPEM: leaf, ChainPEM: chain})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	versions := vault.Versions("web")
	if len(versions) != 1 || ref != "https://"+vaultHost+"/certificates/web/"+versions[0] {
		t.Fatalf("ref = %s, versions %v", ref, versions)
	}

	km, err := ks.Export(ctx, plugin.ExportRequest{Config: config, KeyRef: ref, Format: plugin.KeyFormatVaultRef})
	if err != nil || km.Ref != "https://"+vaultHost+"/secrets/web/"+versions[0] {
		t.Errorf("Export(vault_ref) = %v, %v", km, err)
	}
	km, err = ks.Export(ctx, plugin.ExportRequest{Config: config, KeyRef: ref, Format: plugin.KeyFormatPEM})
	if err != nil || !bytes.HasPrefix(km.Data, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Errorf("Export(pem) = %v, %v", km, err)
	}
	if _, err := ks.Export(ctx, plugin.ExportRequest{Config: locked, KeyRef: ref, Format: plugin.KeyFormatPFX}); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("Export(pfx, exportable false) err = %v, want ErrPermanent", err)
	}

	// Error kinds survive the gRPC hop.
	vault.Deny(fakevault.OpGetSecret)
	_, err = ks.Export(ctx, plugin.ExportRequest{Config: config, KeyRef: ref, Format: plugin.KeyFormatPFX})
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "Microsoft.KeyVault/vaults/secrets/getSecret/action") {
		t.Errorf("403: %v", err)
	}
	vault.Allow(fakevault.OpGetSecret)
	if _, err := ks.PublicKey(ctx, plugin.PublicKeyRequest{Config: config, KeyRef: "https://" + vaultHost + "/certificates/web/0000"}); !errors.Is(err, plugin.ErrNotFound) {
		t.Errorf("404: %v", err)
	}

	// An abandoned key is released; a completed one is kept.
	stale, err := ks.CreateCSR(ctx, plugin.CSRRequest{Config: config, CertificateID: "7", Names: names, KeyType: plugin.KeyTypeECDSAP384})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{stale.KeyRef, ref} {
		if err := ks.Release(ctx, plugin.ReleaseRequest{Config: config, KeyRef: r}); err != nil {
			t.Errorf("Release(%s): %v", r, err)
		}
	}
	if vault.HasPending("web") || len(vault.Versions("web")) != 1 {
		t.Error("Release did not delete only the pending request")
	}
	if tokens.Load() == 0 {
		t.Error("the plugin never asked the managed identity endpoint for a token")
	}
}

// TestTargetOverGRPC drives the target the plugin serves next to the key
// store: the implicit target for the key store's own certificate (found in
// place, nothing imported), a copy to another certificate (imported from
// the key store's secret), and rollbacks of both.
func TestTargetOverGRPC(t *testing.T) {
	ks, tg, vault, _ := startPlugin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	caps, err := tg.Describe(ctx)
	if err != nil || !caps.RollbackNeedsMaterial || !caps.PropagatesAsync || !caps.NeedsExportableKey {
		t.Fatalf("Describe = %+v, %v", caps, err)
	}
	ksConfig := json.RawMessage(`{"vault":"https://` + vaultHost + `","certificate_name":"web"}`)
	v, err := plugin.ValidateKeyStore(ctx, ks, plugin.KeyStoreValidateRequest{Config: ksConfig, CertificateID: "7"})
	if err != nil || v.Capabilities == nil || v.Capabilities.ImplicitTarget == nil {
		t.Fatalf("key store validate = %+v, %v", v, err)
	}
	implicit := v.Capabilities.ImplicitTarget
	if implicit.DeploymentID != "https://"+vaultHost+"/certificates/web" {
		t.Errorf("deployment id = %q", implicit.DeploymentID)
	}
	tv, err := plugin.ValidateTarget(ctx, tg, plugin.TargetValidateRequest{Config: implicit.Config, CertificateID: "7", Label: "azure-keyvault", KeyStoreDeploymentID: implicit.DeploymentID})
	if err != nil || tv.DeploymentID != implicit.DeploymentID || len(tv.Problems) != 0 {
		t.Fatalf("target validate = %+v, %v", tv, err)
	}
	drConfig := json.RawMessage(`{"vault":"https://` + vaultHost + `","certificate_name":"web-dr","tags":{"site":"dr"}}`)
	if _, err := plugin.Match(*v.Capabilities, caps, plugin.KeyTypeECDSAP256); err != nil {
		t.Fatalf("match: %v", err)
	}

	type cert struct{ ref, leaf, chain, serial string }
	issue := func() cert {
		csr, err := ks.CreateCSR(ctx, plugin.CSRRequest{Config: ksConfig, CertificateID: "7", Names: []string{"api.example.com"}, KeyType: plugin.KeyTypeECDSAP256})
		if err != nil {
			t.Fatal(err)
		}
		leaf, chain, err := fakevault.Sign(csr.PEM)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := ks.Complete(ctx, plugin.CompleteRequest{Config: ksConfig, KeyRef: csr.KeyRef, CertPEM: leaf, ChainPEM: chain})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := pem.Decode([]byte(leaf))
		c, _ := x509.ParseCertificate(b.Bytes)
		return cert{ref, leaf, chain, fmt.Sprintf("%x", c.SerialNumber)}
	}
	vaultRef := func(c cert) plugin.KeyMaterial {
		km, err := ks.Export(ctx, plugin.ExportRequest{Config: ksConfig, KeyRef: c.ref, Format: plugin.KeyFormatVaultRef})
		if err != nil {
			t.Fatal(err)
		}
		return km
	}
	deploy := func(cfg json.RawMessage, c cert) string {
		t.Helper()
		staged, err := tg.Stage(ctx, plugin.StageRequest{Config: cfg, CertificateID: "7", Label: "kv", CertPEM: c.leaf, ChainPEM: c.chain,
			FullChainPEM: c.leaf + c.chain, Key: vaultRef(c), Serial: c.serial})
		if err != nil {
			t.Fatalf("Stage: %v", err)
		}
		prev, err := tg.Activate(ctx, plugin.ActivateRequest{Config: cfg, StagedRef: staged, CertificateID: "7", Label: "kv"})
		if err != nil {
			t.Fatalf("Activate: %v", err)
		}
		return prev
	}
	current := func(cfg json.RawMessage) string {
		s, err := tg.Current(ctx, plugin.CurrentRequest{Config: cfg, CertificateID: "7"})
		if err != nil {
			t.Fatalf("Current: %v", err)
		}
		return s
	}
	rollback := func(cfg json.RawMessage, prevRef string, c cert) error {
		return tg.Rollback(ctx, plugin.RollbackRequest{Config: cfg, PreviousRef: prevRef, CertificateID: "7", Label: "kv",
			PreviousCertPEM: c.leaf, PreviousChainPEM: c.chain, PreviousFullChainPEM: c.leaf + c.chain, PreviousKey: vaultRef(c), PreviousSerial: c.serial})
	}

	first := issue()
	if prev := deploy(implicit.Config, first); prev != "" {
		t.Errorf("first deployment previous = %q", prev)
	}
	if prev := deploy(drConfig, first); prev != "" || current(drConfig) != first.serial {
		t.Errorf("first copy previous = %q, current %s", prev, current(drConfig))
	}
	second := issue()
	prev := deploy(implicit.Config, second)
	if prev != "serial:"+first.serial || current(implicit.Config) != second.serial || len(vault.Versions("web")) != 2 {
		t.Fatalf("own certificate: previous %q, current %s, versions %d", prev, current(implicit.Config), len(vault.Versions("web")))
	}
	drPrev := deploy(drConfig, second)
	if drPrev != "serial:"+first.serial || current(drConfig) != second.serial || vault.Tags("web-dr", "")["site"] != "dr" {
		t.Fatalf("copy: previous %q, current %s", drPrev, current(drConfig))
	}

	// Roll both back: the first certificate is imported again as the
	// latest version.
	if err := rollback(implicit.Config, prev, first); err != nil || current(implicit.Config) != first.serial || len(vault.Versions("web")) != 3 {
		t.Errorf("own rollback: %v, current %s", err, current(implicit.Config))
	}
	if err := rollback(drConfig, drPrev, first); err != nil || current(drConfig) != first.serial {
		t.Errorf("copy rollback: %v, current %s", err, current(drConfig))
	}
	// Without material it is refused, and the error kind survives gRPC.
	if err := tg.Rollback(ctx, plugin.RollbackRequest{Config: drConfig, PreviousRef: "serial:01", CertificateID: "7"}); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("rollback without material: %v", err)
	}
}

// startPlugin builds the plugin binary and starts it the way the connector
// does, with the fake vault reachable at https://kv.vault.test.
func startPlugin(t *testing.T) (plugin.KeyStore, plugin.Target, *fakevault.Server, *atomic.Int32) {
	t.Helper()
	if testing.Short() {
		t.Skip("builds and starts the plugin binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "krakenkey-connector-plugin-azure-keyvault")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	vault, err := fakevault.New([]string{vaultHost}, "https://vault.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vault.Close)
	proxy := httptest.NewServer(connectProxy(t, vaultHost+":443", vault.Listener.Addr().String()))
	t.Cleanup(proxy.Close)
	tokens := &atomic.Int32{}
	identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-IDENTITY-HEADER") != identityToken || r.URL.Query().Get("resource") != "https://vault.test" {
			http.Error(w, "bad token request", http.StatusBadRequest)
			return
		}
		tokens.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": fakevault.Token,
			"expires_on":   strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10),
			"resource":     "https://vault.test",
			"token_type":   "Bearer",
		})
	}))
	t.Cleanup(identity.Close)
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, vault.CAPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin)
	cmd.Env = []string{
		"HOME=" + dir,
		"SSL_CERT_FILE=" + caFile,
		"HTTPS_PROXY=" + proxy.URL,
		"IDENTITY_ENDPOINT=" + identity.URL,
		"IDENTITY_HEADER=" + identityToken,
		"AZURE_TOKEN_CREDENTIALS=ManagedIdentityCredential",
	}
	cfg := plugin.ClientConfig(cmd, hclog.New(&hclog.LoggerOptions{Output: os.Stderr, Level: hclog.Warn}))
	cfg.SkipHostEnv = true // keep the developer's own Azure settings out
	client := goplugin.NewClient(cfg)
	t.Cleanup(client.Kill)
	rpc, err := client.Client()
	if err != nil {
		t.Fatalf("start plugin: %v", err)
	}
	ks, err := plugin.DispenseKeyStore(rpc)
	if err != nil {
		t.Fatal(err)
	}
	tg, err := plugin.DispenseTarget(rpc)
	if err != nil {
		t.Fatal(err)
	}
	return ks, tg, vault, tokens
}

// connectProxy is a minimal HTTPS proxy that tunnels CONNECT requests for
// one host to the fake vault.
func connectProxy(t *testing.T, host, upstream string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != host {
			t.Errorf("proxy: unexpected %s %s", r.Method, r.Host)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		up, err := net.Dial("tcp", upstream)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = up.Close()
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() {
			_, _ = io.Copy(up, conn)
			_ = up.Close()
		}()
		_, _ = io.Copy(conn, up)
		_ = conn.Close()
	})
}
