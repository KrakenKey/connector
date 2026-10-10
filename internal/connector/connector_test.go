package connector

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/krakenkey/connector/internal/api"
	"github.com/krakenkey/connector/internal/audit"
	"github.com/krakenkey/connector/internal/certutil"
	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/deploy"
	"github.com/krakenkey/connector/internal/pluginhost"
	"github.com/krakenkey/connector/internal/testca"
	"github.com/krakenkey/connector/internal/verify"
)

// fakeKrakenKey serves the three certificate routes the connector uses and
// signs renewal CSRs with a test CA.
type fakeKrakenKey struct {
	t  *testing.T
	ca *testca.CA

	mu       sync.Mutex
	certs    map[int]*api.Cert
	requests []string
}

func newFakeKrakenKey(t *testing.T, ca *testca.CA, ids ...int) (*fakeKrakenKey, *httptest.Server) {
	f := &fakeKrakenKey{t: t, ca: ca, certs: map[int]*api.Cert{}}
	for _, id := range ids {
		leaf, leafPEM := ca.Issue(t, testca.Key(t).Public(), []string{"api.example.com"}, 0)
		later := time.Now().Add(60 * 24 * time.Hour)
		f.certs[id] = &api.Cert{ID: id, Status: api.StatusIssued, CrtPem: leafPEM, ChainPem: ca.IntermediatePEM,
			ExpiresAt: &leaf.NotAfter, RenewAfter: &later}
	}
	srv := httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeKrakenKey) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "Bearer kk_test" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/certs/tls/"), "/")
	id, _ := strconv.Atoi(parts[0])
	cert, ok := f.certs[id]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"statusCode":404,"message":"Certificate not found"}`))
		return
	}
	switch {
	case r.Method == http.MethodGet && len(parts) == 1:
		_ = json.NewEncoder(w).Encode(cert)
	case r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "chain":
		_ = json.NewEncoder(w).Encode(api.Chain{FullChainPem: cert.CrtPem + cert.ChainPem})
	case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "renew":
		var body struct{ CsrPem string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		req, err := certutil.ParseCSR(body.CsrPem)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		leaf, leafPEM := f.ca.Issue(f.t, req.PublicKey, certutil.CSRNames(req), 0)
		later := time.Now().Add(60 * 24 * time.Hour)
		cert.CrtPem, cert.ExpiresAt, cert.RenewAfter = leafPEM, &leaf.NotAfter, &later
		_ = json.NewEncoder(w).Encode(api.CertResponse{ID: id, Status: api.StatusRenewing})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// tlsFromDir starts a TLS server that loads its certificate from files on
// every handshake, like a web server after a reload.
func tlsFromDir(t *testing.T, dir string) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, err := tls.LoadX509KeyPair(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "key.pem"))
		return &c, err
	}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func writeConfig(t *testing.T, yaml string) *config.Config {
	t.Helper()
	t.Setenv("KK_API_URL", "")
	cfg, err := config.Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func TestRunOnceEndToEnd(t *testing.T) {
	ca := testca.New(t)
	kk, apiSrv := newFakeKrakenKey(t, ca, 1043, 2000)
	tmp := t.TempDir()
	webDir := filepath.Join(tmp, "web")
	if err := os.Mkdir(webDir, 0o755); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(tmp, "roots.pem")
	_ = os.WriteFile(caFile, []byte(ca.RootPEM), 0o600)
	addr := tlsFromDir(t, webDir)
	hookLog := filepath.Join(tmp, "hook.log")

	cfg := writeConfig(t, fmt.Sprintf(`
krakenkey: { api_url: %q }
data_dir: %s
certificates:
  - id: 1043
    names: [api.example.com]
    targets:
      - label: web
        plugin: file
        dir: %s
        files: { cert: cert.pem, chain: chain.pem, fullchain: fullchain.pem, key: key.pem }
        then: { exec: [sh, -c, 'echo "$KK_ACTION $KK_TARGET_LABEL" >> %s'] }
        verify: { host: api.example.com, address: %q, ca_file: %s, window: 20s }
  - id: 2000
    names: [api.example.com]
    targets:
      - { label: other, plugin: exec, command: [/bin/true] }
`, apiSrv.URL, filepath.Join(tmp, "data"), webDir, hookLog, addr, caFile))

	auditLog, err := audit.Open(filepath.Join(tmp, "data", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = auditLog.Close() }()
	state, _ := deploy.OpenStateStore(cfg.DataDir)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	host := pluginhost.New(cfg, log)
	defer host.Close()
	c := &Connector{
		Config: cfg, Resolver: host, Log: log,
		Engine: &deploy.Engine{
			API:      api.NewClient(cfg.KrakenKey.APIURL, "kk_test", "test"),
			Verifier: &verify.Verifier{DialTimeout: time.Second, MinBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond},
			Audit:    auditLog, State: state, Log: log,
		},
	}

	// Limit the pass to one certificate, as `run --once --cert 1043` does.
	if err := c.RunOnce(context.Background(), RunOptions{CertID: 1043}); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	for _, r := range kk.requests {
		if strings.Contains(r, "/2000") {
			t.Errorf("certificate 2000 was touched: %s", r)
		}
	}

	// The web server now serves the renewed certificate.
	served, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "api.example.com", RootCAs: ca.Pool()})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	gotSerial := certutil.SerialHex(served.ConnectionState().PeerCertificates[0].SerialNumber)
	_ = served.Close()
	wantLeaf, _ := certutil.ParseLeaf(kk.certs[1043].CrtPem)
	if gotSerial != certutil.SerialHex(wantLeaf.SerialNumber) {
		t.Errorf("served serial %s, want %s", gotSerial, certutil.SerialHex(wantLeaf.SerialNumber))
	}

	hook, _ := os.ReadFile(hookLog)
	if strings.TrimSpace(string(hook)) != "deploy web" {
		t.Errorf("then hook runs = %q", hook)
	}

	// Audit log has the full sequence, with the previous ref recorded.
	f, _ := os.Open(filepath.Join(tmp, "data", "audit.jsonl"))
	defer func() { _ = f.Close() }()
	var steps []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e audit.Entry
		_ = json.Unmarshal(sc.Bytes(), &e)
		steps = append(steps, e.Step+":"+e.Result)
		if e.Step == audit.StepActivate && e.PreviousRef == "" {
			t.Error("activate entry without previous_ref")
		}
		if strings.Contains(sc.Text(), "PRIVATE KEY") {
			t.Error("audit log contains key material")
		}
	}
	want := "create_csr:ok renew:ok issued:ok stage:ok activate:ok then:ok verify:ok"
	if strings.Join(steps, " ") != want {
		t.Errorf("audit steps = %s\nwant %s", strings.Join(steps, " "), want)
	}

	// Force a second renewal: the first key is released afterwards.
	keysDir := filepath.Join(cfg.DataDir, "keys", "1043")
	if err := c.RunOnce(context.Background(), RunOptions{CertID: 1043, Force: true}); err != nil {
		t.Fatalf("forced RunOnce: %v", err)
	}
	entries, _ := os.ReadDir(keysDir)
	keys := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".key") {
			keys++
		}
	}
	if keys != 1 {
		t.Errorf("%d keys on disk after a verified renewal, want 1", keys)
	}
}

func TestRunOnceStopsOnAuthError(t *testing.T) {
	ca := testca.New(t)
	kk, apiSrv := newFakeKrakenKey(t, ca, 1, 2)
	tmp := t.TempDir()
	cfg := writeConfig(t, fmt.Sprintf(`
krakenkey: { api_url: %q }
data_dir: %s
certificates:
  - { id: 1, names: [api.example.com], targets: [{ label: a, plugin: exec, command: [/bin/true] }] }
  - { id: 2, names: [api.example.com], targets: [{ label: a, plugin: exec, command: [/bin/true] }] }
`, apiSrv.URL, filepath.Join(tmp, "data")))
	state, _ := deploy.OpenStateStore(cfg.DataDir)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	host := pluginhost.New(cfg, log)
	defer host.Close()
	c := &Connector{Config: cfg, Resolver: host, Log: log, Engine: &deploy.Engine{
		API: api.NewClient(cfg.KrakenKey.APIURL, "kk_wrong", "test"), Verifier: verify.New(),
		Audit: &discardAudit{}, State: state, Log: log,
	}}
	err := c.RunOnce(context.Background(), RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v", err)
	}
	if len(kk.requests) != 1 {
		t.Errorf("requests after a 401: %v", kk.requests)
	}
	if err := c.Run(context.Background()); err == nil {
		t.Error("Run did not stop on a 401")
	}
}

type discardAudit struct{}

func (discardAudit) Write(audit.Entry) error { return nil }

func TestValidateReport(t *testing.T) {
	ca := testca.New(t)
	kk, apiSrv := newFakeKrakenKey(t, ca, 1043)
	tmp := t.TempDir()
	cfg := writeConfig(t, fmt.Sprintf(`
krakenkey: { api_url: %q }
data_dir: %s
certificates:
  - id: 1043
    names: [api.example.com, extra.example.com]
    key_store: { key_type: rsa-4096 }
    targets:
      - label: web
        plugin: file
        dir: /does/not/exist
        files: { fullchain: f.pem, key: k.pem }
        verify: { host: api.example.com, address: "127.0.0.1:8443", skip_chain_validation: true }
  - id: 404
    names: [api.example.com]
    targets:
      - { label: hook, plugin: exec, command: [/bin/true], verify: { host: api.example.com } }
`, apiSrv.URL, filepath.Join(tmp, "data")))
	host := pluginhost.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer host.Close()
	manual := "manual"
	kk.certs[1043].AutoRenew, kk.certs[1043].ManagedBy = true, &manual

	var out bytes.Buffer
	n := Validate(context.Background(), cfg, host, api.NewClient(cfg.KrakenKey.APIURL, "kk_test", "test"), &out)
	report := out.String()
	for _, want := range []string{
		"PROBLEM: with key store local: key store cannot create rsa-4096 keys",
		"PROBLEM: dir /does/not/exist",
		"verify: TLS to 127.0.0.1:8443 with SNI api.example.com, window 10m0s, chain NOT validated (skip_chain_validation)",
		"WARNING: certificate 1043: target web skips chain validation",
		"PROBLEM: config names [api.example.com extra.example.com] differ from the certificate's names [api.example.com]",
		"KrakenKey: status issued",
		"renew after",
		"PROBLEM: KrakenKey has no certificate 404",
		"verify: TLS to api.example.com:443 with SNI api.example.com, window 10m0s, chain checked against system roots",
		"target hook (exec): key as pem, rollback supported",
		"WARNING: KrakenKey also renews certificate 1043 on its own (autoRenew is on)",
		`WARNING: KrakenKey reports certificate 1043 as managed by "manual"`,
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report does not contain %q", want)
		}
	}
	if n != 4 || !strings.Contains(report, "4 problem(s), 3 warning(s)") {
		t.Errorf("problems = %d\n%s", n, report)
	}
}
