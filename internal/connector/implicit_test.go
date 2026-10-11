package connector

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/krakenkey/connector/internal/api"
	"github.com/krakenkey/connector/internal/audit"
	"github.com/krakenkey/connector/internal/certutil"
	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/deploy"
	"github.com/krakenkey/connector/internal/testca"
	"github.com/krakenkey/connector/internal/testplugin"
	"github.com/krakenkey/connector/internal/verify"
	"github.com/krakenkey/connector/pkg/plugin"
)

// vaultResolver serves one in-memory vault as both the key store and the
// target of the plugin "vault". The plugin "copy" serves another target
// over the same vault, so it can deploy to the key store's place without
// being the key store's plugin.
type vaultResolver struct {
	v *testplugin.Vault
	t *testplugin.VaultTarget
}

func newVaultResolver() vaultResolver {
	v := testplugin.NewVault()
	return vaultResolver{v: v, t: v.Target()}
}

func (r vaultResolver) KeyStore(name string) (plugin.KeyStore, error) {
	if name != "vault" {
		return nil, fmt.Errorf("unknown key store %q", name)
	}
	return r.v, nil
}

func (r vaultResolver) Target(name string) (plugin.Target, error) {
	if name != "vault" && name != "copy" {
		return nil, fmt.Errorf("unknown target %q", name)
	}
	return r.t, nil
}

func vaultCert(targets ...config.Target) config.Certificate {
	return config.Certificate{
		ID: 7, Names: []string{"api.example.com"},
		KeyStore: config.KeyStore{Plugin: "vault", KeyType: plugin.KeyTypeECDSAP256, Settings: map[string]any{"vault": "main"}},
		Targets:  targets,
	}
}

func TestConfigAllowsNoTargetsOnlyForExternalKeyStores(t *testing.T) {
	t.Setenv("KK_API_URL", "")
	_, err := config.Parse(strings.NewReader(`
certificates:
  - { id: 1, names: [api.example.com] }
`))
	if err == nil || !strings.Contains(err.Error(), "targets must list at least one target") {
		t.Errorf("local key store without targets: %v", err)
	}
	if _, err := config.Parse(strings.NewReader(`
plugins: { vault: { path: /opt/vault } }
certificates:
  - { id: 1, names: [api.example.com], key_store: { plugin: vault, vault: main } }
`)); err != nil {
		t.Errorf("external key store without targets: %v", err)
	}
}

func TestImplicitTargetAdded(t *testing.T) {
	r := newVaultResolver()
	job, rep := BuildJob(context.Background(), vaultCert(), r)
	if !rep.OK() || len(rep.Targets) != 1 || len(job.Targets) != 1 || len(job.Cert.Targets) != 1 {
		t.Fatalf("report %+v %+v", rep, rep.Targets)
	}
	tr, tc := rep.Targets[0], job.Cert.Targets[0]
	if tr.Label != "vault" || tc.Label != "vault" || config.ImplicitTargetLabel("vault") != "vault" {
		t.Errorf("label = %q / %q", tr.Label, tc.Label)
	}
	if !tr.Implicit || !tr.KeyStoreDeployment || !tc.Implicit || !tc.KeyStoreDeployment || tc.Plugin != "vault" {
		t.Errorf("not marked implicit: %+v %+v", tr, tc)
	}
	if tr.Format != plugin.KeyFormatVaultRef || tr.RollbackUnavailable != "" {
		t.Errorf("format %s, rollback unavailable %q", tr.Format, tr.RollbackUnavailable)
	}
	if s, _ := tc.SettingsJSON(); string(s) != `{"vault":"main"}` {
		t.Errorf("settings = %s", s)
	}
	if reqs := r.t.ValidateRequests; len(reqs) != 1 || reqs[0].KeyStoreDeploymentID != "vault:main" {
		t.Errorf("validate requests = %+v", reqs)
	}
}

func TestExplicitTargetReplacesImplicit(t *testing.T) {
	r := newVaultResolver()
	verifyBlock := &config.Verify{Host: "api.example.com", Port: 443}
	cert := vaultCert(
		config.Target{Label: "copy-dr", Plugin: "copy", Settings: map[string]any{"vault": "dr"}},
		config.Target{Label: "edge", Plugin: "vault", Settings: map[string]any{"vault": "MAIN"}, Verify: verifyBlock},
	)
	job, rep := BuildJob(context.Background(), cert, r)
	if !rep.OK() || len(rep.Targets) != 2 {
		t.Fatalf("report %+v", rep.Targets)
	}
	if got := []string{job.Cert.Targets[0].Label, job.Cert.Targets[1].Label}; got[0] != "copy-dr" || got[1] != "edge" {
		t.Errorf("targets = %v", got)
	}
	edge := rep.Targets[1]
	if edge.Implicit || !edge.KeyStoreDeployment || !job.Cert.Targets[1].KeyStoreDeployment || job.Cert.Targets[1].Verify != verifyBlock {
		t.Errorf("edge = %+v", edge)
	}
	if rep.Targets[0].KeyStoreDeployment {
		t.Error("a target of another plugin is not the key store's deployment")
	}
	// The key store deployment id goes only to targets of the key
	// store's plugin.
	for _, req := range r.t.ValidateRequests {
		if want := map[string]string{"copy-dr": "", "edge": "vault:main"}[req.Label]; req.KeyStoreDeploymentID != want {
			t.Errorf("validate %s got key store deployment %q, want %q", req.Label, req.KeyStoreDeploymentID, want)
		}
	}

	var out bytes.Buffer
	cfg := &config.Config{Certificates: []config.Certificate{cert}}
	if n := Validate(context.Background(), cfg, r, nil, &out); n != 0 ||
		!strings.Contains(out.String(), "target edge (vault, the key store's own deployment, replacing the implicit target)") ||
		strings.Contains(out.String(), "implicit: added") {
		t.Errorf("validate (%d problems):\n%s", n, out.String())
	}
}

func TestValidateShowsImplicitTarget(t *testing.T) {
	r := newVaultResolver()
	var out bytes.Buffer
	cfg := &config.Config{Certificates: []config.Certificate{vaultCert()}}
	if n := Validate(context.Background(), cfg, r, nil, &out); n != 0 {
		t.Fatalf("validate (%d problems):\n%s", n, out.String())
	}
	for _, want := range []string{
		"target vault (vault, implicit: added by the key store, which deploys there itself): key as vault_ref",
		"verify: none",
		"add a target of plugin vault that deploys to the key store's certificate, with a verify block",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("validate output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestImplicitTargetProblems(t *testing.T) {
	cases := map[string]struct {
		cert config.Certificate
		want string
	}{
		"two targets in one place": {
			vaultCert(
				config.Target{Label: "a", Plugin: "copy", Settings: map[string]any{"vault": "dr"}},
				config.Target{Label: "b", Plugin: "copy", Settings: map[string]any{"vault": "DR"}},
			),
			"deploys to the same place as target a",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, rep := BuildJob(context.Background(), c.cert, newVaultResolver())
			if rep.OK() || !strings.Contains(firstProblem(rep), c.want) {
				t.Errorf("problem = %q, want %q", firstProblem(rep), c.want)
			}
		})
	}
}

func TestNoTargetsWithoutImplicitTarget(t *testing.T) {
	cert := config.Certificate{
		ID: 7, Names: []string{"api.example.com"},
		KeyStore: config.KeyStore{Plugin: "vault", KeyType: plugin.KeyTypeECDSAP256},
	}
	general := plugin.KeyStoreCapabilities{Provides: []plugin.KeyFormat{plugin.KeyFormatPEM}, Exportable: true, KeyTypes: []plugin.KeyType{plugin.KeyTypeECDSAP256}}
	// Describe's implicit target is ignored: it has no settings.
	general.ImplicitTarget = &plugin.ImplicitTarget{Config: []byte(`{}`), DeploymentID: "x"}
	_, rep := BuildJob(context.Background(), cert, capsResolver{ks: general})
	if rep.OK() || len(rep.Targets) != 0 || !strings.Contains(firstProblem(rep), "targets must list at least one target (key store vault adds none by itself)") {
		t.Errorf("report %+v", rep)
	}

	// An implicit target without a deployment id is refused.
	withoutID := general
	withoutID.ImplicitTarget = &plugin.ImplicitTarget{Config: []byte(`{}`)}
	_, rep = BuildJob(context.Background(), cert, capsResolver{ks: general, effective: &withoutID})
	if rep.OK() || !strings.Contains(firstProblem(rep), "no deployment id") {
		t.Errorf("report %+v", rep)
	}
}

func TestImplicitTargetWithLockedKeyStore(t *testing.T) {
	r := newVaultResolver()
	r.v.Exportable = false
	cert := vaultCert(config.Target{Label: "dr", Plugin: "copy", Settings: map[string]any{"vault": "dr"}})
	_, rep := BuildJob(context.Background(), cert, r)
	if len(rep.Targets) != 2 {
		t.Fatalf("targets %+v", rep.Targets)
	}
	// The key store's own deployment needs no export, but cannot roll back.
	own := rep.Targets[0]
	if !own.Implicit || len(own.Problems) != 0 || !strings.Contains(own.RollbackUnavailable, "does not allow export") || len(own.Warnings) != 1 {
		t.Errorf("implicit target = %+v", own)
	}
	// Another place needs the key, which the key store will not give.
	if dr := rep.Targets[1]; !strings.Contains(strings.Join(dr.Problems, "; "), "target needs the private key, but the key store does not allow export") {
		t.Errorf("dr target = %+v", dr)
	}
}

// vaultEnv runs passes with the in-memory vault, a fake KrakenKey and an
// endpoint that serves the vault's latest version.
type vaultEnv struct {
	t      *testing.T
	ca     *testca.CA
	kk     *fakeKrakenKey
	apiURL string
	r      vaultResolver
	tmp    string
	addr   string
	caFile string
	sent   *sentReports
	// sharer, if set, gets the config summary after each pass.
	sharer *ConfigSharer
}

func newVaultEnv(t *testing.T) *vaultEnv {
	e := &vaultEnv{t: t, ca: testca.New(t), r: newVaultResolver(), tmp: t.TempDir(), sent: &sentReports{}}
	var srv *httptest.Server
	e.kk, srv = newFakeKrakenKey(t, e.ca, 1043)
	e.apiURL = srv.URL
	e.caFile = filepath.Join(e.tmp, "roots.pem")
	if err := os.WriteFile(e.caFile, []byte(e.ca.RootPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	tlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tlsSrv.TLS = &tls.Config{GetCertificate: e.r.v.GetCertificate("main")}
	tlsSrv.StartTLS()
	t.Cleanup(tlsSrv.Close)
	e.addr = tlsSrv.Listener.Addr().String()
	return e
}

func (e *vaultEnv) config(targets string) *config.Config {
	return writeConfig(e.t, fmt.Sprintf(`
krakenkey: { api_url: %q }
data_dir: %s
plugins: { vault: { path: /opt/krakenkey-connector-plugin-vault }, copy: { path: /opt/krakenkey-connector-plugin-vault } }
certificates:
  - id: 1043
    names: [api.example.com]
    key_store: { plugin: vault, vault: main }
%s
`, e.apiURL, filepath.Join(e.tmp, "data"), targets))
}

func (e *vaultEnv) run(cfg *config.Config, force bool) error {
	e.t.Helper()
	auditLog, err := audit.Open(cfg.AuditLog)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = auditLog.Close() }()
	state, err := deploy.OpenStateStore(cfg.DataDir)
	if err != nil {
		e.t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := &Connector{
		Config: cfg, Resolver: e.r, Log: log,
		Engine: &deploy.Engine{
			API:      api.NewClient(cfg.KrakenKey.APIURL, "kk_test", "test"),
			Verifier: &verify.Verifier{DialTimeout: time.Second, MinBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond},
			Audit:    auditLog, State: state, Log: log,
		},
		Reporter:     &Reporter{API: e.sent, Config: cfg, State: state, Log: log},
		ConfigSharer: e.sharer,
	}
	return c.RunOnce(context.Background(), RunOptions{Force: force})
}

func (e *vaultEnv) serial() string {
	leaf, err := certutil.ParseLeaf(e.kk.certs[1043].CrtPem)
	if err != nil {
		e.t.Fatal(err)
	}
	return certutil.SerialHex(leaf.SerialNumber)
}

func (e *vaultEnv) lastReport() api.ReportCertificate {
	e.t.Helper()
	if len(e.sent.reports) == 0 {
		e.t.Fatal("nothing reported")
	}
	rep := e.sent.reports[len(e.sent.reports)-1]
	if len(rep.Certificates) != 1 {
		e.t.Fatalf("report = %+v", rep)
	}
	return rep.Certificates[0]
}

func (e *vaultEnv) state() *deploy.State {
	store, _ := deploy.OpenStateStore(filepath.Join(e.tmp, "data"))
	st, err := store.Load(1043)
	if err != nil || st == nil {
		e.t.Fatalf("state: %v", err)
	}
	return st
}

// TestImplicitTargetEndToEnd runs a certificate without configured targets
// whose key store deploys by itself: it is deployed, reported and, once a
// configured target with a verify block replaces the implicit one,
// verified.
func TestImplicitTargetEndToEnd(t *testing.T) {
	e := newVaultEnv(t)

	// No targets: the implicit one is deployed and reported, unverified.
	cfg := e.config("")
	if err := e.run(cfg, false); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	first := e.serial()
	if got := e.r.v.Latest("main"); got != first {
		t.Fatalf("vault latest = %s, want %s", got, first)
	}
	if vs := e.r.v.Versions("main"); len(vs) != 1 {
		t.Errorf("the implicit target added versions: %d", len(vs))
	}
	if ts := e.state().Targets["vault"]; ts.Serial != first || ts.Outcome != deploy.OutcomeUnverifiable {
		t.Errorf("state = %+v", ts)
	}
	rc := e.lastReport()
	if len(rc.Targets) != 1 || rc.Targets[0].Label != "vault" || rc.Targets[0].State != api.DeployActivatedUnverifiable || rc.Targets[0].Serial != first {
		t.Errorf("report = %+v", rc.Targets)
	}
	entries := readAudit(t, cfg.AuditLog)
	if !strings.Contains(entries, "stage:ok") || !strings.Contains(entries, "activate:ok") || !strings.Contains(entries, "verify:skipped") {
		t.Errorf("audit = %s", entries)
	}

	// A configured target for the same place with a verify block replaces
	// the implicit target; a renewal is verified on the endpoint.
	cfg = e.config(fmt.Sprintf(`    targets:
      - label: edge
        plugin: vault
        vault: MAIN
        verify: { host: api.example.com, address: %q, ca_file: %s, window: 20s }`, e.addr, e.caFile))
	if err := e.run(cfg, true); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	second := e.serial()
	if second == first || e.r.v.Latest("main") != second || len(e.r.v.Versions("main")) != 2 {
		t.Fatalf("vault versions %+v, want latest %s", e.r.v.Versions("main"), second)
	}
	st := e.state()
	if ts := st.Targets["edge"]; ts.Serial != second || ts.Outcome != deploy.OutcomeVerified {
		t.Errorf("edge state = %+v", ts)
	}
	if _, ok := st.Targets["vault"]; ok {
		t.Error("the replaced implicit target is still in the state")
	}
	rc = e.lastReport()
	if len(rc.Targets) != 1 || rc.Targets[0].Label != "edge" || rc.Targets[0].State != api.DeployVerified || rc.Targets[0].Serial != second {
		t.Errorf("report = %+v", rc.Targets)
	}
}

// TestKeyStoreDeploymentRollsBack checks that rolling back the key store's
// own deployment puts the previous certificate back as the latest
// version, although the target already served the new one before
// Activate.
func TestKeyStoreDeploymentRollsBack(t *testing.T) {
	e := newVaultEnv(t)
	if err := e.run(e.config(""), false); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	first := e.serial()

	// The same label as the implicit target keeps its history. The then
	// command fails after a deployment and succeeds after a rollback.
	cfg := e.config(`    targets:
      - label: vault
        plugin: vault
        vault: main
        then: { exec: [sh, -c, 'test "$KK_ACTION" = rollback'] }`)
	err := e.run(cfg, true)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("second pass: %v", err)
	}
	second := e.serial()
	vs := e.r.v.Versions("main")
	if len(vs) != 3 || vs[1].Serial != second || vs[2].Serial != first || e.r.v.Latest("main") != first {
		t.Fatalf("vault versions after rollback: %+v", vs)
	}
	ts := e.state().Targets["vault"]
	if ts.Serial != first || ts.Outcome != deploy.OutcomeRolledBack || ts.LiveBefore != "" {
		t.Errorf("state = %+v", ts)
	}
	rc := e.lastReport()
	if len(rc.Targets) != 1 || rc.Targets[0].State != api.DeployRolledBack || rc.Targets[0].Serial != first {
		t.Errorf("report = %+v", rc.Targets)
	}
}

// TestKeyStoreDeploymentRollbackRefusedWithoutExport checks that the key
// store's own deployment reports a failed rollback, and keeps the new
// certificate, when the key store does not allow export.
func TestKeyStoreDeploymentRollbackRefusedWithoutExport(t *testing.T) {
	e := newVaultEnv(t)
	e.r.v.Exportable = false
	if err := e.run(e.config(""), false); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	cfg := e.config(`    targets:
      - label: vault
        plugin: vault
        vault: main
        then: { exec: [/bin/false] }`)
	err := e.run(cfg, true)
	if err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("second pass: %v", err)
	}
	second := e.serial()
	if e.r.v.Latest("main") != second {
		t.Errorf("vault latest = %s, want the new %s", e.r.v.Latest("main"), second)
	}
	ts := e.state().Targets["vault"]
	if ts.Serial != second || ts.Outcome != deploy.OutcomeFailed {
		t.Errorf("state = %+v", ts)
	}
	if rc := e.lastReport(); rc.Targets[0].State != api.DeployFailed || !strings.Contains(rc.Targets[0].Error, "rollback failed") {
		t.Errorf("report = %+v", rc.Targets)
	}
}

func readAudit(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	var steps []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e audit.Entry
		if err := json.Unmarshal([]byte(line), &e); err == nil {
			steps = append(steps, e.Step+":"+e.Result)
		}
	}
	return strings.Join(steps, " ")
}

// TestImplicitTargetLabelTaken keeps a config from before implicit targets
// working when a target there already uses the implicit target's label.
func TestImplicitTargetLabelTaken(t *testing.T) {
	r := newVaultResolver()
	job, rep := BuildJob(context.Background(), vaultCert(config.Target{Label: "vault", Plugin: "copy", Settings: map[string]any{"vault": "dr"}}), r)
	if !rep.OK() || len(rep.Targets) != 1 || len(job.Cert.Targets) != 1 || rep.Targets[0].Implicit {
		t.Fatalf("report %+v %+v", rep, rep.Targets)
	}
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], `the configured target "vault", which deploys somewhere else, uses its label`) {
		t.Errorf("warnings = %q", rep.Warnings)
	}
	var out bytes.Buffer
	cfg := &config.Config{Certificates: []config.Certificate{vaultCert(config.Target{Label: "vault", Plugin: "copy", Settings: map[string]any{"vault": "dr"}})}}
	if n := Validate(context.Background(), cfg, r, nil, &out); n != 0 || !strings.Contains(out.String(), "  WARNING: key store vault deploys to its own certificate") {
		t.Errorf("validate (%d problems):\n%s", n, out.String())
	}
	// A target that replaces the implicit one may use the label, and no
	// warning is given then.
	_, rep = BuildJob(context.Background(), vaultCert(config.Target{Label: "vault", Plugin: "vault", Settings: map[string]any{"vault": "main"}}), r)
	if !rep.OK() || len(rep.Warnings) != 0 || !rep.Targets[0].KeyStoreDeployment {
		t.Errorf("replacing target: %+v %+v", rep, rep.Targets)
	}
}

func TestImplicitTargetWithoutDeploymentID(t *testing.T) {
	r := newVaultResolver()
	r.t.NoDeploymentID = true
	_, rep := BuildJob(context.Background(), vaultCert(), r)
	if rep.OK() || len(rep.Targets) != 1 || !strings.Contains(firstProblem(rep), "does not say where it deploys (no deployment id)") {
		t.Errorf("report %+v %+v", rep, rep.Targets)
	}
}

// checksumResolver says that the plugins "vault" and "copy" are the same
// executable.
type checksumResolver struct{ vaultResolver }

func (checksumResolver) PluginChecksum(name string) string {
	if name == "vault" || name == "copy" {
		return "abc123"
	}
	return ""
}

func TestSameExecutableUnderTwoNames(t *testing.T) {
	cert := vaultCert(config.Target{Label: "other-name", Plugin: "copy", Settings: map[string]any{"vault": "main"}})
	_, rep := BuildJob(context.Background(), cert, checksumResolver{newVaultResolver()})
	if len(rep.Targets) != 2 {
		t.Fatalf("targets %+v", rep.Targets)
	}
	if w := strings.Join(rep.Targets[1].Warnings, "; "); !strings.Contains(w, "plugins copy and vault are the same executable") {
		t.Errorf("warnings = %q", w)
	}
	// Without checksums (built-in plugins, or not started) nothing is said.
	_, rep = BuildJob(context.Background(), cert, newVaultResolver())
	if len(rep.Targets[1].Warnings) != 0 {
		t.Errorf("warnings without checksums = %q", rep.Targets[1].Warnings)
	}
}

// TestAsyncKeyStoreDeploymentVerifiesAgain checks a target that picks up
// changes on its own schedule: a failed check is reported as failed on
// that target, not rolled back, and checked again on the next pass.
func TestAsyncKeyStoreDeploymentVerifiesAgain(t *testing.T) {
	e := newVaultEnv(t)
	e.r.t.Async = true
	stale := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	stale.TLS = &tls.Config{GetCertificate: e.r.v.GetCertificate("empty")}
	stale.Config.ErrorLog = stdlog.New(io.Discard, "", 0)
	stale.StartTLS()
	t.Cleanup(stale.Close)
	target := func(addr string) string {
		return fmt.Sprintf(`    targets:
      - label: vault
        plugin: vault
        vault: main
        verify: { host: api.example.com, address: %q, ca_file: %s, window: 1s }`, addr, e.caFile)
	}

	err := e.run(e.config(target(stale.Listener.Addr().String())), false)
	if err == nil || !strings.Contains(err.Error(), "verify failed; not rolled back because the target picks up changes on its own schedule") {
		t.Fatalf("first pass: %v", err)
	}
	serial := e.serial()
	if vs := e.r.v.Versions("main"); len(vs) != 1 {
		t.Errorf("rolled back: %d versions", len(vs))
	}
	if ts := e.state().Targets["vault"]; ts.Serial != serial || ts.Outcome != deploy.OutcomeVerifyFailed {
		t.Errorf("state = %+v", ts)
	}
	rc := e.lastReport()
	if rc.Targets[0].State != api.DeployFailed || rc.Targets[0].Serial != serial || !strings.Contains(rc.Targets[0].Error, "not rolled back") {
		t.Errorf("report = %+v", rc.Targets)
	}

	// The next pass checks again, without deploying again.
	stages := e.r.t.Stages
	if err := e.run(e.config(target(e.addr)), false); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if e.r.t.Stages != stages {
		t.Error("the second pass deployed again")
	}
	if ts := e.state().Targets["vault"]; ts.Outcome != deploy.OutcomeVerified || ts.LastError != "" {
		t.Errorf("state = %+v", ts)
	}
	if rc := e.lastReport(); rc.Targets[0].State != api.DeployVerified {
		t.Errorf("report = %+v", rc.Targets)
	}
}

// TestKeyStoreDeploymentStageFailure checks that a failed Stage on the key
// store's own deployment, which the key store made live already, is
// recorded as activated rather than failed on the old certificate.
func TestKeyStoreDeploymentStageFailure(t *testing.T) {
	e := newVaultEnv(t)
	if err := e.run(e.config(""), false); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	e.r.t.FailStage = fmt.Errorf("%w: vault busy", plugin.ErrUnavailable)
	if err := e.run(e.config(""), true); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	serial := e.serial()
	if ts := e.state().Targets["vault"]; ts.Serial != serial || ts.Outcome != deploy.OutcomeUnverifiable {
		t.Errorf("state = %+v", ts)
	}
	if rc := e.lastReport(); rc.Targets[0].State != api.DeployActivatedUnverifiable || rc.Targets[0].Serial != serial {
		t.Errorf("report = %+v", rc.Targets)
	}
	if a := readAudit(t, filepath.Join(e.tmp, "data", "audit.jsonl")); !strings.Contains(a, "stage:failed recover:ok verify:skipped") {
		t.Errorf("audit = %s", a)
	}
}

// TestUpgradeAddsImplicitTarget runs a certificate first as a connector
// before implicit targets would (no implicit target), then with them: the
// implicit target is deployed without a renewal, and the configured target
// is left alone. A configured target that already uses the implicit
// target's label keeps working.
func TestUpgradeAddsImplicitTarget(t *testing.T) {
	for _, label := range []string{"lb", "vault"} {
		t.Run(label, func(t *testing.T) {
			e := newVaultEnv(t)
			e.r.v.NoImplicit = true
			cfg := e.config(fmt.Sprintf(`    targets:
      - { label: %s, plugin: copy, vault: dr }`, label))
			if err := e.run(cfg, false); err != nil {
				t.Fatalf("before the upgrade: %v", err)
			}
			serial := e.serial()
			e.kk.mu.Lock()
			renewals := len(e.kk.requests)
			e.kk.mu.Unlock()
			stages := e.r.t.Stages

			e.r.v.NoImplicit = false
			if err := e.run(cfg, false); err != nil {
				t.Fatalf("after the upgrade: %v", err)
			}
			for _, req := range e.kk.requests[renewals:] {
				if strings.HasSuffix(req, "/renew") {
					t.Errorf("renewed after the upgrade: %s", req)
				}
			}
			st := e.state()
			rc := e.lastReport()
			if label == "vault" {
				if e.r.t.Stages != stages || len(rc.Targets) != 1 || rc.Targets[0].Label != "vault" || st.Targets["vault"].Serial != serial {
					t.Errorf("label taken: stages %d -> %d, report %+v", stages, e.r.t.Stages, rc.Targets)
				}
				return
			}
			if e.r.t.Stages != stages+1 {
				t.Errorf("stages %d -> %d, want one for the implicit target", stages, e.r.t.Stages)
			}
			if st.Targets["vault"].Serial != serial || st.Targets["lb"].Serial != serial {
				t.Errorf("state = %+v", st.Targets)
			}
			if len(rc.Targets) != 2 || rc.Targets[0].Label != "vault" || rc.Targets[1].Label != "lb" {
				t.Errorf("report = %+v", rc.Targets)
			}
		})
	}
}
