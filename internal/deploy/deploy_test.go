package deploy

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/krakenkey/connector/internal/api"
	"github.com/krakenkey/connector/internal/audit"
	"github.com/krakenkey/connector/internal/certutil"
	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/testca"
	"github.com/krakenkey/connector/internal/testplugin"
	"github.com/krakenkey/connector/internal/verify"
	"github.com/krakenkey/connector/pkg/plugin"
)

var names = []string{"api.example.com", "www.example.com"}

// fakeAPI is KrakenKey with an in-memory CA.
type fakeAPI struct {
	t  *testing.T
	ca *testca.CA

	mu     sync.Mutex
	cert   api.Cert
	renews int
	// Overrides for the next issuance.
	issueNames []string
	issueKey   crypto.PublicKey
	failIssue  string
	// hang makes WaitForIssuance give up although the certificate is
	// issued, like a timeout or a cancelled pass.
	hang bool
}

func newFakeAPI(t *testing.T) *fakeAPI {
	ca := testca.New(t)
	// The certificate as first issued, for a key the connector never saw.
	leaf, leafPEM := ca.Issue(t, testca.Key(t).Public(), names, 0)
	renewAfter := time.Now().Add(60 * 24 * time.Hour)
	return &fakeAPI{t: t, ca: ca, cert: api.Cert{
		ID: 1043, Status: api.StatusIssued, CrtPem: leafPEM, ChainPem: ca.IntermediatePEM,
		ExpiresAt: &leaf.NotAfter, RenewAfter: &renewAfter,
	}}
}

func (f *fakeAPI) GetCert(context.Context, int) (*api.Cert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.cert
	return &c, nil
}

func (f *fakeAPI) issue(pub crypto.PublicKey, n []string) {
	leaf, leafPEM := f.ca.Issue(f.t, pub, n, 0)
	renewAfter := time.Now().Add(60 * 24 * time.Hour)
	f.cert.CrtPem, f.cert.Status, f.cert.ExpiresAt, f.cert.RenewAfter = leafPEM, api.StatusIssued, &leaf.NotAfter, &renewAfter
}

func (f *fakeAPI) RenewCert(_ context.Context, _ int, csrPEM string) (*api.CertResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renews++
	req, err := certutil.ParseCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	if f.failIssue != "" {
		f.cert.Status, f.cert.FailureReason = api.StatusFailed, f.failIssue
		return &api.CertResponse{ID: 1043, Status: api.StatusRenewing}, nil
	}
	n, pub := certutil.CSRNames(req), req.PublicKey
	if f.issueNames != nil {
		n = f.issueNames
	}
	if f.issueKey != nil {
		pub = f.issueKey
	}
	f.issue(pub, n)
	return &api.CertResponse{ID: 1043, Status: api.StatusRenewing}, nil
}

// serverRenew is KrakenKey renewing on its own with the stored CSR, so the
// new certificate has the same key as the current one.
func (f *fakeAPI) serverRenew() {
	f.mu.Lock()
	defer f.mu.Unlock()
	leaf, _ := certutil.ParseLeaf(f.cert.CrtPem)
	f.issue(leaf.PublicKey, certutil.CertNames(leaf))
}

func (f *fakeAPI) WaitForIssuance(_ context.Context, _ int, previous string) (*api.Cert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hang {
		return nil, errors.New("waiting for certificate 1043: timed out")
	}
	if f.cert.Status == api.StatusFailed {
		return nil, &api.IssuanceFailedError{Reason: f.cert.FailureReason}
	}
	if f.cert.CrtPem == previous {
		return nil, errors.New("not reissued")
	}
	c := f.cert
	return &c, nil
}

func (f *fakeAPI) GetCertChain(context.Context, int) (*api.Chain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &api.Chain{FullChainPem: f.cert.CrtPem + f.cert.ChainPem}, nil
}

func (f *fakeAPI) serial() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	leaf, _ := certutil.ParseLeaf(f.cert.CrtPem)
	return certutil.SerialHex(leaf.SerialNumber)
}

// fakeTarget serves whatever was activated last, unless broken, in which
// case the endpoint keeps serving what it served before.
type fakeTarget struct {
	plugin.UnimplementedTarget
	mu           sync.Mutex
	caps         plugin.TargetCapabilities
	live         string // serial the endpoint serves
	installed    string // serial last activated
	staged       map[string]string
	prev         map[string]string
	stages       int
	discards     []string
	rollbacks    int
	broken       bool
	failActivate error
	noCurrent    bool
}

func newFakeTarget() *fakeTarget {
	return &fakeTarget{
		caps:   plugin.TargetCapabilities{Accepts: []plugin.KeyFormat{plugin.KeyFormatPEM}, NeedsExportableKey: true, SupportsRollback: true},
		staged: map[string]string{}, prev: map[string]string{},
	}
}

func (f *fakeTarget) Describe(context.Context) (plugin.TargetCapabilities, error) { return f.caps, nil }
func (f *fakeTarget) Validate(context.Context, plugin.TargetValidateRequest) ([]string, error) {
	return nil, nil
}

func (f *fakeTarget) Current(context.Context, plugin.CurrentRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.noCurrent {
		return "", fmt.Errorf("%w: Current", plugin.ErrUnsupported)
	}
	return f.installed, nil
}

func (f *fakeTarget) Stage(_ context.Context, req plugin.StageRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if req.Key.Format != plugin.KeyFormatPEM || len(req.Key.Data) == 0 {
		return "", errors.New("no key")
	}
	f.stages++
	ref := fmt.Sprintf("s%d", f.stages)
	f.staged[ref] = req.Serial
	return ref, nil
}

func (f *fakeTarget) Activate(_ context.Context, req plugin.ActivateRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failActivate != nil {
		return "", f.failActivate
	}
	prevRef := "p" + req.StagedRef
	f.prev[prevRef] = f.installed
	f.installed = f.staged[req.StagedRef]
	delete(f.staged, req.StagedRef)
	if !f.broken {
		f.live = f.installed
	}
	return prevRef, nil
}

func (f *fakeTarget) Rollback(_ context.Context, req plugin.RollbackRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	old, ok := f.prev[req.PreviousRef]
	if !ok {
		return fmt.Errorf("%w: ref %s", plugin.ErrNotFound, req.PreviousRef)
	}
	f.rollbacks++
	f.installed = old
	f.live = old
	return nil
}

func (f *fakeTarget) Discard(_ context.Context, req plugin.DiscardRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discards = append(f.discards, req.StagedRef)
	delete(f.staged, req.StagedRef)
	return nil
}

// fakeVerifier checks the fake target registered for the dial address.
type fakeVerifier struct {
	targets map[string]*fakeTarget
	reqs    []verify.Request
	hook    func(verify.Request) error
}

func (v *fakeVerifier) Verify(_ context.Context, req verify.Request) error {
	v.reqs = append(v.reqs, req)
	if v.hook != nil {
		if err := v.hook(req); err != nil {
			return err
		}
	}
	tg := v.targets[req.Address]
	tg.mu.Lock()
	defer tg.mu.Unlock()
	want := certutil.SerialHex(req.Expected.SerialNumber)
	if tg.live != want {
		return &verify.MismatchError{Address: req.Address, Host: req.Host, WantSerial: want, ServedSerial: tg.live}
	}
	return nil
}

type memAudit struct {
	mu      sync.Mutex
	entries []audit.Entry
	failOn  string
}

func (m *memAudit) Write(e audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failOn != "" && e.Step == m.failOn {
		return errors.New("disk full")
	}
	m.entries = append(m.entries, e)
	return nil
}

func (m *memAudit) steps(target string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, e := range m.entries {
		if e.Target == target {
			out = append(out, e.Step+":"+e.Result)
		}
	}
	return out
}

func (m *memAudit) has(step, result, contains string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.Step == step && e.Result == result && strings.Contains(e.Detail+" "+e.Error, contains) {
			return true
		}
	}
	return false
}

type env struct {
	api      *fakeAPI
	ks       *testplugin.KeyStore
	targets  map[string]*fakeTarget
	verifier *fakeVerifier
	audit    *memAudit
	engine   *Engine
	job      Job
	then     []string
	now      time.Time
}

func setup(t *testing.T, labels ...string) *env {
	t.Helper()
	e := &env{
		api:     newFakeAPI(t),
		ks:      testplugin.NewKeyStore(),
		targets: map[string]*fakeTarget{},
		audit:   &memAudit{},
		now:     time.Now(),
	}
	e.verifier = &fakeVerifier{targets: map[string]*fakeTarget{}}
	state, err := OpenStateStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e.engine = &Engine{
		API: e.api, Verifier: e.verifier, Audit: e.audit, State: state,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return e.now },
		RunThen: func(_ context.Context, argv, env []string, _ time.Duration) error {
			action := ""
			for _, kv := range env {
				if v, ok := strings.CutPrefix(kv, "KK_ACTION="); ok {
					action = v
				}
			}
			e.then = append(e.then, strings.Join(argv, " ")+" "+action)
			if argv[0] == "fail" || (argv[0] == "fail-deploy" && action == "deploy") {
				return errors.New("reload failed")
			}
			return nil
		},
	}
	e.job = Job{
		Cert: config.Certificate{
			ID: 1043, Names: names,
			KeyStore: config.KeyStore{Plugin: "mem", KeyType: plugin.KeyTypeECDSAP256},
		},
		KeyStoreName: "mem", KeyStore: e.ks, KeyStoreConfig: json.RawMessage(`{}`),
	}
	for _, l := range labels {
		tg := newFakeTarget()
		e.targets[l] = tg
		addr := l + ".internal:443"
		e.verifier.targets[addr] = tg
		tc := config.Target{Label: l, Plugin: "fake", Verify: &config.Verify{Host: "api.example.com", Address: addr}}
		e.job.Cert.Targets = append(e.job.Cert.Targets, tc)
		e.job.Targets = append(e.job.Targets, TargetJob{
			Config: tc, Plugin: tg, Settings: json.RawMessage(`{}`), Caps: tg.caps, Format: plugin.KeyFormatPEM, Window: time.Second,
		})
	}
	return e
}

func (e *env) process(t *testing.T, force bool) error {
	t.Helper()
	// Capabilities may have been changed by the test after setup.
	for i := range e.job.Targets {
		e.job.Targets[i].Caps = e.targets[e.job.Targets[i].Config.Label].caps
	}
	return e.engine.Process(context.Background(), e.job, Options{RunID: "run", Force: force})
}

func (e *env) state(t *testing.T) *State {
	t.Helper()
	st, err := e.engine.State.Load(1043)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestFirstRunRenewsAndDeploys(t *testing.T) {
	e := setup(t, "a", "b")
	if err := e.process(t, false); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if e.api.renews != 1 {
		t.Fatalf("renews = %d, want 1 (first run must get a connector-held key)", e.api.renews)
	}
	serial := e.api.serial()
	for l, tg := range e.targets {
		if tg.live != serial {
			t.Errorf("target %s serves %q, want %s", l, tg.live, serial)
		}
		want := []string{"stage:ok", "activate:ok", "verify:ok"}
		if got := e.audit.steps(l); !slices.Equal(got, want) {
			t.Errorf("target %s audit = %v, want %v", l, got, want)
		}
	}
	for _, en := range e.audit.entries {
		if en.Step == audit.StepActivate && (en.PreviousRef == "" || en.NewSerial != serial) {
			t.Errorf("activate entry without previous ref or serial: %+v", en)
		}
		if en.Step == audit.StepCreateCSR && !strings.Contains(en.Detail, "first run") {
			t.Errorf("create_csr detail = %q", en.Detail)
		}
	}
	st := e.state(t)
	if st.Serial != serial || st.Targets["a"].Serial != serial || st.Targets["b"].Serial != serial || st.KeyRef == "" ||
		st.KeySPKI == "" || st.Pending != nil || st.Targets["a"].Phase != "" || st.Targets["a"].NotAfter.IsZero() {
		t.Errorf("state = %+v", st)
	}
	if !strings.Contains(st.FullChainPEM, strings.TrimSpace(e.api.ca.IntermediatePEM)) {
		t.Error("full chain missing the intermediate")
	}
	if e.ks.Completed[st.KeyRef] == "" {
		t.Error("key store Complete was not called")
	}

	// A second pass finds nothing to do.
	stages := e.targets["a"].stages
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	if e.api.renews != 1 || e.targets["a"].stages != stages {
		t.Errorf("second pass renewed or redeployed: renews=%d stages=%d", e.api.renews, e.targets["a"].stages)
	}
}

func TestForceRenewsAndReleasesOldKey(t *testing.T) {
	e := setup(t, "a")
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	firstKey := e.state(t).KeyRef

	if err := e.process(t, true); err != nil {
		t.Fatal(err)
	}
	if e.api.renews != 2 {
		t.Fatalf("renews = %d, want 2", e.api.renews)
	}
	if !e.audit.has(audit.StepCreateCSR, audit.ResultOK, "forced") {
		t.Error("forced renewal not recorded")
	}
	st := e.state(t)
	if st.KeyRef == firstKey || len(st.RetiredKeys) != 0 {
		t.Errorf("state = %+v", st)
	}
	if !slices.Contains(e.ks.Released, firstKey) {
		t.Errorf("old key %s not released after every target was verified (released %v)", firstKey, e.ks.Released)
	}
}

func TestDueCheck(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	later := time.Now().Add(60 * 24 * time.Hour)
	cases := []struct {
		name       string
		renewAfter *time.Time
		advance    time.Duration
		want       int
	}{
		{"renewAfter passed", &past, 0, 2},
		{"renewAfter in the future", &later, 0, 1},
		// Test certificates live 90 days; without renewAfter the connector
		// renews two thirds in, after about 60 days.
		{"no renewAfter, early in the lifetime", nil, 30 * 24 * time.Hour, 1},
		{"no renewAfter, two thirds through the lifetime", nil, 61 * 24 * time.Hour, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := setup(t, "a")
			if err := e.process(t, false); err != nil {
				t.Fatal(err)
			}
			e.api.cert.RenewAfter = c.renewAfter
			e.now = e.now.Add(c.advance)
			if err := e.process(t, false); err != nil {
				t.Fatal(err)
			}
			if e.api.renews != c.want {
				t.Errorf("renews = %d, want %d", e.api.renews, c.want)
			}
		})
	}
}

func TestBusyCertificateIsSkipped(t *testing.T) {
	e := setup(t, "a")
	e.api.cert.Status = api.StatusRenewing
	if err := e.process(t, true); err != nil {
		t.Fatal(err)
	}
	if e.api.renews != 0 || e.targets["a"].stages != 0 {
		t.Error("busy certificate was renewed or deployed")
	}
}

func TestNamesMismatchIsRejected(t *testing.T) {
	e := setup(t, "a")
	e.api.issueNames = []string{"api.example.com", "www.example.com", "evil.example.com"}
	err := e.process(t, false)
	var rej *RejectedError
	if !errors.As(err, &rej) || !strings.Contains(err.Error(), "evil.example.com") {
		t.Fatalf("err = %v, want a names rejection", err)
	}
	assertNothingDeployed(t, e)
}

func TestKeyMismatchIsRejected(t *testing.T) {
	e := setup(t, "a")
	e.api.issueKey = testca.Key(t).Public()
	err := e.process(t, false)
	var rej *RejectedError
	if !errors.As(err, &rej) || !strings.Contains(err.Error(), "public key") {
		t.Fatalf("err = %v, want a key rejection", err)
	}
	assertNothingDeployed(t, e)
}

func TestIssuanceFailureReleasesKey(t *testing.T) {
	e := setup(t, "a")
	e.api.failIssue = "CNAME missing"
	err := e.process(t, false)
	var f *api.IssuanceFailedError
	if !errors.As(err, &f) {
		t.Fatalf("err = %v", err)
	}
	assertNothingDeployed(t, e)
}

func assertNothingDeployed(t *testing.T, e *env) {
	t.Helper()
	for l, tg := range e.targets {
		if tg.stages != 0 {
			t.Errorf("target %s was staged", l)
		}
	}
	if len(e.ks.Released) != 1 {
		t.Errorf("released = %v, want the unused new key", e.ks.Released)
	}
	if st := e.state(t); st != nil && (st.Serial != "" || st.Pending != nil) {
		t.Errorf("state records a rejected certificate: %+v", st)
	}
}

func TestInterruptedRenewalIsAdopted(t *testing.T) {
	e := setup(t, "a")
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	oldKey := e.state(t).KeyRef

	// KrakenKey issues, but the connector stops waiting first.
	e.api.hang = true
	if err := e.process(t, true); err == nil {
		t.Fatal("expected the wait to fail")
	}
	st := e.state(t)
	if st.Pending == nil {
		t.Fatal("pending key not recorded")
	}
	pendingKey := st.Pending.KeyRef
	if slices.Contains(e.ks.Released, pendingKey) {
		t.Fatal("pending key released although KrakenKey may still issue for it")
	}

	// The next pass adopts the certificate instead of renewing again.
	e.api.hang = false
	if err := e.process(t, false); err != nil {
		t.Fatalf("adopting pass: %v", err)
	}
	if e.api.renews != 2 {
		t.Errorf("renews = %d, want 2 (no third renewal)", e.api.renews)
	}
	st = e.state(t)
	if st.KeyRef != pendingKey || st.Pending != nil || st.Serial != e.api.serial() {
		t.Errorf("state = %+v", st)
	}
	if e.targets["a"].live != e.api.serial() {
		t.Error("adopted certificate not deployed")
	}
	if !slices.Contains(e.ks.Released, oldKey) {
		t.Error("old key not released after the adopted certificate was deployed")
	}
	if !e.audit.has(audit.StepIssued, audit.ResultOK, "earlier pass completed") {
		t.Error("adoption not audited")
	}
}

func TestServerSideRenewalIsAdopted(t *testing.T) {
	e := setup(t, "a")
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	key := e.state(t).KeyRef
	e.api.serverRenew()
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	if e.api.renews != 1 {
		t.Errorf("renews = %d; a renewal KrakenKey made with the connector's key must not trigger another", e.api.renews)
	}
	st := e.state(t)
	if st.KeyRef != key || st.Serial != e.api.serial() || e.targets["a"].live != st.Serial {
		t.Errorf("state = %+v, live %s", st, e.targets["a"].live)
	}
	if len(e.ks.Released) != 0 {
		t.Errorf("released %v; the key is still in use", e.ks.Released)
	}
}

func TestOrphanKeysAreReleased(t *testing.T) {
	e := setup(t, "a")
	orphan, err := e.ks.CreateCSR(context.Background(), plugin.CSRRequest{CertificateID: "1043", Names: names, KeyType: plugin.KeyTypeECDSAP256})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(e.ks.Released, orphan.KeyRef) {
		t.Errorf("orphaned key %s not released (released %v)", orphan.KeyRef, e.ks.Released)
	}
	if slices.Contains(e.ks.Released, e.state(t).KeyRef) {
		t.Error("current key released")
	}
}

func TestVerifyFailureRollsBackOnlyThatTarget(t *testing.T) {
	e := setup(t, "a", "b")
	for i := range e.job.Targets {
		e.job.Targets[i].Config.Then = &config.Then{Exec: []string{"reload", e.job.Targets[i].Config.Label}}
	}
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	oldSerial := e.api.serial()
	oldKey := e.state(t).KeyRef
	e.then = nil

	// b keeps serving the old certificate after activation.
	e.targets["b"].broken = true
	err := e.process(t, true)
	if err == nil || !strings.Contains(err.Error(), "target b") || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "target a") {
		t.Errorf("target a reported as failed: %v", err)
	}
	newSerial := e.api.serial()
	if e.targets["a"].live != newSerial || e.targets["a"].rollbacks != 0 {
		t.Errorf("target a: live %s rollbacks %d", e.targets["a"].live, e.targets["a"].rollbacks)
	}
	if e.targets["b"].rollbacks != 1 || e.targets["b"].installed != oldSerial {
		t.Errorf("target b: installed %s rollbacks %d, want rolled back to %s", e.targets["b"].installed, e.targets["b"].rollbacks, oldSerial)
	}
	wantThen := []string{"reload a deploy", "reload b deploy", "reload b rollback"}
	if !slices.Equal(e.then, wantThen) {
		t.Errorf("then runs = %v, want %v", e.then, wantThen)
	}
	if got, want := e.audit.steps("b")[4:], []string{"stage:ok", "activate:ok", "then:ok", "verify:failed", "rollback:ok"}; !slices.Equal(got, want) {
		t.Errorf("b audit = %v, want %v", got, want)
	}

	st := e.state(t)
	if st.Targets["a"].Serial != newSerial || st.Targets["b"].Serial != oldSerial || st.Targets["b"].LastError == "" ||
		st.Targets["b"].Failures != 1 || st.Targets["b"].Phase != "" {
		t.Errorf("state targets = %+v", st.Targets)
	}
	if !slices.Contains(st.RetiredKeys, oldKey) || slices.Contains(e.ks.Released, oldKey) {
		t.Errorf("old key must be kept while b still uses it: retired %v released %v", st.RetiredKeys, e.ks.Released)
	}

	// Before the retry delay, b is left alone.
	e.targets["b"].broken = false
	stagesB := e.targets["b"].stages
	if err := e.process(t, false); err != nil {
		t.Fatalf("pass inside the retry delay: %v", err)
	}
	if e.targets["b"].stages != stagesB {
		t.Error("b retried before its retry delay")
	}

	// After it, the next pass deploys to b only and releases the old key,
	// without renewing.
	e.now = e.now.Add(DefaultRetryBase + time.Minute)
	stagesA := e.targets["a"].stages
	if err := e.process(t, false); err != nil {
		t.Fatalf("retry pass: %v", err)
	}
	if e.api.renews != 2 || e.targets["a"].stages != stagesA {
		t.Errorf("retry pass renewed or touched a: renews %d", e.api.renews)
	}
	if e.targets["b"].live != newSerial {
		t.Errorf("b serves %s, want %s", e.targets["b"].live, newSerial)
	}
	if ts := e.state(t).Targets["b"]; ts.Failures != 0 || !ts.NextAttempt.IsZero() {
		t.Errorf("failure count not reset: %+v", ts)
	}
	if !slices.Contains(e.ks.Released, oldKey) || len(e.state(t).RetiredKeys) != 0 {
		t.Errorf("old key not released: %v", e.ks.Released)
	}
}

func TestRetryDelayGrows(t *testing.T) {
	e := setup(t, "a")
	e.targets["a"].broken = true
	var delays []time.Duration
	for range 3 {
		_ = e.process(t, false)
		ts := e.state(t).Targets["a"]
		delays = append(delays, ts.NextAttempt.Sub(e.now))
		e.now = ts.NextAttempt.Add(time.Second)
	}
	if delays[0] != DefaultRetryBase || delays[1] != 2*DefaultRetryBase || delays[2] != 4*DefaultRetryBase {
		t.Errorf("delays = %v", delays)
	}
}

func TestNoRollbackToExpiringCertificate(t *testing.T) {
	e := setup(t, "a")
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	// The deployed certificate is about to expire.
	st := e.state(t)
	ts := st.Targets["a"]
	ts.NotAfter = e.now.Add(2 * time.Hour)
	st.Targets["a"] = ts
	if err := e.engine.State.Save(st); err != nil {
		t.Fatal(err)
	}

	e.targets["a"].broken = true
	err := e.process(t, true)
	if err == nil || !strings.Contains(err.Error(), "not rolled back") || !strings.Contains(err.Error(), "expires") {
		t.Fatalf("err = %v", err)
	}
	if e.targets["a"].rollbacks != 0 || e.targets["a"].installed != e.api.serial() {
		t.Error("rolled back to a certificate that expires within a day")
	}
	if !e.audit.has(audit.StepRollback, audit.ResultSkipped, "expires") {
		t.Error("skipped rollback not audited")
	}
}

func TestAsyncTargetIsNotRolledBack(t *testing.T) {
	e := setup(t, "a")
	e.targets["a"].caps.PropagatesAsync = true
	e.targets["a"].broken = true
	err := e.process(t, false)
	if err == nil || !strings.Contains(err.Error(), "not rolled back") {
		t.Fatalf("err = %v", err)
	}
	if e.targets["a"].rollbacks != 0 {
		t.Error("async target was rolled back")
	}
	if got := e.audit.steps("a"); !slices.Equal(got, []string{"stage:ok", "activate:ok", "verify:reported"}) {
		t.Errorf("audit = %v", got)
	}
	if st := e.state(t); st.Targets["a"].Serial != st.Serial {
		t.Errorf("async target should be recorded as deployed: %+v", st.Targets["a"])
	}
}

func TestActivateFailureDiscardsAndLeavesOtherTargets(t *testing.T) {
	e := setup(t, "a", "b")
	e.targets["a"].failActivate = errors.New("permission denied")
	err := e.process(t, false)
	if err == nil || !strings.Contains(err.Error(), "target a: permission denied") {
		t.Fatalf("err = %v", err)
	}
	if e.targets["a"].rollbacks != 0 {
		t.Error("rollback called without a previous ref")
	}
	if len(e.targets["a"].discards) != 1 || len(e.targets["a"].staged) != 0 {
		t.Errorf("staged material not discarded: %v", e.targets["a"].discards)
	}
	if e.targets["b"].live != e.api.serial() {
		t.Error("target b not deployed")
	}
}

func TestExportFailureIsAudited(t *testing.T) {
	e := setup(t, "a")
	e.job.Targets[0].Format = plugin.KeyFormatPFX // the test key store only exports PEM
	if err := e.process(t, false); err == nil {
		t.Fatal("expected an export error")
	}
	if got := e.audit.steps("a"); !slices.Equal(got, []string{"export_key:failed"}) {
		t.Errorf("audit = %v", got)
	}
}

func TestThenFailureRollsBack(t *testing.T) {
	e := setup(t, "a")
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	e.then = nil
	e.job.Targets[0].Config.Then = &config.Then{Exec: []string{"fail-deploy"}}
	err := e.process(t, true)
	if err == nil || !strings.Contains(err.Error(), "reload failed (rolled back)") {
		t.Fatalf("err = %v", err)
	}
	if e.targets["a"].rollbacks != 1 {
		t.Error("not rolled back")
	}
	if !slices.Equal(e.then, []string{"fail-deploy deploy", "fail-deploy rollback"}) {
		t.Errorf("then runs = %v", e.then)
	}

	// When the command also fails after the rollback, the error says so.
	e2 := setup(t, "a")
	if err := e2.process(t, false); err != nil {
		t.Fatal(err)
	}
	e2.job.Targets[0].Config.Then = &config.Then{Exec: []string{"fail"}}
	err = e2.process(t, true)
	if err == nil || !strings.Contains(err.Error(), "files rolled back, but then.exec failed afterwards") {
		t.Fatalf("err = %v", err)
	}
}

func TestAuditFailureOnActivateRollsBack(t *testing.T) {
	e := setup(t, "a")
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	e.audit.failOn = audit.StepActivate
	err := e.process(t, true)
	if err == nil || !strings.Contains(err.Error(), "could not record the activation") {
		t.Fatalf("err = %v", err)
	}
	if e.targets["a"].rollbacks != 1 {
		t.Error("activation left live without an audit record")
	}
}

func TestNoRollbackSupport(t *testing.T) {
	e := setup(t, "a")
	e.targets["a"].caps.SupportsRollback = false
	e.targets["a"].broken = true
	err := e.process(t, false)
	if err == nil || !strings.Contains(err.Error(), "target does not support rollback") {
		t.Fatalf("err = %v", err)
	}
	if e.targets["a"].rollbacks != 0 {
		t.Error("rollback called on a target without rollback support")
	}
	// The target holds the new certificate, so it is not activated again.
	stages := e.targets["a"].stages
	e.now = e.now.Add(48 * time.Hour)
	_ = e.process(t, false)
	if e.targets["a"].stages != stages {
		t.Error("certificate activated again on top of itself")
	}
}

func TestVerifyRequestUsesConfig(t *testing.T) {
	e := setup(t, "a")
	e.job.Targets[0].Config.Verify.SkipChainValidation = true
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	r := e.verifier.reqs[0]
	if r.Host != "api.example.com" || r.Address != "a.internal:443" || !r.SkipChainValidation || r.Window != time.Second {
		t.Errorf("verify request = %+v", r)
	}
	if certutil.SerialHex(r.Expected.SerialNumber) != e.api.serial() {
		t.Error("verify expected the wrong certificate")
	}
}

// crashAtVerify makes the next verification "crash" the connector: it
// snapshots the state file at that moment, and restore() puts the state
// file and the target back as they were, as if the process had died there.
type crashAtVerify struct {
	e        *env
	t        *testing.T
	snapshot []byte
	live     string
	inst     string
	prev     map[string]string
}

func (c *crashAtVerify) arm() {
	c.e.verifier.hook = func(verify.Request) error {
		c.e.verifier.hook = nil
		data, err := os.ReadFile(c.e.engine.State.path(1043))
		if err != nil {
			c.t.Fatal(err)
		}
		c.snapshot = data
		tg := c.e.targets["a"]
		c.live, c.inst, c.prev = tg.live, tg.installed, maps(tg.prev)
		return errors.New("crash")
	}
}

func (c *crashAtVerify) restore() {
	if err := os.WriteFile(c.e.engine.State.path(1043), c.snapshot, 0o600); err != nil {
		c.t.Fatal(err)
	}
	tg := c.e.targets["a"]
	tg.live, tg.installed, tg.prev, tg.rollbacks = c.live, c.inst, c.prev, 0
}

func maps(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestCrashAfterActivateRollsBackToRecordedPrevious(t *testing.T) {
	e := setup(t, "a")
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	oldSerial := e.api.serial()

	// Renew; the connector dies while verifying, with the new certificate
	// active on a target that does not actually serve it.
	e.targets["a"].broken = true
	crash := &crashAtVerify{e: e, t: t}
	crash.arm()
	_ = e.process(t, true)
	crash.restore()
	newSerial := e.api.serial()
	if st := e.state(t); st.Targets["a"].Phase != PhaseActivated || st.Targets["a"].PreviousRef == "" {
		t.Fatalf("snapshot state = %+v", st.Targets["a"])
	}
	if e.targets["a"].installed != newSerial {
		t.Fatal("test setup: new certificate should be installed")
	}

	// The next run finishes the deployment: verification fails, and the
	// rollback must restore the old certificate recorded before the
	// crash, not re-activate the new one.
	stages := e.targets["a"].stages
	err := e.process(t, false)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("recovery err = %v", err)
	}
	if e.targets["a"].installed != oldSerial || e.targets["a"].rollbacks != 1 {
		t.Errorf("installed %s after recovery, want old %s", e.targets["a"].installed, oldSerial)
	}
	if e.targets["a"].stages != stages {
		t.Error("recovery staged again instead of resolving the interrupted deployment")
	}
	if !e.audit.has(audit.StepRecover, audit.ResultOK, "activated") {
		t.Error("recovery not audited")
	}
}

func TestCrashAfterActivateIsFinishedWhenHealthy(t *testing.T) {
	e := setup(t, "a")
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	crash := &crashAtVerify{e: e, t: t}
	crash.arm()
	_ = e.process(t, true)
	crash.restore()

	if err := e.process(t, false); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	st := e.state(t)
	if st.Targets["a"].Serial != e.api.serial() || st.Targets["a"].Phase != "" || e.targets["a"].rollbacks != 0 {
		t.Errorf("state after recovery = %+v", st.Targets["a"])
	}
}

func TestCrashDuringActivate(t *testing.T) {
	for _, activated := range []bool{true, false} {
		t.Run(fmt.Sprintf("activated=%v", activated), func(t *testing.T) {
			e := setup(t, "a")
			if err := e.process(t, false); err != nil {
				t.Fatal(err)
			}
			oldSerial := e.api.serial()
			// Renew and deploy normally, then rewrite the state as if the
			// process had died inside Activate.
			if err := e.process(t, true); err != nil {
				t.Fatal(err)
			}
			newSerial := e.api.serial()
			st := e.state(t)
			ts := st.Targets["a"]
			ts.Serial, ts.Phase, ts.DeployingSerial, ts.StagedRef, ts.PreviousRef = oldSerial, PhaseActivating, newSerial, "s99", ""
			st.Targets["a"] = ts
			_ = e.engine.State.Save(st)
			if !activated {
				e.targets["a"].installed, e.targets["a"].live = oldSerial, oldSerial
			}
			stages := e.targets["a"].stages

			if err := e.process(t, false); err != nil {
				t.Fatalf("recovery: %v", err)
			}
			if !slices.Contains(e.targets["a"].discards, "s99") {
				t.Error("staged ref from the interrupted run not discarded")
			}
			if got := e.state(t).Targets["a"]; got.Serial != newSerial || got.Phase != "" {
				t.Errorf("state after recovery = %+v", got)
			}
			wantStages := stages
			if !activated {
				wantStages++ // not activated: deployed normally
			}
			if e.targets["a"].stages != wantStages {
				t.Errorf("stages = %d, want %d", e.targets["a"].stages, wantStages)
			}
		})
	}
}
