package deploy

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	leaf, leafPEM := f.ca.Issue(f.t, pub, n, 0)
	renewAfter := time.Now().Add(60 * 24 * time.Hour)
	f.cert.CrtPem, f.cert.Status, f.cert.ExpiresAt, f.cert.RenewAfter = leafPEM, api.StatusIssued, &leaf.NotAfter, &renewAfter
	return &api.CertResponse{ID: 1043, Status: api.StatusRenewing}, nil
}

func (f *fakeAPI) WaitForIssuance(_ context.Context, _ int, previous string) (*api.Cert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	leaf, _ := certutil.ParseLeaf(f.cert.CrtPem)
	return certutil.SerialHex(leaf.SerialNumber)
}

// fakeTarget serves whatever was activated last, unless broken, in which
// case it keeps serving what it had.
type fakeTarget struct {
	mu           sync.Mutex
	caps         plugin.TargetCapabilities
	live         string // serial the endpoint serves
	installed    string // serial last activated
	staged       map[string]string
	prev         map[string]string
	stages       int
	rollbacks    int
	broken       bool
	failActivate error
}

func newFakeTarget() *fakeTarget {
	return &fakeTarget{
		caps:   plugin.TargetCapabilities{Accepts: []plugin.KeyFormat{plugin.KeyFormatPEM}, NeedsExportableKey: true, SupportsRollback: true},
		staged: map[string]string{}, prev: map[string]string{},
	}
}

func (f *fakeTarget) Describe(context.Context) (plugin.TargetCapabilities, error) { return f.caps, nil }
func (f *fakeTarget) Validate(context.Context, json.RawMessage) ([]string, error) { return nil, nil }
func (f *fakeTarget) Current(context.Context, json.RawMessage) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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

func (f *fakeTarget) Activate(_ context.Context, _ json.RawMessage, ref string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failActivate != nil {
		return "", f.failActivate
	}
	prevRef := "p" + ref
	f.prev[prevRef] = f.installed
	f.installed = f.staged[ref]
	if !f.broken {
		f.live = f.installed
	}
	return prevRef, nil
}

func (f *fakeTarget) Rollback(_ context.Context, _ json.RawMessage, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	old, ok := f.prev[ref]
	if !ok {
		return fmt.Errorf("unknown ref %s", ref)
	}
	f.rollbacks++
	f.installed = old
	f.live = old
	return nil
}

// fakeVerifier checks the fake target registered for the dial address.
type fakeVerifier struct {
	targets map[string]*fakeTarget
	reqs    []verify.Request
}

func (v *fakeVerifier) Verify(_ context.Context, req verify.Request) error {
	v.reqs = append(v.reqs, req)
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

type env struct {
	api      *fakeAPI
	ks       *testplugin.KeyStore
	targets  map[string]*fakeTarget
	verifier *fakeVerifier
	audit    *memAudit
	engine   *Engine
	job      Job
	then     []string
}

func setup(t *testing.T, labels ...string) *env {
	t.Helper()
	e := &env{
		api:     newFakeAPI(t),
		ks:      testplugin.NewKeyStore(),
		targets: map[string]*fakeTarget{},
		audit:   &memAudit{},
	}
	e.verifier = &fakeVerifier{targets: map[string]*fakeTarget{}}
	state, err := OpenStateStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e.engine = &Engine{
		API: e.api, Verifier: e.verifier, Audit: e.audit, State: state,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
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
	if st.Serial != serial || st.Targets["a"].Serial != serial || st.Targets["b"].Serial != serial || st.KeyRef == "" {
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
	var detail string
	for _, en := range e.audit.entries {
		if en.Step == audit.StepCreateCSR {
			detail = en.Detail
		}
	}
	if !strings.Contains(detail, "forced") {
		t.Errorf("forced renewal not recorded: %q", detail)
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
	soon := time.Now().Add(20 * 24 * time.Hour)
	later := time.Now().Add(60 * 24 * time.Hour)
	cases := []struct {
		name       string
		renewAfter *time.Time
		expiresAt  *time.Time
		want       int
	}{
		{"renewAfter passed", &past, &later, 2},
		{"renewAfter in the future", &later, &soon, 1},
		{"no renewAfter, expiry within 30 days", nil, &soon, 2},
		{"no renewAfter, expiry beyond 30 days", nil, &later, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := setup(t, "a")
			if err := e.process(t, false); err != nil {
				t.Fatal(err)
			}
			e.api.cert.RenewAfter, e.api.cert.ExpiresAt = c.renewAfter, c.expiresAt
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
	if st := e.state(t); st != nil {
		t.Errorf("state saved for a rejected certificate: %+v", st)
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
	if st.Targets["a"].Serial != newSerial || st.Targets["b"].Serial != oldSerial || st.Targets["b"].LastError == "" {
		t.Errorf("state targets = %+v", st.Targets)
	}
	if !slices.Contains(st.RetiredKeys, oldKey) || slices.Contains(e.ks.Released, oldKey) {
		t.Errorf("old key must be kept while b still uses it: retired %v released %v", st.RetiredKeys, e.ks.Released)
	}

	// Once b works again, the next pass deploys to b only and releases the
	// old key, without renewing.
	e.targets["b"].broken = false
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
	if !slices.Contains(e.ks.Released, oldKey) || len(e.state(t).RetiredKeys) != 0 {
		t.Errorf("old key not released: %v", e.ks.Released)
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

func TestActivateFailureLeavesOtherTargets(t *testing.T) {
	e := setup(t, "a", "b")
	e.targets["a"].failActivate = errors.New("permission denied")
	err := e.process(t, false)
	if err == nil || !strings.Contains(err.Error(), "target a: permission denied") {
		t.Fatalf("err = %v", err)
	}
	if e.targets["a"].rollbacks != 0 {
		t.Error("rollback called without a previous ref")
	}
	if e.targets["b"].live != e.api.serial() {
		t.Error("target b not deployed")
	}
}

func TestThenFailureRollsBack(t *testing.T) {
	e := setup(t, "a")
	e.job.Targets[0].Config.Then = &config.Then{Exec: []string{"fail-deploy"}}
	err := e.process(t, false)
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
	e2.job.Targets[0].Config.Then = &config.Then{Exec: []string{"fail"}}
	err = e2.process(t, false)
	if err == nil || !strings.Contains(err.Error(), "files rolled back, but then.exec failed afterwards") {
		t.Fatalf("err = %v", err)
	}
}

func TestAuditFailureOnActivateRollsBack(t *testing.T) {
	e := setup(t, "a")
	e.audit.failOn = audit.StepActivate
	err := e.process(t, false)
	if err == nil || !strings.Contains(err.Error(), "audit log") {
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
	if err == nil || !strings.Contains(err.Error(), "cannot roll back") {
		t.Fatalf("err = %v", err)
	}
	if e.targets["a"].rollbacks != 0 {
		t.Error("rollback called on a target without rollback support")
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
