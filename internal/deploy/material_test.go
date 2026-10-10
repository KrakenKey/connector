package deploy

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/krakenkey/connector/internal/audit"
	"github.com/krakenkey/connector/internal/certutil"
	"github.com/krakenkey/connector/internal/verify"
	"github.com/krakenkey/connector/pkg/plugin"
)

// materialSetup returns an env whose target "a" needs the previous
// certificate and key to roll back.
func materialSetup(t *testing.T, labels ...string) *env {
	t.Helper()
	e := setup(t, labels...)
	e.targets["a"].caps.RollbackNeedsMaterial = true
	return e
}

// checkMaterial checks that req carries certificate serial and the key that
// belongs to it.
func checkMaterial(t *testing.T, req plugin.RollbackRequest, serial string) {
	t.Helper()
	if req.PreviousSerial != serial {
		t.Fatalf("previous serial = %q, want %s", req.PreviousSerial, serial)
	}
	leaf, err := certutil.ParseLeaf(req.PreviousCertPEM)
	if err != nil || certutil.SerialHex(leaf.SerialNumber) != serial {
		t.Fatalf("previous cert does not parse to serial %s: %v", serial, err)
	}
	if req.PreviousChainPEM == "" || !strings.HasPrefix(req.PreviousFullChainPEM, strings.TrimSpace(req.PreviousCertPEM)) {
		t.Error("previous chain or full chain missing")
	}
	if req.PreviousKey.Format != plugin.KeyFormatPEM {
		t.Fatalf("previous key format = %q", req.PreviousKey.Format)
	}
	block, _ := pem.Decode(req.PreviousKey.Data)
	if block == nil {
		t.Fatal("previous key is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(key.(crypto.Signer).Public())
	if string(pub) != string(leaf.RawSubjectPublicKeyInfo) {
		t.Error("previous key does not belong to the previous certificate")
	}
}

func TestRollbackHandsBackPreviousMaterial(t *testing.T) {
	e := materialSetup(t, "a", "b")
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	oldSerial := e.api.serial()
	oldKey := e.state(t).KeyRef

	e.targets["a"].broken = true
	e.targets["b"].broken = true
	err := e.process(t, true)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("err = %v", err)
	}
	a := e.targets["a"]
	if a.rollbacks != 1 || a.installed != oldSerial || len(a.rollbackReqs) != 1 {
		t.Fatalf("target a: rollbacks %d installed %s reqs %d", a.rollbacks, a.installed, len(a.rollbackReqs))
	}
	checkMaterial(t, a.rollbackReqs[0], oldSerial)
	if b := e.targets["b"]; b.rollbacks != 1 || len(b.rollbackReqs) != 0 {
		t.Errorf("target b without the capability: rollbacks %d, material requests %d", b.rollbacks, len(b.rollbackReqs))
	}

	st := e.state(t)
	if len(st.PreviousCerts) != 1 || st.PreviousCerts[0].Serial != oldSerial || st.PreviousCerts[0].KeyRef != oldKey {
		t.Errorf("previous certs = %+v, want the old certificate", st.PreviousCerts)
	}
	for _, en := range e.audit.entries {
		if strings.Contains(en.Detail+en.Error, "PRIVATE KEY") {
			t.Errorf("audit entry carries key material: %+v", en)
		}
	}

	// Once both targets serve the new certificate, the old one and its key
	// are forgotten.
	e.targets["a"].broken, e.targets["b"].broken = false, false
	e.now = e.now.Add(DefaultRetryBase + 1)
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	st = e.state(t)
	if len(st.PreviousCerts) != 0 || len(st.RetiredKeys) != 0 || !slices.Contains(e.ks.Released, oldKey) {
		t.Errorf("after every target verified: previous %+v retired %v released %v", st.PreviousCerts, st.RetiredKeys, e.ks.Released)
	}
}

func TestRollbackMaterialAfterRestart(t *testing.T) {
	// Each Process call loads the state from disk, so this is the same as
	// a new connector process. The crash leaves the target activated and
	// unverified; the next run verifies, fails and rolls back with the
	// material recorded before the crash.
	e := materialSetup(t, "a")
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	oldSerial := e.api.serial()

	e.targets["a"].broken = true
	crash := &crashAtVerify{e: e, t: t}
	crash.arm()
	_ = e.process(t, true)
	crash.restore()
	if st := e.state(t); st.Targets["a"].Phase != PhaseActivated || len(st.PreviousCerts) != 1 {
		t.Fatalf("snapshot state: target %+v previous %+v", st.Targets["a"], st.PreviousCerts)
	}

	err := e.process(t, false)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("recovery err = %v", err)
	}
	a := e.targets["a"]
	if a.installed != oldSerial || len(a.rollbackReqs) != 1 {
		t.Fatalf("installed %s after recovery, want %s", a.installed, oldSerial)
	}
	checkMaterial(t, a.rollbackReqs[0], oldSerial)
}

func TestRollbackMaterialForOlderInterruptedDeployment(t *testing.T) {
	// A deployment of B was interrupted after Activate, and C was issued
	// before the next run. Recovery puts A back with A's material.
	e := materialSetup(t, "a")
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	serialA := e.api.serial()
	crash := &crashAtVerify{e: e, t: t}
	crash.arm()
	_ = e.process(t, true)
	crash.restore()

	// The forced pass issues C first, then finds B half deployed.
	if err := e.process(t, true); err != nil {
		t.Fatalf("pass after the crash: %v", err)
	}
	a := e.targets["a"]
	if len(a.rollbackReqs) == 0 {
		t.Fatal("interrupted deployment was not rolled back")
	}
	checkMaterial(t, a.rollbackReqs[0], serialA)
	if a.installed != e.api.serial() {
		t.Errorf("target serves %s, want the newest certificate %s", a.installed, e.api.serial())
	}
}

func TestRollbackWithoutMaterial(t *testing.T) {
	cases := map[string]struct {
		// prepare runs before the failing deployment; crash makes that
		// deployment crash after Activate and returns the state to resume.
		prepare func(t *testing.T, e *env)
		crash   func(t *testing.T, st *State)
		reason  string
	}{
		"first deployment": {
			reason: "has not deployed a certificate to this target before",
		},
		"key released": {
			prepare: func(t *testing.T, e *env) {
				firstDeploy(t, e)
				_ = e.ks.Release(context.Background(), plugin.ReleaseRequest{KeyRef: e.state(t).KeyRef})
			},
			reason: "could not export its key",
		},
		"key store cannot export": {
			prepare: func(t *testing.T, e *env) {
				firstDeploy(t, e)
				e.job.Targets[0].RollbackUnavailable = "the key store does not allow export"
			},
			reason: "does not allow export",
		},
		"certificate not recorded": {
			// State written by a connector version that did not record
			// earlier certificates, in the middle of a deployment.
			prepare: firstDeploy,
			crash:   func(_ *testing.T, st *State) { st.PreviousCerts = nil },
			reason:  "no longer holds certificate",
		},
		"certificate expired": {
			prepare: firstDeploy,
			crash: func(_ *testing.T, st *State) {
				for i := range st.PreviousCerts {
					st.PreviousCerts[i].NotAfter = st.UpdatedAt.Add(-time.Hour)
				}
				ts := st.Targets["a"]
				ts.NotAfter = time.Time{} // older state without the target's expiry
				st.Targets["a"] = ts
			},
			reason: "has expired",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := materialSetup(t, "a")
			if c.prepare != nil {
				c.prepare(t, e)
			}
			e.targets["a"].broken = true
			var err error
			if c.crash != nil {
				crash := &crashAtVerify{e: e, t: t}
				crash.arm()
				_ = e.process(t, true)
				crash.restore()
				st := e.state(t)
				c.crash(t, st)
				if err := os.WriteFile(e.engine.State.path(1043), mustJSON(t, st), 0o600); err != nil {
					t.Fatal(err)
				}
				err = e.process(t, false)
			} else {
				err = e.process(t, true)
			}
			if err == nil || !strings.Contains(err.Error(), "rollback failed") || !strings.Contains(err.Error(), "previous certificate and key required") {
				t.Fatalf("err = %v", err)
			}
			a := e.targets["a"]
			if len(a.rollbackReqs) != 1 || a.rollbackReqs[0].HasPreviousMaterial() {
				t.Fatalf("rollback requests = %v, want one without material", a.rollbackReqs)
			}
			if !e.audit.has(audit.StepRollback, audit.ResultFailed, c.reason) {
				t.Errorf("rollback audit does not say why there was no material (%q)", c.reason)
			}
			if ts := e.state(t).Targets["a"]; ts.Outcome != OutcomeFailed {
				t.Errorf("target state = %+v", ts)
			}
		})
	}
}

func firstDeploy(t *testing.T, e *env) {
	t.Helper()
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, st *State) []byte {
	t.Helper()
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCancelledPassKeepsStateOfTargetsNotReached(t *testing.T) {
	e := setup(t, "a", "b", "c")
	firstDeploy(t, e)
	oldSerial := e.api.serial()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.verifier.hook = func(verify.Request) error {
		cancel()
		return nil
	}
	for i := range e.job.Targets {
		e.job.Targets[i].Caps = e.targets[e.job.Targets[i].Config.Label].caps
	}
	_ = e.engine.Process(ctx, e.job, Options{RunID: "run", Force: true})

	st := e.state(t)
	for _, l := range []string{"b", "c"} {
		if ts, ok := st.Targets[l]; !ok || ts.Serial != oldSerial {
			t.Errorf("state of target %s after a cancelled pass = %+v (present %v), want serial %s", l, ts, ok, oldSerial)
		}
	}
	if len(st.PreviousCerts) != 1 || st.PreviousCerts[0].Serial != oldSerial {
		t.Errorf("previous certificate the other targets still serve was dropped: %+v", st.PreviousCerts)
	}
}
