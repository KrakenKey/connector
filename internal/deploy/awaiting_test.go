package deploy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/krakenkey/connector/internal/api"
	"github.com/krakenkey/connector/internal/audit"
)

// awaitingCSR makes the fake's certificate one KrakenKey created with names
// only.
func (f *fakeAPI) awaitingCSR(requested []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	created := time.Now().Add(-time.Minute)
	f.cert = api.Cert{ID: 1043, Status: api.StatusAwaitingCSR, RequestedNames: requested, RenewAfter: &created}
}

func TestAwaitingCSRIsIssuedAndDeployed(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(fmt.Sprintf("force=%v", force), func(t *testing.T) {
			e := setup(t, "a", "b")
			// Same names, other order and case.
			e.api.awaitingCSR([]string{"WWW.example.com", "api.example.com"})
			if err := e.process(t, force); err != nil {
				t.Fatalf("Process: %v", err)
			}
			if e.api.renews != 1 {
				t.Errorf("renews = %d, want 1", e.api.renews)
			}
			serial := e.api.serial()
			for l, tg := range e.targets {
				if tg.live != serial {
					t.Errorf("target %s serves %q, want %s", l, tg.live, serial)
				}
			}
			if !e.audit.has(audit.StepCreateCSR, audit.ResultOK, "first issuance") {
				t.Error("create_csr not audited as a first issuance")
			}
			for _, en := range e.audit.entries {
				if en.OldSerial != "" {
					t.Errorf("an entry refers to a previous certificate: %+v", en)
				}
			}
			st := e.state(t)
			if st.Serial != serial || st.KeyRef == "" || st.Pending != nil || len(st.RetiredKeys) != 0 {
				t.Errorf("state = %+v", st)
			}
			// The next pass leaves it alone.
			if err := e.process(t, false); err != nil || e.api.renews != 1 {
				t.Errorf("second pass: renews %d, err %v", e.api.renews, err)
			}
		})
	}
}

func TestAwaitingCSRNamesMismatch(t *testing.T) {
	for name, requested := range map[string][]string{
		"different names": {"api.example.com", "evil.example.com"},
		"fewer names":     {"api.example.com"},
		"no names sent":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			e := setup(t, "a")
			e.api.awaitingCSR(requested)
			err := e.process(t, true)
			if err == nil || !strings.Contains(err.Error(), "names") {
				t.Fatalf("err = %v", err)
			}
			if refs, _ := e.ks.KeyRefs("1043"); e.api.renews != 0 || len(refs) != 0 {
				t.Errorf("renewed or made a key: renews %d, keys %v", e.api.renews, refs)
			}
			if e.targets["a"].stages != 0 {
				t.Error("target staged")
			}
			if !e.audit.has(audit.StepCheck, audit.ResultFailed, "names") {
				t.Error("mismatch not audited")
			}
		})
	}
}

func TestAwaitingCSRAfterLostRenewal(t *testing.T) {
	// An earlier pass sent a CSR, but KrakenKey never got it: the
	// certificate is still waiting. The old pending key is dropped and a
	// new CSR is sent.
	e := setup(t, "a")
	e.api.awaitingCSR(names)
	e.engine.API = &failRenew{fakeAPI: e.api}
	if err := e.process(t, false); err == nil {
		t.Fatal("expected the lost renewal to fail the pass")
	}
	pending := e.state(t).Pending
	if pending == nil {
		t.Fatal("pending key not kept after an unknown outcome")
	}
	e.engine.API = e.api
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(e.ks.Released, pending.KeyRef) || e.targets["a"].live != e.api.serial() {
		t.Errorf("released %v, live %s", e.ks.Released, e.targets["a"].live)
	}
}

// failRenew loses every renewal request on the way to KrakenKey.
type failRenew struct{ *fakeAPI }

func (f *failRenew) RenewCert(context.Context, int, string) (*api.CertResponse, error) {
	return nil, errors.New("connection reset")
}
