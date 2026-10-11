package deploy

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/krakenkey/connector/internal/audit"
	"github.com/krakenkey/connector/pkg/plugin"
)

// TestInterruptedOlderDeploymentSupersededByKeyStore covers a deployment
// of an older certificate that was interrupted after Activate, when the
// target already serves the current certificate (the key store made it
// live in Complete). Rolling back would put the older certificate back
// over the current one, so the old deployment is just ended.
func TestInterruptedOlderDeploymentSupersededByKeyStore(t *testing.T) {
	e := materialSetup(t, "a")
	firstDeploy(t, e)
	tg := e.targets["a"]
	current := e.state(t).Serial

	st := e.state(t)
	st.Targets["a"] = TargetState{Serial: "0a", Phase: PhaseActivated, DeployingSerial: "0b", PreviousRef: "p-old"}
	if err := e.engine.State.Save(st); err != nil {
		t.Fatal(err)
	}
	tg.prev["p-old"] = "0a"
	if err := e.process(t, false); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if tg.rollbacks != 0 || len(tg.rollbackReqs) != 0 {
		t.Errorf("rolled back %d times over the current certificate", tg.rollbacks)
	}
	if ts := e.state(t).Targets["a"]; ts.Serial != current || ts.Phase != "" || ts.Outcome != OutcomeVerified {
		t.Errorf("state = %+v", ts)
	}
	if !e.audit.has(audit.StepRecover, audit.ResultSkipped, "serves the newer certificate") {
		t.Error("no audit entry for the superseded deployment")
	}

	// When the target does not serve the current certificate, the older
	// deployment is rolled back as before.
	st = e.state(t)
	st.Targets["a"] = TargetState{Serial: current, Phase: PhaseActivated, DeployingSerial: "0b", PreviousRef: "p-old2"}
	_ = e.engine.State.Save(st)
	tg.prev["p-old2"] = current
	tg.installed, tg.live = "0b", "0b"
	tg.caps.RollbackNeedsMaterial = false
	_ = e.process(t, false)
	if tg.rollbacks != 1 || tg.installed != current {
		t.Errorf("rollbacks %d, installed %s", tg.rollbacks, tg.installed)
	}
}

// TestKeyStoreDeploymentStageFailureInPlace: when Stage fails on the key
// store's own deployment but the target serves the new certificate (the
// key store made it live), it is checked as activated; any other target
// records the failure.
func TestKeyStoreDeploymentStageFailureInPlace(t *testing.T) {
	for _, own := range []bool{true, false} {
		t.Run(fmt.Sprintf("key store deployment %t", own), func(t *testing.T) {
			e := setup(t, "a")
			e.job.Targets[0].Config.KeyStoreDeployment = own
			firstDeploy(t, e)
			tg := e.targets["a"]
			tg.failStage = fmt.Errorf("%w: busy", plugin.ErrUnavailable)
			tg.serveOnStage = true
			err := e.process(t, true)
			ts := e.state(t).Targets["a"]
			if own {
				if err != nil || ts.Serial != e.api.serial() || ts.Outcome != OutcomeVerified {
					t.Errorf("err %v, state %+v", err, ts)
				}
				if !e.audit.has(audit.StepRecover, audit.ResultOK, "stage failed, but the key store's certificate is in place") {
					t.Error("no recover audit entry")
				}
				return
			}
			if err == nil || ts.Outcome != OutcomeFailed || ts.Serial == e.api.serial() {
				t.Errorf("err %v, state %+v", err, ts)
			}
		})
	}
}

// TestAsyncVerifyFailureCheckedAgain: a failed check on a target that picks
// up changes on its own schedule is recorded as verify_failed, not rolled
// back, reported as a TargetError, and checked again on later passes
// without deploying again.
func TestAsyncVerifyFailureCheckedAgain(t *testing.T) {
	e := setup(t, "a", "b")
	firstDeploy(t, e)
	tg := e.targets["a"]
	tg.caps.PropagatesAsync = true
	tg.broken = true
	err := e.process(t, true)
	var te *TargetError
	if err == nil || !OnlyTargetErrors(err) || !errors.As(err, &te) || te.Label != "a" ||
		!strings.Contains(err.Error(), "not rolled back because the target picks up changes on its own schedule") {
		t.Fatalf("err = %v", err)
	}
	serial := e.api.serial()
	ts := e.state(t).Targets["a"]
	if ts.Serial != serial || ts.Outcome != OutcomeVerifyFailed || tg.rollbacks != 0 || ts.Failures != 0 {
		t.Fatalf("state = %+v, rollbacks %d", ts, tg.rollbacks)
	}
	stages := tg.stages

	// Still not served: still failed, checked again, nothing deployed.
	if err := e.process(t, false); err == nil || tg.stages != stages {
		t.Errorf("second pass: %v, stages %d -> %d", err, stages, tg.stages)
	}
	// Served now: verified.
	tg.live = tg.installed
	if err := e.process(t, false); err != nil {
		t.Fatalf("third pass: %v", err)
	}
	if ts := e.state(t).Targets["a"]; ts.Outcome != OutcomeVerified || ts.LastError != "" || tg.stages != stages {
		t.Errorf("state = %+v", ts)
	}
	// Without a verify block any more, the target is just activated.
	tg.broken = true
	_ = e.process(t, true)
	e.job.Targets[0].Config.Verify = nil
	if err := e.process(t, false); err != nil {
		t.Fatal(err)
	}
	if ts := e.state(t).Targets["a"]; ts.Outcome != OutcomeUnverifiable {
		t.Errorf("state = %+v", ts)
	}
}
