// Package deploy is the connector's renewal and deployment state machine.
//
// For each certificate, a pass does:
//
//  1. Due check: renew when renewAfter has passed (or 30 days before expiry
//     when the API does not send renewAfter), when forced, or when the
//     connector does not hold the key for the current certificate.
//  2. Ask the key store for a new key and CSR, renew with it, and wait for
//     issuance.
//  3. Check that the issued leaf carries the key store's public key and
//     exactly the configured names. Otherwise reject it and deploy nothing.
//  4. For each target on its own: export the key in the agreed format,
//     Stage, Activate (recording the previous ref in the audit log before
//     anything else), run the then command, and verify the endpoint. On
//     failure, roll that target back. Other targets are not affected.
//  5. When every target serves the new certificate, release the old keys.
//
// Targets that failed keep their old certificate and are retried on the
// next pass.
package deploy

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/krakenkey/connector/internal/api"
	"github.com/krakenkey/connector/internal/audit"
	"github.com/krakenkey/connector/internal/certutil"
	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/execx"
	"github.com/krakenkey/connector/internal/verify"
	"github.com/krakenkey/connector/pkg/plugin"
)

// API is the part of the KrakenKey API the engine uses.
type API interface {
	GetCert(ctx context.Context, id int) (*api.Cert, error)
	RenewCert(ctx context.Context, id int, csrPEM string) (*api.CertResponse, error)
	WaitForIssuance(ctx context.Context, id int, previousCrt string) (*api.Cert, error)
	GetCertChain(ctx context.Context, id int) (*api.Chain, error)
}

// Verifier checks an endpoint.
type Verifier interface {
	Verify(ctx context.Context, req verify.Request) error
}

// CommandRunner runs then.exec commands.
type CommandRunner func(ctx context.Context, argv, env []string, timeout time.Duration) error

// Engine runs passes. All fields except Now and RunThen are required.
type Engine struct {
	API      API
	Verifier Verifier
	Audit    audit.Writer
	State    *StateStore
	Log      *slog.Logger
	// RunThen defaults to execx.Run.
	RunThen CommandRunner
	// Now defaults to time.Now.
	Now func() time.Time
	// RollbackTimeout bounds a rollback, which runs even if the pass is
	// being cancelled. Default 5m.
	RollbackTimeout time.Duration
}

// Job is one configured certificate with its plugins resolved.
type Job struct {
	Cert           config.Certificate
	KeyStoreName   string
	KeyStore       plugin.KeyStore
	KeyStoreConfig json.RawMessage
	Targets        []TargetJob
}

// TargetJob is one configured target with its plugin resolved.
type TargetJob struct {
	Config   config.Target
	Plugin   plugin.Target
	Settings json.RawMessage
	Caps     plugin.TargetCapabilities
	// Format is the key format agreed by plugin.Match.
	Format plugin.KeyFormat
	// Window is the resolved verify window.
	Window time.Duration
	// Roots come from verify.ca_file; nil means the system roots.
	Roots *x509.CertPool
}

// Options change one pass.
type Options struct {
	RunID string
	// Force renews even when the certificate is not due.
	Force bool
}

// RejectedError means an issued certificate failed the checks against the
// configured names or the key store's key, and nothing was deployed.
type RejectedError struct{ Reason string }

func (e *RejectedError) Error() string {
	return "issued certificate rejected, nothing deployed: " + e.Reason
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) audit(entry audit.Entry) error {
	if err := e.Audit.Write(entry); err != nil {
		e.Log.Error("audit log write failed", "error", err, "step", entry.Step)
		return err
	}
	return nil
}

// Process runs one pass for one certificate.
func (e *Engine) Process(ctx context.Context, job Job, opts Options) error {
	id := job.Cert.ID
	log := e.Log.With("certificate_id", id, "run_id", opts.RunID)
	entry := func(step, result string) audit.Entry {
		return audit.Entry{RunID: opts.RunID, CertificateID: id, Step: step, Result: result}
	}

	cert, err := e.API.GetCert(ctx, id)
	if err != nil {
		return fmt.Errorf("certificate %d: %w", id, err)
	}
	if cert.ManagedBy != nil {
		log.Debug("certificate record", "managed_by", *cert.ManagedBy)
	}

	st, err := e.State.Load(id)
	if err != nil {
		return err
	}
	if st != nil && st.KeyStore != job.KeyStoreName {
		log.Warn("key store changed since the last run; starting over with the new one",
			"old_key_store", st.KeyStore, "new_key_store", job.KeyStoreName)
		st = nil
	}

	currentSerial := ""
	if cert.CrtPem != "" {
		if leaf, err := certutil.ParseLeaf(cert.CrtPem); err == nil {
			currentSerial = certutil.SerialHex(leaf.SerialNumber)
		}
	}
	held := st != nil && st.KeyRef != "" && st.Serial != "" && st.Serial == currentSerial

	switch cert.Status {
	case api.StatusPending, api.StatusIssuing, api.StatusRenewing, api.StatusRevoking:
		log.Info("certificate is busy in KrakenKey; checking again next pass", "status", cert.Status)
		e2 := entry(audit.StepCheck, audit.ResultSkipped)
		e2.Detail = "status " + cert.Status
		_ = e.audit(e2)
		return nil
	case api.StatusRevoked:
		return fmt.Errorf("certificate %d is revoked; issue a new one in KrakenKey and update the config", id)
	}

	renewAt, fromAPI, known := cert.RenewAt()
	reason := ""
	switch {
	case opts.Force:
		reason = "forced with --force"
	case st == nil:
		reason = "first run: the connector does not hold the key for the current certificate yet"
	case !held:
		reason = "the current certificate was not issued for a key this connector holds"
	case !known:
		reason = "the API sent neither renewAfter nor expiresAt"
	case !e.now().Before(renewAt):
		if fromAPI {
			reason = "renewAfter has passed"
		} else {
			reason = "less than 30 days to expiry (the API sent no renewAfter)"
		}
	}

	if reason != "" {
		if opts.Force {
			log.Warn("renewing because --force was given, although the certificate may not be due",
				"renew_after", renewAt, "renew_after_known", known)
		}
		log.Info("renewing", "reason", reason, "status", cert.Status, "current_serial", currentSerial)
		st, err = e.renew(ctx, log, job, cert, st, currentSerial, reason, opts)
		if err != nil {
			return fmt.Errorf("certificate %d: %w", id, err)
		}
	} else {
		log.Info("not due for renewal", "renew_after", renewAt, "renew_after_from_api", fromAPI)
	}

	return e.deployPending(ctx, log, job, st, opts)
}

func (e *Engine) renew(ctx context.Context, log *slog.Logger, job Job, cert *api.Cert, st *State,
	oldSerial, reason string, opts Options) (*State, error) {
	id := job.Cert.ID
	entry := func(step, result string) audit.Entry {
		return audit.Entry{RunID: opts.RunID, CertificateID: id, Step: step, Result: result, OldSerial: oldSerial}
	}
	fail := func(step string, err error) error {
		a := entry(step, audit.ResultFailed)
		var rej *RejectedError
		if errors.As(err, &rej) {
			a.Result = audit.ResultRejected
		}
		a.Error = err.Error()
		_ = e.audit(a)
		return err
	}

	csr, err := job.KeyStore.CreateCSR(ctx, plugin.CSRRequest{
		Config:        job.KeyStoreConfig,
		CertificateID: strconv.Itoa(id),
		Names:         job.Cert.Names,
		KeyType:       job.Cert.KeyStore.KeyType,
	})
	if err != nil {
		return nil, fail(audit.StepCreateCSR, err)
	}
	a := entry(audit.StepCreateCSR, audit.ResultOK)
	a.Detail = reason
	_ = e.audit(a)

	// From here on, a failure leaves a key nobody will use.
	release := func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		r := entry(audit.StepRelease, audit.ResultOK)
		r.Detail = "unused key from a failed renewal"
		if err := job.KeyStore.Release(rctx, plugin.ReleaseRequest{Config: job.KeyStoreConfig, KeyRef: csr.KeyRef}); err != nil {
			log.Warn("could not release unused key", "error", err)
			r.Result, r.Error = audit.ResultFailed, err.Error()
		}
		_ = e.audit(r)
	}

	req, err := certutil.ParseCSR(csr.PEM)
	if err != nil {
		release()
		return nil, fail(audit.StepCreateCSR, fmt.Errorf("key store returned a bad CSR: %w", err))
	}
	if !certutil.SameNames(certutil.CSRNames(req), job.Cert.Names) {
		release()
		return nil, fail(audit.StepCreateCSR, fmt.Errorf("key store returned a CSR for %v, want %v",
			certutil.CSRNames(req), job.Cert.Names))
	}

	if _, err := e.API.RenewCert(ctx, id, csr.PEM); err != nil {
		release()
		return nil, fail(audit.StepRenew, err)
	}
	_ = e.audit(entry(audit.StepRenew, audit.ResultOK))
	log.Info("renewal requested; waiting for issuance")

	issued, err := e.API.WaitForIssuance(ctx, id, cert.CrtPem)
	if err != nil {
		release()
		return nil, fail(audit.StepIssued, err)
	}
	leaf, err := certutil.ParseLeaf(issued.CrtPem)
	if err != nil {
		release()
		return nil, fail(audit.StepIssued, &RejectedError{Reason: "cannot parse the issued certificate: " + err.Error()})
	}
	newSerial := certutil.SerialHex(leaf.SerialNumber)
	if !certutil.SamePublicKey(leaf.PublicKey, req.PublicKey) {
		release()
		return nil, fail(audit.StepIssued, &RejectedError{Reason: fmt.Sprintf(
			"certificate %s does not carry the public key from the connector's CSR", newSerial)})
	}
	if !certutil.SameNames(certutil.CertNames(leaf), job.Cert.Names) {
		release()
		return nil, fail(audit.StepIssued, &RejectedError{Reason: fmt.Sprintf(
			"certificate %s covers %v, but the config lists %v", newSerial,
			certutil.NormalizeNames(certutil.CertNames(leaf)), certutil.NormalizeNames(job.Cert.Names))})
	}

	fullChain := e.fullChain(ctx, log, id, issued, leaf)

	keyRef, err := job.KeyStore.Complete(ctx, plugin.CompleteRequest{
		Config: job.KeyStoreConfig, KeyRef: csr.KeyRef, CertPEM: issued.CrtPem, ChainPEM: issued.ChainPem,
	})
	if err != nil {
		release()
		return nil, fail(audit.StepComplete, err)
	}

	next := &State{
		CertificateID: id,
		KeyStore:      job.KeyStoreName,
		KeyRef:        keyRef,
		Serial:        newSerial,
		CertPEM:       issued.CrtPem,
		ChainPEM:      issued.ChainPem,
		FullChainPEM:  fullChain,
		Targets:       map[string]TargetState{},
		UpdatedAt:     e.now().UTC(),
	}
	if st != nil {
		next.Targets = st.Targets
		next.RetiredKeys = append(next.RetiredKeys, st.RetiredKeys...)
		if st.KeyRef != "" && st.KeyRef != keyRef && !slices.Contains(next.RetiredKeys, st.KeyRef) {
			next.RetiredKeys = append(next.RetiredKeys, st.KeyRef)
		}
	}
	if err := e.State.Save(next); err != nil {
		return nil, err
	}
	ok := entry(audit.StepIssued, audit.ResultOK)
	ok.NewSerial = newSerial
	_ = e.audit(ok)
	log.Info("certificate issued and checked", "new_serial", newSerial, "old_serial", oldSerial)
	return next, nil
}

// fullChain prefers the API's fullChainPem, but falls back to leaf plus
// chain if it is missing or does not start with the issued leaf.
func (e *Engine) fullChain(ctx context.Context, log *slog.Logger, id int, issued *api.Cert, leaf *x509.Certificate) string {
	built := strings.TrimSpace(issued.CrtPem) + "\n"
	if c := strings.TrimSpace(issued.ChainPem); c != "" {
		built += c + "\n"
	}
	chain, err := e.API.GetCertChain(ctx, id)
	if err != nil {
		log.Warn("could not fetch the full chain; building it from the certificate record", "error", err)
		return built
	}
	certs, err := certutil.ParseCerts([]byte(chain.FullChainPem))
	if err != nil || !certs[0].Equal(leaf) {
		log.Warn("full chain from the API does not start with the issued leaf; building it from the certificate record")
		return built
	}
	return chain.FullChainPem
}

func (e *Engine) deployPending(ctx context.Context, log *slog.Logger, job Job, st *State, opts Options) error {
	if st == nil {
		return nil
	}
	labels := make([]string, 0, len(job.Targets))
	var errs []error
	for _, tj := range job.Targets {
		label := tj.Config.Label
		labels = append(labels, label)
		ts := st.Targets[label]
		if ts.Serial == st.Serial {
			continue
		}
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		deployed, prevRef, err := e.deployTarget(ctx, log.With("target", label), job, tj, st, ts.Serial, opts)
		if prevRef != "" {
			ts.PreviousRef = prevRef
		}
		if deployed {
			ts.Serial = st.Serial
		}
		ts.LastError = ""
		if err != nil {
			ts.LastError = err.Error()
			errs = append(errs, fmt.Errorf("target %s: %w", label, err))
		}
		ts.UpdatedAt = e.now().UTC()
		st.Targets[label] = ts
		if err := e.State.Save(st); err != nil {
			errs = append(errs, err)
		}
	}

	// Forget targets that are no longer configured.
	for label := range st.Targets {
		if !slices.Contains(labels, label) {
			delete(st.Targets, label)
		}
	}

	allCurrent := true
	for _, label := range labels {
		if st.Targets[label].Serial != st.Serial {
			allCurrent = false
		}
	}
	if allCurrent && len(st.RetiredKeys) > 0 {
		var kept []string
		for _, ref := range st.RetiredKeys {
			a := audit.Entry{RunID: opts.RunID, CertificateID: job.Cert.ID, Step: audit.StepRelease, Result: audit.ResultOK,
				Detail: "every target serves serial " + st.Serial}
			if err := job.KeyStore.Release(ctx, plugin.ReleaseRequest{Config: job.KeyStoreConfig, KeyRef: ref}); err != nil {
				log.Warn("could not release old key; will retry", "error", err)
				a.Result, a.Error = audit.ResultFailed, err.Error()
				kept = append(kept, ref)
			}
			_ = e.audit(a)
		}
		st.RetiredKeys = kept
		if len(kept) == 0 {
			log.Info("old keys released; every target serves the current certificate", "serial", st.Serial)
		}
	}
	if err := e.State.Save(st); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// deployTarget deploys the state's certificate to one target. deployed is
// true when the target now holds the new certificate (verified, or not
// rolled back because it propagates on its own schedule).
func (e *Engine) deployTarget(ctx context.Context, log *slog.Logger, job Job, tj TargetJob, st *State,
	oldSerial string, opts Options) (deployed bool, prevRef string, err error) {
	label := tj.Config.Label
	entry := func(step, result string) audit.Entry {
		return audit.Entry{RunID: opts.RunID, CertificateID: job.Cert.ID, Target: label, Step: step,
			Result: result, OldSerial: oldSerial, NewSerial: st.Serial}
	}
	failEntry := func(step string, err error) {
		a := entry(step, audit.ResultFailed)
		a.Error = err.Error()
		_ = e.audit(a)
		log.Error("deployment step failed", "step", step, "error", err)
	}

	key, err := job.KeyStore.Export(ctx, plugin.ExportRequest{Config: job.KeyStoreConfig, KeyRef: st.KeyRef, Format: tj.Format})
	if err != nil {
		failEntry(audit.StepStage, err)
		return false, "", err
	}
	stagedRef, err := tj.Plugin.Stage(ctx, plugin.StageRequest{
		Config:        tj.Settings,
		CertificateID: strconv.Itoa(job.Cert.ID),
		Label:         label,
		CertPEM:       st.CertPEM,
		ChainPEM:      st.ChainPEM,
		FullChainPEM:  st.FullChainPEM,
		Key:           key,
		Serial:        st.Serial,
	})
	if err != nil {
		failEntry(audit.StepStage, err)
		return false, "", err
	}
	_ = e.audit(entry(audit.StepStage, audit.ResultOK))

	prevRef, err = tj.Plugin.Activate(ctx, tj.Settings, stagedRef)
	if err != nil {
		failEntry(audit.StepActivate, err)
		return false, "", err
	}
	act := entry(audit.StepActivate, audit.ResultOK)
	act.PreviousRef = prevRef
	if aerr := e.audit(act); aerr != nil {
		// Without a record of how to undo this, do not leave it live.
		cause := fmt.Errorf("could not record the activation in the audit log: %w", aerr)
		return false, prevRef, e.rollback(ctx, log, job, tj, st, prevRef, entry, cause)
	}
	log.Info("activated", "serial", st.Serial)

	if tj.Config.Then != nil {
		if err := e.runThen(ctx, job, tj, st.Serial, "deploy"); err != nil {
			failEntry(audit.StepThen, err)
			return false, prevRef, e.rollback(ctx, log, job, tj, st, prevRef, entry, err)
		}
		_ = e.audit(entry(audit.StepThen, audit.ResultOK))
	}

	v := tj.Config.Verify
	if v == nil {
		log.Warn("no verify block for this target; the deployment is not checked")
		a := entry(audit.StepVerify, audit.ResultSkipped)
		a.Detail = "no verify block in config"
		_ = e.audit(a)
		return true, prevRef, nil
	}
	leaf, err := certutil.ParseLeaf(st.CertPEM)
	if err != nil {
		return false, prevRef, e.rollback(ctx, log, job, tj, st, prevRef, entry, err)
	}
	if v.SkipChainValidation {
		log.Warn("chain validation is off for this target (verify.skip_chain_validation); only the served leaf is checked")
	}
	vreq := verify.Request{
		Host:                v.Host,
		Address:             v.DialAddress(),
		Expected:            leaf,
		Window:              tj.Window,
		Roots:               tj.Roots,
		SkipChainValidation: v.SkipChainValidation,
	}
	log.Info("verifying", "address", vreq.Address, "sni", vreq.Host, "window", vreq.Window)
	if err := e.Verifier.Verify(ctx, vreq); err != nil {
		if tj.Caps.PropagatesAsync {
			a := entry(audit.StepVerify, audit.ResultReported)
			a.Error = err.Error()
			a.Detail = "target propagates on its own schedule; not rolled back"
			_ = e.audit(a)
			log.Error("verification failed; not rolling back because this target propagates on its own schedule", "error", err)
			return true, prevRef, fmt.Errorf("verify (not rolled back): %w", err)
		}
		failEntry(audit.StepVerify, err)
		return false, prevRef, e.rollback(ctx, log, job, tj, st, prevRef, entry, err)
	}
	a := entry(audit.StepVerify, audit.ResultOK)
	if v.SkipChainValidation {
		a.Detail = "chain validation skipped by config"
	}
	_ = e.audit(a)
	log.Info("deployed and verified", "serial", st.Serial)
	return true, prevRef, nil
}

// rollback undoes an activation and returns cause joined with any rollback
// error. It runs even if ctx is cancelled.
func (e *Engine) rollback(ctx context.Context, log *slog.Logger, job Job, tj TargetJob, st *State, prevRef string,
	entry func(step, result string) audit.Entry, cause error) error {
	if !tj.Caps.SupportsRollback {
		a := entry(audit.StepRollback, audit.ResultSkipped)
		a.Detail = "target does not support rollback"
		_ = e.audit(a)
		log.Error("target does not support rollback; it may be left with the new certificate", "error", cause)
		return fmt.Errorf("%w (target cannot roll back)", cause)
	}
	timeout := e.RollbackTimeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()

	a := entry(audit.StepRollback, audit.ResultOK)
	a.PreviousRef = prevRef
	if err := tj.Plugin.Rollback(rctx, tj.Settings, prevRef); err != nil {
		a.Result, a.Error = audit.ResultFailed, err.Error()
		_ = e.audit(a)
		log.Error("rollback failed", "error", err)
		return errors.Join(cause, fmt.Errorf("rollback failed: %w", err))
	}
	if tj.Config.Then != nil {
		if err := e.runThen(rctx, job, tj, "", "rollback"); err != nil {
			a.Result, a.Error = audit.ResultFailed, err.Error()
			a.Detail = "files rolled back; then.exec failed afterwards"
			_ = e.audit(a)
			log.Error("rolled back, but then.exec failed afterwards", "error", err)
			return errors.Join(cause, fmt.Errorf("files rolled back, but then.exec failed afterwards: %w", err))
		}
	}
	_ = e.audit(a)
	log.Warn("rolled back to the previous certificate", "cause", cause)
	return fmt.Errorf("%w (rolled back)", cause)
}

func (e *Engine) runThen(ctx context.Context, job Job, tj TargetJob, serial, action string) error {
	run := e.RunThen
	if run == nil {
		run = execx.Run
	}
	env := execx.Env(
		"KK_ACTION="+action,
		"KK_CERT_ID="+strconv.Itoa(job.Cert.ID),
		"KK_CERT_SERIAL="+serial,
		"KK_TARGET_LABEL="+tj.Config.Label,
	)
	if err := run(ctx, tj.Config.Then.Exec, env, tj.Config.Then.Timeout); err != nil {
		return fmt.Errorf("then.exec: %w", err)
	}
	return nil
}
