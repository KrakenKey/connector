// Package deploy is the connector's renewal and deployment state machine.
//
// For each certificate, a pass does:
//
//  1. Adoption: if KrakenKey's current certificate carries a key the
//     connector holds (its current key, or a key whose renewal was still
//     in flight when an earlier pass stopped waiting), take that
//     certificate instead of renewing again. This also covers renewals
//     KrakenKey made on its own with the stored CSR.
//  2. Due check: renew when renewAfter has passed (or, if the API does not
//     send it, two thirds into the certificate's lifetime), when forced, or
//     when the connector does not hold the key for the current certificate.
//     A certificate KrakenKey created with names only (awaiting_csr) is
//     always due: the connector makes its first CSR, after checking that
//     the configured names are the ones KrakenKey is waiting for.
//  3. Ask the key store for a new key and CSR, record it as pending, renew
//     with it, and wait for issuance.
//  4. Check that the issued leaf carries the key store's public key and
//     exactly the configured names. Otherwise reject it and deploy nothing.
//  5. For each target on its own: finish or undo any deployment an earlier
//     run left half done, then export the key, Stage, Activate (recording
//     the previous ref in the state and the audit log before anything else),
//     run the then command, and verify the endpoint. On failure, roll that
//     target back, unless the certificate to go back to expires within a
//     day. Other targets are not affected. A target that cannot keep the
//     previous certificate and key itself (RollbackNeedsMaterial) is handed
//     them on rollback: the state keeps every earlier certificate a target
//     still serves, and the key store keeps its key.
//     The key store's own deployment (config.Target.KeyStoreDeployment)
//     already serves the new certificate when its turn comes, since the
//     key store made it live in Complete; a rollback there restores the
//     certificate the state recorded before that.
//  6. When every target serves the new certificate, release the old keys
//     and forget the earlier certificates.
//
// Targets that failed keep their old certificate and are retried on later
// passes, with growing delays.
package deploy

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
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

// KeyLister is implemented by key stores that can list their keys for a
// certificate (the built-in local key store). The engine uses it to delete
// keys its state no longer refers to.
type KeyLister interface {
	KeyRefs(certificateID string) ([]string, error)
}

// CommandRunner runs then.exec commands.
type CommandRunner func(ctx context.Context, argv, env []string, timeout time.Duration) error

// Defaults for Engine fields.
const (
	DefaultRollbackTimeout = 5 * time.Minute
	DefaultRetryBase       = 30 * time.Minute
	MaxRetryDelay          = 24 * time.Hour
	// RollbackMinValidity is how long the certificate a rollback would
	// restore must still be valid. Rolling back to something that expires
	// sooner than this is worse than keeping the new certificate.
	RollbackMinValidity = 24 * time.Hour
)

// Engine runs passes. API, Verifier, Audit, State and Log are required.
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
	// being cancelled.
	RollbackTimeout time.Duration
	// RetryBase is the delay after a target's first failed deployment; it
	// doubles with each further failure, up to MaxRetryDelay.
	RetryBase time.Duration
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
	// Format is the key format agreed by plugin.Match, or by
	// plugin.MatchKeyStoreDeployment for the key store's own deployment
	// (Config.KeyStoreDeployment). It is empty only for such a target that
	// gets no key.
	Format plugin.KeyFormat
	// Window is the resolved verify window.
	Window time.Duration
	// Roots come from verify.ca_file; nil means the system roots.
	Roots *x509.CertPool
	// RollbackUnavailable, when set, says why the previous certificate
	// and key cannot be handed to a target with RollbackNeedsMaterial (see
	// plugin.RollbackUnavailable). Rollback is then called without them.
	RollbackUnavailable string
}

// Options change one pass.
type Options struct {
	RunID string
	// Force renews even when the certificate is not due, and retries
	// failed targets without waiting for their retry delay.
	Force bool
}

// RejectedError means an issued certificate failed the checks against the
// configured names or the key store's key, and nothing was deployed.
type RejectedError struct{ Reason string }

func (e *RejectedError) Error() string {
	return "issued certificate rejected, nothing deployed: " + e.Reason
}

// BlocksDeployment marks a rejection as a failure on the connector's side.
func (e *RejectedError) BlocksDeployment() bool { return true }

// BlockedError wraps a failure on the connector's side (key store, config)
// that kept a certificate from being renewed or deployed. Status reports
// show such failures as failed deployments. Failures on KrakenKey's side
// (issuance failed, API errors) are not BlockedErrors.
type BlockedError struct{ Err error }

func (e *BlockedError) Error() string { return e.Err.Error() }

// Unwrap returns the wrapped error.
func (e *BlockedError) Unwrap() error { return e.Err }

// BlocksDeployment marks the error as a failure on the connector's side.
func (e *BlockedError) BlocksDeployment() bool { return true }

// IsBlocked reports whether err, or an error it wraps, is a failure on the
// connector's side that kept a certificate from being deployed: any error
// with a BlocksDeployment method that returns true.
func IsBlocked(err error) bool {
	var b interface{ BlocksDeployment() bool }
	return errors.As(err, &b) && b.BlocksDeployment()
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

func spkiHash(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// run carries what one certificate's pass needs.
type run struct {
	e    *Engine
	job  Job
	opts Options
	log  *slog.Logger
	st   *State
}

func (r *run) entry(step, result string) audit.Entry {
	return audit.Entry{RunID: r.opts.RunID, CertificateID: r.job.Cert.ID, Step: step, Result: result}
}

func (r *run) save() error {
	r.st.UpdatedAt = r.e.now().UTC()
	return r.e.State.Save(r.st)
}

func (r *run) bg(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), d)
}

// Process runs one pass for one certificate.
func (e *Engine) Process(ctx context.Context, job Job, opts Options) error {
	id := job.Cert.ID
	r := &run{e: e, job: job, opts: opts, log: e.Log.With("certificate_id", id, "run_id", opts.RunID)}

	cert, err := e.API.GetCert(ctx, id)
	if err != nil {
		return fmt.Errorf("certificate %d: %w", id, err)
	}
	if cert.ManagedBy != nil {
		r.log.Debug("certificate record", "managed_by", *cert.ManagedBy, "auto_renew", cert.AutoRenew)
	}

	st, err := e.State.Load(id)
	if err != nil {
		return err
	}
	if st != nil && st.KeyStore != job.KeyStoreName {
		r.log.Warn("key store changed since the last run; starting over with the new one",
			"old_key_store", st.KeyStore, "new_key_store", job.KeyStoreName)
		st = nil
	}
	if st == nil {
		st = &State{CertificateID: id, KeyStore: job.KeyStoreName, Targets: map[string]TargetState{}}
	}
	if st.KeySPKI == "" && st.CertPEM != "" {
		if leaf, err := certutil.ParseLeaf(st.CertPEM); err == nil {
			st.KeySPKI = spkiHash(leaf.RawSubjectPublicKeyInfo)
		}
	}
	r.st = st

	switch cert.Status {
	case api.StatusPending, api.StatusIssuing, api.StatusRenewing, api.StatusRevoking:
		r.log.Info("certificate is busy in KrakenKey; checking again next pass", "status", cert.Status)
		a := r.entry(audit.StepCheck, audit.ResultSkipped)
		a.Detail = "status " + cert.Status
		_ = e.audit(a)
		return nil
	case api.StatusRevoked:
		return fmt.Errorf("certificate %d is revoked; issue a new one in KrakenKey and update the config", id)
	}

	awaiting := cert.Status == api.StatusAwaitingCSR
	if awaiting {
		if err := checkRequestedNames(cert, job.Cert.Names); err != nil {
			a := r.entry(audit.StepCheck, audit.ResultFailed)
			a.Error = err.Error()
			_ = e.audit(a)
			return fmt.Errorf("certificate %d: %w", id, err)
		}
	}

	var leaf *x509.Certificate
	leafSerial, leafSPKI := "", ""
	// An awaiting_csr certificate has no leaf yet; nothing to adopt or
	// compare.
	if cert.CrtPem != "" && !awaiting {
		if l, err := certutil.ParseLeaf(cert.CrtPem); err == nil {
			leaf = l
			leafSerial = certutil.SerialHex(l.SerialNumber)
			leafSPKI = spkiHash(l.RawSubjectPublicKeyInfo)
		}
	}

	adoptRefused := false
	if leaf != nil && leafSerial != st.Serial && cert.Status == api.StatusIssued {
		if err := r.adopt(ctx, cert, leafSPKI); err != nil {
			if !errors.Is(err, errAdoptRefused) {
				return fmt.Errorf("certificate %d: %w", id, err)
			}
			// Retrying the same Complete every pass would not help; get
			// a certificate for a new key instead.
			r.log.Warn("the key store refused the certificate KrakenKey renewed with the connector's key; renewing with a new key", "error", err)
			adoptRefused = true
		}
	}
	held := st.KeyRef != "" && leaf != nil && leafSerial == st.Serial && leafSPKI == st.KeySPKI

	renewAt, source, known := cert.RenewAt()
	reason := ""
	switch {
	case awaiting:
		reason = "first issuance: KrakenKey is waiting for a CSR from this connector"
	case adoptRefused:
		reason = "the key store refused the certificate KrakenKey renewed with the connector's key"
	case opts.Force:
		reason = "forced with --force"
	case st.KeyRef == "":
		reason = "first run: the connector does not hold the key for the current certificate yet"
	case !held:
		reason = "the current certificate was not issued for a key this connector holds"
	case !known:
		r.log.Warn("cannot tell when to renew: the API sent neither renewAfter nor a parsable certificate or expiry; not renewing")
	case !e.now().Before(renewAt):
		reason = "renewal time reached (" + source + ")"
	}

	if reason != "" {
		if opts.Force && !awaiting {
			r.log.Warn("renewing because --force was given, although the certificate may not be due",
				"renew_after", renewAt, "renew_after_source", source)
		}
		r.log.Info("renewing", "reason", reason, "status", cert.Status, "current_serial", leafSerial)
		if err := r.renew(ctx, cert, leafSerial, reason); err != nil {
			return fmt.Errorf("certificate %d: %w", id, err)
		}
	} else if known {
		r.log.Info("not due for renewal", "renew_after", renewAt, "source", source)
	}

	if st.Serial == "" {
		return nil
	}
	err = r.deployPending(ctx)
	r.sweepOrphans(ctx)
	return err
}

// checkRequestedNames compares the configured names with the names an
// awaiting_csr certificate was created for. KrakenKey refuses a CSR for
// other names, so asking would only waste a key.
func checkRequestedNames(cert *api.Cert, configured []string) error {
	if len(cert.RequestedNames) == 0 {
		return errors.New("KrakenKey is waiting for a CSR but did not say for which names (no requestedNames)")
	}
	if !certutil.SameNames(cert.RequestedNames, configured) {
		return &RequestedNamesError{Configured: certutil.NormalizeNames(configured), Requested: certutil.NormalizeNames(cert.RequestedNames)}
	}
	return nil
}

// RequestedNamesError means the configured names differ from the names an
// awaiting_csr certificate was created for, so the connector will not
// issue it. It is a failure on the connector's side (its config): status
// reports show it as a failed deployment.
type RequestedNamesError struct {
	Configured, Requested []string
}

func (e *RequestedNamesError) Error() string {
	return fmt.Sprintf("config names %v differ from the names KrakenKey is waiting for %v; change the config to match, or create the certificate again with the right names",
		e.Configured, e.Requested)
}

// BlocksDeployment marks the error as a failure on the connector's side.
func (e *RequestedNamesError) BlocksDeployment() bool { return true }

// errCompleteRefused marks a permanent Complete failure, and
// errAdoptRefused one for a certificate KrakenKey renewed on its own with
// the connector's current key. The pass then renews with a new key instead
// of retrying the same Complete on every pass.
var (
	errCompleteRefused = errors.New("key store refused the issued certificate")
	errAdoptRefused    = errors.New("cannot adopt KrakenKey's renewal")
)

// adopt takes KrakenKey's current certificate when it carries a key the
// connector holds.
func (r *run) adopt(ctx context.Context, cert *api.Cert, leafSPKI string) error {
	st := r.st
	switch {
	case st.Pending != nil && leafSPKI == st.Pending.SPKI:
		r.log.Info("a renewal from an earlier pass has completed; deploying it", "key_ref", st.Pending.KeyRef)
		return r.finishIssued(ctx, cert, st.Pending.KeyRef, st.Pending.SPKI, true, "renewal from an earlier pass completed")
	case st.KeyRef != "" && leafSPKI == st.KeySPKI:
		if st.Pending != nil {
			// KrakenKey's current certificate is not the one the pending
			// key was for, so that renewal will not produce it. Resolve
			// it first: some key stores refuse to complete another
			// certificate while a request of their own is open.
			r.releaseKey(ctx, st.Pending.KeyRef, "pending key from a renewal superseded by KrakenKey's renewal with the current key")
			st.Pending = nil
			if err := r.save(); err != nil {
				return err
			}
		}
		r.log.Info("KrakenKey renewed the certificate with the connector's current key; deploying it")
		err := r.finishIssued(ctx, cert, st.KeyRef, st.KeySPKI, false, "renewed by KrakenKey with the connector's key")
		if errors.Is(err, errCompleteRefused) {
			return fmt.Errorf("%w: %w", errAdoptRefused, err)
		}
		return err
	}
	return nil
}

// renew creates a key and CSR, records it as pending, renews and waits.
func (r *run) renew(ctx context.Context, cert *api.Cert, oldSerial, reason string) error {
	job, st := r.job, r.st
	fail := func(step string, err error) error {
		a := r.entry(step, audit.ResultFailed)
		a.OldSerial = oldSerial
		var rej *RejectedError
		if errors.As(err, &rej) {
			a.Result = audit.ResultRejected
		}
		a.Error = err.Error()
		_ = r.e.audit(a)
		return err
	}

	if st.Pending != nil {
		// The earlier renewal did not produce the current certificate; its
		// key will never be used.
		r.releaseKey(ctx, st.Pending.KeyRef, "pending key from a renewal that did not complete")
		st.Pending = nil
		if err := r.save(); err != nil {
			return err
		}
	}

	csr, err := job.KeyStore.CreateCSR(ctx, plugin.CSRRequest{
		Config:        job.KeyStoreConfig,
		CertificateID: strconv.Itoa(job.Cert.ID),
		Names:         job.Cert.Names,
		KeyType:       job.Cert.KeyStore.KeyType,
	})
	if err != nil {
		return fail(audit.StepCreateCSR, &BlockedError{Err: err})
	}
	req, err := certutil.ParseCSR(csr.PEM)
	if err == nil && !certutil.SameNames(certutil.CSRNames(req), job.Cert.Names) {
		err = fmt.Errorf("key store returned a CSR for %v, want %v", certutil.CSRNames(req), job.Cert.Names)
	}
	if err != nil {
		r.releaseKey(ctx, csr.KeyRef, "unused key from a bad CSR")
		return fail(audit.StepCreateCSR, &BlockedError{Err: fmt.Errorf("key store returned a bad CSR: %w", err)})
	}
	a := r.entry(audit.StepCreateCSR, audit.ResultOK)
	a.Detail = reason
	_ = r.e.audit(a)

	// Record the key before asking for the certificate, so a renewal that
	// finishes after this pass stops waiting is adopted, not repeated.
	st.Pending = &PendingKey{KeyRef: csr.KeyRef, SPKI: spkiHash(req.RawSubjectPublicKeyInfo), CreatedAt: r.e.now().UTC()}
	if err := r.save(); err != nil {
		r.releaseKey(ctx, csr.KeyRef, "unused key; state could not be saved")
		return err
	}
	dropPending := func(why string) {
		r.releaseKey(ctx, csr.KeyRef, why)
		st.Pending = nil
		_ = r.save()
	}

	if _, err := r.e.API.RenewCert(ctx, job.Cert.ID, csr.PEM); err != nil {
		if api.IsClientError(err) {
			dropPending("unused key; KrakenKey refused the renewal")
		} else {
			r.log.Warn("renewal request outcome unknown; keeping the key in case it went through", "error", err)
		}
		return fail(audit.StepRenew, err)
	}
	_ = r.e.audit(r.entry(audit.StepRenew, audit.ResultOK))
	r.log.Info("renewal requested; waiting for issuance")

	issued, err := r.e.API.WaitForIssuance(ctx, job.Cert.ID, cert.CrtPem)
	if err != nil {
		var failed *api.IssuanceFailedError
		if errors.As(err, &failed) || api.IsClientError(err) {
			dropPending("unused key from a failed renewal")
		} else {
			r.log.Warn("stopped waiting for issuance; the next pass picks up the certificate if it is issued", "error", err)
		}
		return fail(audit.StepIssued, err)
	}
	return r.finishIssued(ctx, issued, csr.KeyRef, st.Pending.SPKI, true, reason)
}

// finishIssued checks an issued certificate against the key and names,
// completes it in the key store and makes it the current certificate.
// fromPending says whether keyRef is the pending key (released on reject)
// or the current one.
func (r *run) finishIssued(ctx context.Context, issued *api.Cert, keyRef, spki string, fromPending bool, detail string) error {
	job, st := r.job, r.st
	oldSerial := st.Serial
	reject := func(reason string) error {
		err := &RejectedError{Reason: reason}
		if fromPending {
			r.releaseKey(ctx, keyRef, "unused key from a rejected certificate")
			st.Pending = nil
			_ = r.save()
		}
		a := r.entry(audit.StepIssued, audit.ResultRejected)
		a.OldSerial, a.Error = oldSerial, err.Error()
		_ = r.e.audit(a)
		return err
	}

	leaf, err := certutil.ParseLeaf(issued.CrtPem)
	if err != nil {
		return reject("cannot parse the issued certificate: " + err.Error())
	}
	newSerial := certutil.SerialHex(leaf.SerialNumber)
	if spkiHash(leaf.RawSubjectPublicKeyInfo) != spki {
		return reject(fmt.Sprintf("certificate %s does not carry the public key from the connector's CSR", newSerial))
	}
	if !certutil.SameNames(certutil.CertNames(leaf), job.Cert.Names) {
		return reject(fmt.Sprintf("certificate %s covers %v, but the config lists %v", newSerial,
			certutil.NormalizeNames(certutil.CertNames(leaf)), certutil.NormalizeNames(job.Cert.Names)))
	}
	// The key store must still hold the key.
	if der, err := job.KeyStore.PublicKey(ctx, plugin.PublicKeyRequest{Config: job.KeyStoreConfig, KeyRef: keyRef}); err == nil {
		if spkiHash(der) != spki {
			return reject("the key store's key does not match its CSR")
		}
	} else if errors.Is(err, plugin.ErrNotFound) {
		return reject("the key store no longer holds the key for this certificate")
	} else if !plugin.IsUnsupported(err) {
		return &BlockedError{Err: fmt.Errorf("key store: %w", err)}
	}

	fullChain := r.fullChain(ctx, issued, leaf)
	newRef, err := job.KeyStore.Complete(ctx, plugin.CompleteRequest{
		Config: job.KeyStoreConfig, KeyRef: keyRef, CertPEM: issued.CrtPem, ChainPEM: issued.ChainPem,
	})
	if err != nil {
		a := r.entry(audit.StepComplete, audit.ResultFailed)
		a.Error = err.Error()
		_ = r.e.audit(a)
		if plugin.IsPermanent(err) {
			err = fmt.Errorf("%w: %w", errCompleteRefused, err)
		}
		return &BlockedError{Err: err}
	}

	if st.Serial != "" && st.Serial != newSerial && st.CertPEM != "" {
		// Targets still serve the outgoing certificate until they are
		// deployed; keep it for targets that need it to roll back.
		prev := st.current()
		st.PreviousCerts = slices.DeleteFunc(st.PreviousCerts, func(c CertRecord) bool { return c.Serial == prev.Serial })
		st.PreviousCerts = append(st.PreviousCerts, prev)
	}
	if st.KeyRef != "" && st.KeyRef != newRef && !slices.Contains(st.RetiredKeys, st.KeyRef) {
		st.RetiredKeys = append(st.RetiredKeys, st.KeyRef)
	}
	st.KeyRef, st.KeySPKI = newRef, spki
	st.Serial, st.NotAfter = newSerial, leaf.NotAfter
	st.CertPEM, st.ChainPEM, st.FullChainPEM = issued.CrtPem, issued.ChainPem, fullChain
	if fromPending {
		st.Pending = nil
	}
	if err := r.save(); err != nil {
		return err
	}
	a := r.entry(audit.StepIssued, audit.ResultOK)
	a.OldSerial, a.NewSerial, a.Detail = oldSerial, newSerial, detail
	_ = r.e.audit(a)
	r.log.Info("certificate issued and checked", "new_serial", newSerial, "old_serial", oldSerial)
	return nil
}

func (r *run) releaseKey(ctx context.Context, ref, why string) {
	rctx, cancel := r.bg(ctx, time.Minute)
	defer cancel()
	a := r.entry(audit.StepRelease, audit.ResultOK)
	a.Detail = why
	if err := r.job.KeyStore.Release(rctx, plugin.ReleaseRequest{Config: r.job.KeyStoreConfig, KeyRef: ref}); err != nil {
		r.log.Warn("could not release key", "error", err)
		a.Result, a.Error = audit.ResultFailed, err.Error()
	}
	_ = r.e.audit(a)
}

// fullChain prefers the API's fullChainPem, but falls back to leaf plus
// chain if it is missing or does not start with the issued leaf.
func (r *run) fullChain(ctx context.Context, issued *api.Cert, leaf *x509.Certificate) string {
	built := strings.TrimSpace(issued.CrtPem) + "\n"
	if c := strings.TrimSpace(issued.ChainPem); c != "" {
		built += c + "\n"
	}
	chain, err := r.e.API.GetCertChain(ctx, r.job.Cert.ID)
	if err != nil {
		r.log.Warn("could not fetch the full chain; building it from the certificate record", "error", err)
		return built
	}
	certs, err := certutil.ParseCerts([]byte(chain.FullChainPem))
	if err != nil || !certs[0].Equal(leaf) {
		r.log.Warn("full chain from the API does not start with the issued leaf; building it from the certificate record")
		return built
	}
	return chain.FullChainPem
}

func (r *run) deployPending(ctx context.Context) error {
	st := r.st
	labels := make([]string, 0, len(r.job.Targets))
	for _, tj := range r.job.Targets {
		labels = append(labels, tj.Config.Label)
	}
	var errs []error
	for _, tj := range r.job.Targets {
		label := tj.Config.Label
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		tr := &targetRun{run: r, tj: tj, log: r.log.With("target", label)}
		if err := tr.deploy(ctx); err != nil {
			errs = append(errs, fmt.Errorf("target %s: %w", label, err))
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
		ts := st.Targets[label]
		if ts.Serial != st.Serial || ts.Phase != "" {
			allCurrent = false
		}
	}
	if allCurrent && len(st.RetiredKeys) > 0 {
		var kept []string
		for _, ref := range st.RetiredKeys {
			a := r.entry(audit.StepRelease, audit.ResultOK)
			a.Detail = "every target serves serial " + st.Serial
			if err := r.job.KeyStore.Release(ctx, plugin.ReleaseRequest{Config: r.job.KeyStoreConfig, KeyRef: ref}); err != nil {
				r.log.Warn("could not release old key; will retry", "error", err)
				a.Result, a.Error = audit.ResultFailed, err.Error()
				kept = append(kept, ref)
			}
			_ = r.e.audit(a)
		}
		st.RetiredKeys = kept
		if len(kept) == 0 {
			r.log.Info("old keys released; every target serves the current certificate", "serial", st.Serial)
		}
	}
	// Keep an earlier certificate only while a target serves it and its key
	// is still held.
	st.PreviousCerts = slices.DeleteFunc(st.PreviousCerts, func(c CertRecord) bool {
		served := slices.ContainsFunc(labels, func(l string) bool { return st.Targets[l].Serial == c.Serial })
		held := c.KeyRef == st.KeyRef || slices.Contains(st.RetiredKeys, c.KeyRef)
		return c.Serial == st.Serial || !served || !held
	})
	if err := r.save(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// sweepOrphans releases keys the key store holds for this certificate that
// the state no longer refers to (for example left by a crash between
// CreateCSR and saving the state).
func (r *run) sweepOrphans(ctx context.Context) {
	lister, ok := r.job.KeyStore.(KeyLister)
	if !ok {
		return
	}
	refs, err := lister.KeyRefs(strconv.Itoa(r.job.Cert.ID))
	if err != nil {
		r.log.Warn("could not list keys", "error", err)
		return
	}
	keep := append([]string{r.st.KeyRef}, r.st.RetiredKeys...)
	if r.st.Pending != nil {
		keep = append(keep, r.st.Pending.KeyRef)
	}
	for _, ref := range refs {
		if !slices.Contains(keep, ref) {
			r.releaseKey(ctx, ref, "key not referenced by the connector's state")
		}
	}
}

// targetRun deploys to one target.
type targetRun struct {
	*run
	tj  TargetJob
	log *slog.Logger
}

func (t *targetRun) label() string { return t.tj.Config.Label }

func (t *targetRun) ts() TargetState { return t.st.Targets[t.label()] }

func (t *targetRun) setTS(ts TargetState) {
	ts.UpdatedAt = t.e.now().UTC()
	t.st.Targets[t.label()] = ts
}

func (t *targetRun) entry(step, result string) audit.Entry {
	ts := t.ts()
	a := t.run.entry(step, result)
	a.Target, a.OldSerial, a.NewSerial = t.label(), ts.Serial, ts.DeployingSerial
	if a.NewSerial == "" {
		a.NewSerial = t.st.Serial
	}
	return a
}

func (t *targetRun) failStep(step string, err error) {
	a := t.entry(step, audit.ResultFailed)
	a.Error = err.Error()
	_ = t.e.audit(a)
	t.log.Error("deployment step failed", "step", step, "error", err)
}

// recordFailure ends a failed deployment and schedules the next attempt.
// outcome is OutcomeFailed or OutcomeRolledBack.
func (t *targetRun) recordFailure(err error, outcome string) error {
	ts := t.ts()
	ts.endDeployment()
	ts.Outcome = outcome
	ts.Failures++
	base := t.e.RetryBase
	if base == 0 {
		base = DefaultRetryBase
	}
	delay := min(base<<min(ts.Failures-1, 16), MaxRetryDelay)
	ts.NextAttempt = t.e.now().Add(delay).UTC()
	ts.LastError = err.Error()
	t.setTS(ts)
	_ = t.save()
	t.log.Warn("next attempt for this target delayed", "until", ts.NextAttempt, "failures", ts.Failures)
	return err
}

func (t *targetRun) recordSuccess(serial string, notAfter time.Time, outcome string) {
	ts := t.ts()
	ts.Serial, ts.NotAfter = serial, notAfter
	ts.Outcome = outcome
	ts.endDeployment()
	ts.Failures, ts.NextAttempt, ts.LastError = 0, time.Time{}, ""
	t.setTS(ts)
	_ = t.save()
}

func (t *targetRun) deploy(ctx context.Context) error {
	if t.ts().Phase != "" {
		if err := t.recover(ctx); err != nil {
			return err
		}
	}
	ts := t.ts()
	if ts.Serial == t.st.Serial {
		return nil
	}
	if !t.opts.Force && t.e.now().Before(ts.NextAttempt) {
		t.log.Info("waiting before trying this target again", "next_attempt", ts.NextAttempt, "last_error", ts.LastError)
		return nil
	}
	return t.deployCurrent(ctx)
}

// recover finishes or undoes a deployment an earlier run left half done.
func (t *targetRun) recover(ctx context.Context) error {
	ts := t.ts()
	a := t.entry(audit.StepRecover, audit.ResultOK)
	a.Detail = "interrupted in phase " + ts.Phase
	_ = t.e.audit(a)
	t.log.Warn("finishing a deployment interrupted by an earlier run", "phase", ts.Phase, "serial", ts.DeployingSerial)

	switch ts.Phase {
	case PhaseStaged:
		t.discard(ctx, ts.StagedRef)
		ts.endDeployment()
		t.setTS(ts)
		return t.save()

	case PhaseActivating:
		// Activate may or may not have happened. Ask the target.
		t.discard(ctx, ts.StagedRef)
		cur, err := t.tj.Plugin.Current(ctx, plugin.CurrentRequest{Config: t.tj.Settings, CertificateID: strconv.Itoa(t.job.Cert.ID), Label: t.label()})
		if err != nil {
			t.log.Warn("target cannot report its current certificate", "error", err)
			cur = ""
		}
		if cur == "" || cur != ts.DeployingSerial {
			ts.endDeployment()
			t.setTS(ts)
			return t.save()
		}
		// Activated, but the previous ref was lost with the earlier run.
		ts.Phase, ts.StagedRef, ts.PreviousRef = PhaseActivated, "", ""
		t.setTS(ts)
		_ = t.save()
		fallthrough

	case PhaseActivated:
		ts = t.ts()
		if ts.DeployingSerial != t.st.Serial {
			// A newer certificate has been issued since. Put the target
			// back the way it was; the normal path deploys the new one.
			err := t.rollback(ctx, ts.PreviousRef, errors.New("interrupted deployment of an older certificate"), false)
			if t.ts().Phase == "" && t.ts().Serial != t.st.Serial {
				// Rolled back (or kept); carry on with the current one.
				t.log.Info("undid an interrupted deployment of an older certificate", "result", err)
				return nil
			}
			return err
		}
		return t.finishActivated(ctx, ts.PreviousRef, true)
	}
	ts.Phase = ""
	t.setTS(ts)
	return t.save()
}

func (t *targetRun) discard(ctx context.Context, stagedRef string) {
	if stagedRef == "" {
		return
	}
	dctx, cancel := t.bg(ctx, time.Minute)
	defer cancel()
	err := t.tj.Plugin.Discard(dctx, plugin.DiscardRequest{
		Config: t.tj.Settings, StagedRef: stagedRef, CertificateID: strconv.Itoa(t.job.Cert.ID), Label: t.label(),
	})
	if err != nil && !plugin.IsUnsupported(err) && !errors.Is(err, plugin.ErrNotFound) {
		t.log.Warn("could not discard staged files", "error", err)
		a := t.entry(audit.StepDiscard, audit.ResultFailed)
		a.Error = err.Error()
		_ = t.e.audit(a)
	}
}

// current asks the target which certificate it serves, with its own
// timeout. It returns "" when the target cannot tell.
func (t *targetRun) current(ctx context.Context) string {
	cctx, cancel := t.bg(ctx, time.Minute)
	defer cancel()
	cur, err := t.tj.Plugin.Current(cctx, plugin.CurrentRequest{Config: t.tj.Settings, CertificateID: strconv.Itoa(t.job.Cert.ID), Label: t.label()})
	if err != nil {
		if !plugin.IsUnsupported(err) {
			t.log.Warn("target cannot report its current certificate", "error", err)
		}
		return ""
	}
	return cur
}

// notAfter returns the expiry of a certificate the state still records.
func (t *targetRun) notAfter(serial string) time.Time {
	rec, _ := t.st.certRecord(serial)
	return rec.NotAfter
}

func (t *targetRun) deployCurrent(ctx context.Context) error {
	st, tj := t.st, t.tj
	certID := strconv.Itoa(t.job.Cert.ID)

	var key plugin.KeyMaterial
	if tj.Format != "" {
		var err error
		key, err = t.job.KeyStore.Export(ctx, plugin.ExportRequest{Config: t.job.KeyStoreConfig, KeyRef: st.KeyRef, Format: tj.Format})
		if err != nil {
			t.failStep(audit.StepExport, err)
			return t.recordFailure(err, OutcomeFailed)
		}
	}
	stagedRef, err := tj.Plugin.Stage(ctx, plugin.StageRequest{
		Config:        tj.Settings,
		CertificateID: certID,
		Label:         t.label(),
		CertPEM:       st.CertPEM,
		ChainPEM:      st.ChainPEM,
		FullChainPEM:  st.FullChainPEM,
		Key:           key,
		Serial:        st.Serial,
	})
	if err != nil {
		t.failStep(audit.StepStage, err)
		return t.recordFailure(err, OutcomeFailed)
	}
	ts := t.ts()
	ts.Phase, ts.StagedRef, ts.DeployingSerial = PhaseStaged, stagedRef, st.Serial
	t.setTS(ts)
	if err := t.save(); err != nil {
		t.discard(ctx, stagedRef)
		return err
	}
	_ = t.e.audit(t.entry(audit.StepStage, audit.ResultOK))

	ts.Phase = PhaseActivating
	if tj.Caps.RollbackNeedsMaterial {
		// What the target serves now is what a rollback must restore,
		// whatever the state says it was given last. The key store's own
		// deployment is the exception: the key store put the new
		// certificate there in Complete, so a rollback undoes that and
		// restores what the state recorded before it.
		if cur := t.current(ctx); !tj.Config.KeyStoreDeployment || cur != st.Serial {
			ts.LiveBefore = cur
		}
	}
	t.setTS(ts)
	if err := t.save(); err != nil {
		t.discard(ctx, stagedRef)
		return err
	}
	prevRef, err := tj.Plugin.Activate(ctx, plugin.ActivateRequest{
		Config: tj.Settings, StagedRef: stagedRef, CertificateID: certID, Label: t.label(),
	})
	if err != nil {
		t.failStep(audit.StepActivate, err)
		t.discard(ctx, stagedRef)
		if cur := t.current(ctx); cur != "" && cur == st.Serial {
			// The target reports the new certificate although Activate
			// failed (for example the answer was lost). Treat it as
			// activated with an unknown previous state, as recovery does,
			// so the state matches what the target serves.
			a := t.entry(audit.StepRecover, audit.ResultOK)
			a.Detail = "activate failed, but the target serves the new certificate; checking it"
			_ = t.e.audit(a)
			t.log.Warn("activate failed, but the target reports the new certificate; verifying it as activated", "error", err)
			ts = t.ts()
			ts.Phase, ts.StagedRef, ts.PreviousRef = PhaseActivated, "", ""
			t.setTS(ts)
			_ = t.save()
			return t.finishActivated(ctx, "", true)
		}
		return t.recordFailure(err, OutcomeFailed)
	}
	ts.Phase, ts.StagedRef, ts.PreviousRef = PhaseActivated, "", prevRef
	t.setTS(ts)
	saveErr := t.save()
	act := t.entry(audit.StepActivate, audit.ResultOK)
	act.PreviousRef = prevRef
	auditErr := t.e.audit(act)
	if err := errors.Join(saveErr, auditErr); err != nil {
		// Without a record of how to undo this, do not leave it live.
		return t.rollback(ctx, prevRef, fmt.Errorf("could not record the activation: %w", err), true)
	}
	t.log.Info("activated", "serial", st.Serial)
	return t.finishActivated(ctx, prevRef, false)
}

// finishActivated runs the then command and verification after Activate,
// and rolls back on failure. recovering is true when finishing a
// deployment from an earlier run.
func (t *targetRun) finishActivated(ctx context.Context, prevRef string, recovering bool) error {
	st, tj := t.st, t.tj
	if tj.Config.Then != nil {
		if err := t.runThen(ctx, st.Serial, "deploy"); err != nil {
			t.failStep(audit.StepThen, err)
			return t.rollback(ctx, prevRef, err, true)
		}
		_ = t.e.audit(t.entry(audit.StepThen, audit.ResultOK))
	}

	v := tj.Config.Verify
	if v == nil {
		t.log.Warn("no verify block for this target; the deployment is not checked")
		a := t.entry(audit.StepVerify, audit.ResultSkipped)
		a.Detail = "no verify block in config"
		_ = t.e.audit(a)
		t.recordSuccess(st.Serial, st.NotAfter, OutcomeUnverifiable)
		return nil
	}
	leaf, err := certutil.ParseLeaf(st.CertPEM)
	if err != nil {
		return t.rollback(ctx, prevRef, err, true)
	}
	if v.SkipChainValidation {
		t.log.Warn("chain validation is off for this target (verify.skip_chain_validation); only the served leaf is checked")
	}
	vreq := verify.Request{
		Host:                v.Host,
		Address:             v.DialAddress(),
		Expected:            leaf,
		Window:              tj.Window,
		Roots:               tj.Roots,
		SkipChainValidation: v.SkipChainValidation,
	}
	t.log.Info("verifying", "address", vreq.Address, "sni", vreq.Host, "window", vreq.Window)
	if err := t.e.Verifier.Verify(ctx, vreq); err != nil {
		if tj.Caps.PropagatesAsync {
			a := t.entry(audit.StepVerify, audit.ResultReported)
			a.Error = err.Error()
			a.Detail = "target propagates on its own schedule; not rolled back"
			_ = t.e.audit(a)
			t.log.Error("verification failed; not rolling back because this target propagates on its own schedule", "error", err)
			t.recordSuccess(st.Serial, st.NotAfter, OutcomeUnverifiable)
			ts := t.ts()
			ts.LastError = err.Error()
			t.setTS(ts)
			_ = t.save()
			return fmt.Errorf("verify (not rolled back): %w", err)
		}
		t.failStep(audit.StepVerify, err)
		return t.rollback(ctx, prevRef, err, true)
	}
	a := t.entry(audit.StepVerify, audit.ResultOK)
	if v.SkipChainValidation {
		a.Detail = "chain validation skipped by config"
	}
	if recovering {
		a.Detail = strings.TrimPrefix(a.Detail+"; finished an interrupted deployment", "; ")
	}
	_ = t.e.audit(a)
	t.log.Info("deployed and verified", "serial", st.Serial)
	t.recordSuccess(st.Serial, st.NotAfter, OutcomeVerified)
	return nil
}

// rollback undoes an activation and returns cause joined with any rollback
// error. It runs even if ctx is cancelled. It refuses to restore a
// certificate that expires within RollbackMinValidity, and cannot roll back
// without a previous ref.
//
// countFailure is false when undoing an interrupted run's deployment, which
// is not a failure of this target.
func (t *targetRun) rollback(ctx context.Context, prevRef string, cause error, countFailure bool) error {
	done := func(err error, outcome string) error {
		if countFailure {
			return t.recordFailure(err, outcome)
		}
		ts := t.ts()
		ts.endDeployment()
		t.setTS(ts)
		_ = t.save()
		return err
	}
	ts := t.ts()
	keepNew := func(why string) error {
		a := t.entry(audit.StepRollback, audit.ResultSkipped)
		a.Detail, a.Error = why, cause.Error()
		_ = t.e.audit(a)
		t.log.Error("not rolling back; the target keeps the new certificate, which failed its checks", "reason", why, "error", cause)
		// The target holds the new certificate now; record that so it is
		// not activated again on top of itself.
		ts.Serial, ts.NotAfter = ts.DeployingSerial, t.notAfter(ts.DeployingSerial)
		ts.endDeployment()
		ts.LastError = cause.Error()
		ts.Outcome = OutcomeFailed
		t.setTS(ts)
		_ = t.save()
		return fmt.Errorf("%w (not rolled back: %s)", cause, why)
	}

	switch {
	case !t.tj.Caps.SupportsRollback:
		return keepNew("target does not support rollback")
	case prevRef == "":
		return keepNew("the previous state is unknown (activation was interrupted, or the target reported no previous state)")
	case ts.Serial != "" && !ts.NotAfter.IsZero() && ts.NotAfter.Before(t.e.now().Add(RollbackMinValidity)):
		return keepNew(fmt.Sprintf("the previous certificate %s expires at %s", ts.Serial, ts.NotAfter.Format(time.RFC3339)))
	}

	a := t.entry(audit.StepRollback, audit.ResultOK)
	a.PreviousRef = prevRef
	req := plugin.RollbackRequest{
		Config: t.tj.Settings, PreviousRef: prevRef, CertificateID: strconv.Itoa(t.job.Cert.ID), Label: t.label(),
	}
	restores := ts.Serial
	if t.tj.Caps.RollbackNeedsMaterial {
		if ts.LiveBefore != "" {
			restores = ts.LiveBefore
		}
		if why := t.previousMaterial(ctx, &req, restores); why != "" {
			a.Detail = "previous certificate and key not available: " + why
			t.log.Warn("rolling back without the previous certificate and key", "reason", why)
		}
	}

	rctx, cancel := t.bg(ctx, t.rollbackTimeout())
	defer cancel()
	err := t.tj.Plugin.Rollback(rctx, req)
	if err != nil {
		a.Result, a.Error = audit.ResultFailed, err.Error()
		_ = t.e.audit(a)
		t.log.Error("rollback failed", "error", err)
		if cur := t.current(ctx); cur != "" && cur == ts.DeployingSerial {
			// The target still serves the certificate that failed its
			// checks. Record that, so the next deployment's previous
			// state matches the target.
			ts = t.ts()
			ts.Serial, ts.NotAfter = ts.DeployingSerial, t.notAfter(ts.DeployingSerial)
			t.setTS(ts)
		}
		return done(errors.Join(cause, fmt.Errorf("rollback failed: %w", err)), OutcomeFailed)
	}
	if restores != ts.Serial {
		// The target served something other than what the state said;
		// it serves that again now.
		ts = t.ts()
		ts.Serial, ts.NotAfter = restores, t.notAfter(restores)
		t.setTS(ts)
	}
	if t.tj.Config.Then != nil {
		if err := t.runThen(rctx, "", "rollback"); err != nil {
			a.Result, a.Error = audit.ResultFailed, err.Error()
			a.Detail = "files rolled back; then.exec failed afterwards"
			_ = t.e.audit(a)
			t.log.Error("rolled back, but then.exec failed afterwards", "error", err)
			return done(errors.Join(cause, fmt.Errorf("files rolled back, but then.exec failed afterwards: %w", err)), OutcomeRolledBack)
		}
	}
	_ = t.e.audit(a)
	t.log.Warn("rolled back to the previous certificate", "cause", cause)
	return done(fmt.Errorf("%w (rolled back)", cause), OutcomeRolledBack)
}

// rollbackTimeout is the engine's rollback timeout, or the plugin's call
// timeout when that is longer, so a slow target can finish.
func (t *targetRun) rollbackTimeout() time.Duration {
	timeout := t.e.RollbackTimeout
	if timeout == 0 {
		timeout = DefaultRollbackTimeout
	}
	if ct, ok := t.tj.Plugin.(interface{ CallTimeout() time.Duration }); ok {
		timeout = max(timeout, ct.CallTimeout())
	}
	return timeout
}

// previousMaterial fills req with the certificate the target served before
// (serial) and its key, exported in the target's format. It returns why it
// could not, or "". The export has its own short timeout and runs even if
// ctx is cancelled.
func (t *targetRun) previousMaterial(ctx context.Context, req *plugin.RollbackRequest, serial string) string {
	if t.tj.RollbackUnavailable != "" {
		return t.tj.RollbackUnavailable
	}
	if serial == "" {
		return "the connector has not deployed a certificate to this target before"
	}
	rec, ok := t.st.certRecord(serial)
	if !ok || rec.KeyRef == "" || rec.CertPEM == "" {
		return "the connector no longer holds certificate " + serial
	}
	if !rec.NotAfter.IsZero() && !rec.NotAfter.After(t.e.now()) {
		return "certificate " + serial + " has expired"
	}
	ectx, cancel := t.bg(ctx, time.Minute)
	defer cancel()
	key, err := t.job.KeyStore.Export(ectx, plugin.ExportRequest{Config: t.job.KeyStoreConfig, KeyRef: rec.KeyRef, Format: t.tj.Format})
	if err != nil {
		return "key store could not export its key: " + err.Error()
	}
	req.PreviousCertPEM, req.PreviousChainPEM, req.PreviousFullChainPEM = rec.CertPEM, rec.ChainPEM, rec.FullChainPEM
	req.PreviousKey, req.PreviousSerial = key, rec.Serial
	return ""
}

func (t *targetRun) runThen(ctx context.Context, serial, action string) error {
	run := t.e.RunThen
	if run == nil {
		run = execx.Run
	}
	env := execx.Env(
		"KK_ACTION="+action,
		"KK_CERT_ID="+strconv.Itoa(t.job.Cert.ID),
		"KK_CERT_SERIAL="+serial,
		"KK_TARGET_LABEL="+t.label(),
	)
	if err := run(ctx, t.tj.Config.Then.Exec, env, t.tj.Config.Then.Timeout); err != nil {
		return fmt.Errorf("then.exec: %w", err)
	}
	return nil
}
