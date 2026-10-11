// Package connector wires the config, plugins, API client and deploy
// engine together for the run and validate commands.
package connector

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/krakenkey/connector/internal/api"
	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/deploy"
	execTarget "github.com/krakenkey/connector/internal/target/exec"
	"github.com/krakenkey/connector/internal/verify"
	"github.com/krakenkey/connector/pkg/plugin"
)

// Resolver turns plugin names into implementations.
type Resolver interface {
	KeyStore(name string) (plugin.KeyStore, error)
	Target(name string) (plugin.Target, error)
}

// TargetReport describes one target after resolving and checking it.
type TargetReport struct {
	Label    string
	Plugin   string
	Caps     *plugin.TargetCapabilities
	Format   plugin.KeyFormat
	Window   time.Duration
	Problems []string
	// Warnings do not stop deployments.
	Warnings []string
	// RollbackUnavailable says why a failed deployment to this target
	// cannot be rolled back with this key store, or is empty.
	RollbackUnavailable string
	// Implicit is true for the target the key store added by itself.
	Implicit bool
	// KeyStoreDeployment is true for the key store's own deployment: the
	// implicit target, or the configured target that replaced it.
	KeyStoreDeployment bool
}

// CertReport describes one certificate after resolving and checking its
// plugins.
type CertReport struct {
	ID           int
	KeyStore     string
	KeyStoreCaps *plugin.KeyStoreCapabilities
	Problems     []string // key store problems
	// Targets are the certificate's targets in deployment order, including
	// one the key store added (see plugin.ImplicitTarget). They line up
	// with the Job's Cert.Targets.
	Targets []TargetReport
}

// OK reports whether the certificate and all its targets are usable.
func (r *CertReport) OK() bool {
	if len(r.Problems) > 0 {
		return false
	}
	for _, t := range r.Targets {
		if len(t.Problems) > 0 {
			return false
		}
	}
	return true
}

// checkedTarget is a target after Describe and Validate, before it is
// matched with the key store.
type checkedTarget struct {
	tr           TargetReport
	tj           deploy.TargetJob
	caps         *plugin.TargetCapabilities
	deploymentID string
}

func (c *checkedTarget) problem(s string) { c.tr.Problems = append(c.tr.Problems, s) }

// BuildJob resolves a certificate's plugins, runs Describe and Validate,
// and matches capabilities. The job is usable only if report.OK().
//
// A key store can add a target by itself (plugin.ImplicitTarget): it is
// served by the key store's plugin and labeled with the plugin's name
// (config.ImplicitTargetLabel). A configured target of that plugin whose
// Validate reports the same deployment id takes its place. The job's
// Cert.Targets list the targets in deployment order, the implicit one
// first.
func BuildJob(ctx context.Context, cert config.Certificate, r Resolver) (deploy.Job, *CertReport) {
	rep := &CertReport{ID: cert.ID, KeyStore: cert.KeyStore.Plugin}
	job := deploy.Job{Cert: cert, KeyStoreName: cert.KeyStore.Plugin}
	certID := strconv.Itoa(cert.ID)

	var ksCaps *plugin.KeyStoreCapabilities
	ks, err := r.KeyStore(cert.KeyStore.Plugin)
	if err == nil {
		job.KeyStore = ks
		var caps plugin.KeyStoreCapabilities
		if caps, err = ks.Describe(ctx); err == nil {
			// An implicit target depends on the settings; Describe has
			// none.
			caps.ImplicitTarget = nil
			ksCaps = &caps
			rep.KeyStoreCaps = ksCaps
		}
	}
	if err != nil {
		rep.Problems = append(rep.Problems, err.Error())
	}
	if job.KeyStoreConfig, err = cert.KeyStore.SettingsJSON(); err != nil {
		rep.Problems = append(rep.Problems, err.Error())
	}
	var implicit *plugin.ImplicitTarget
	if ks != nil && ksCaps != nil {
		v, err := plugin.ValidateKeyStore(ctx, ks, plugin.KeyStoreValidateRequest{Config: job.KeyStoreConfig, CertificateID: certID})
		switch {
		case plugin.IsUnsupported(err):
		case err != nil:
			rep.Problems = append(rep.Problems, err.Error())
		default:
			rep.Problems = append(rep.Problems, v.Problems...)
			if v.Capabilities != nil {
				// What this certificate's settings allow, which can be
				// less than the key store's general capabilities.
				ksCaps = v.Capabilities
				rep.KeyStoreCaps = ksCaps
				implicit = ksCaps.ImplicitTarget
			}
		}
	}
	if implicit != nil && implicit.DeploymentID == "" {
		rep.Problems = append(rep.Problems, "key store "+cert.KeyStore.Plugin+" adds a target without saying where it deploys (no deployment id); it is ignored")
		implicit = nil
	}
	ksDeploymentID := ""
	if implicit != nil {
		ksDeploymentID = implicit.DeploymentID
	}

	check := func(tc config.Target) *checkedTarget {
		c := &checkedTarget{tr: TargetReport{Label: tc.Label, Plugin: tc.Plugin, Implicit: tc.Implicit}, tj: deploy.TargetJob{Config: tc}}
		t, err := r.Target(tc.Plugin)
		if err != nil {
			c.problem(err.Error())
			return c
		}
		c.tj.Plugin = t
		if c.tj.Settings, err = tc.SettingsJSON(); err != nil {
			c.problem(err.Error())
		}
		caps, err := t.Describe(ctx)
		if err != nil {
			c.problem(err.Error())
			return c
		}
		c.caps = &caps
		req := plugin.TargetValidateRequest{Config: c.tj.Settings, CertificateID: certID, Label: tc.Label}
		if tc.Plugin == cert.KeyStore.Plugin {
			req.KeyStoreDeploymentID = ksDeploymentID
		}
		v, err := plugin.ValidateTarget(ctx, t, req)
		if err != nil {
			c.problem(err.Error())
		}
		for _, p := range v.Problems {
			c.problem(p)
		}
		c.deploymentID = v.DeploymentID
		return c
	}

	var targets []*checkedTarget
	for _, tc := range cert.Targets {
		targets = append(targets, check(tc))
	}

	// Two targets that deploy to the same place would undo each other.
	for i, a := range targets {
		for _, b := range targets[:i] {
			if a.deploymentID != "" && a.deploymentID == b.deploymentID && a.tr.Plugin == b.tr.Plugin {
				a.problem("deploys to the same place as target " + b.tr.Label + "; list it once")
				break
			}
		}
	}

	if implicit != nil {
		label := config.ImplicitTargetLabel(cert.KeyStore.Plugin)
		replaced := false
		for _, c := range targets {
			switch {
			case c.tr.Plugin == cert.KeyStore.Plugin && c.deploymentID == implicit.DeploymentID:
				// The configured target is the key store's own
				// deployment, for example with a verify block.
				replaced = true
				c.tr.KeyStoreDeployment = true
				c.tj.Config.KeyStoreDeployment = true
			case c.tr.Label == label:
				c.problem(fmt.Sprintf("label %q is taken by the target key store %s adds by itself, and this target deploys somewhere else; use another label",
					label, cert.KeyStore.Plugin))
			}
		}
		if !replaced {
			tc := config.Target{Label: label, Plugin: cert.KeyStore.Plugin, Implicit: true, KeyStoreDeployment: true}
			var settingsErr error
			tc.Settings, settingsErr = implicitSettings(implicit.Config)
			c := check(tc)
			c.tr.KeyStoreDeployment = true
			if settingsErr != nil {
				c.problem("settings from key store " + cert.KeyStore.Plugin + ": " + settingsErr.Error())
			}
			if c.deploymentID != "" && c.deploymentID != implicit.DeploymentID {
				c.problem(fmt.Sprintf("the target reports deployment id %q for the settings key store %s gave it, not %q",
					c.deploymentID, cert.KeyStore.Plugin, implicit.DeploymentID))
			}
			// The key store has made the certificate live by the time any
			// target is deployed, so this one goes first.
			targets = append([]*checkedTarget{c}, targets...)
		}
	}

	if len(targets) == 0 {
		rep.Problems = append(rep.Problems, "targets must list at least one target (key store "+cert.KeyStore.Plugin+" adds none by itself)")
	}

	job.Cert.Targets = make([]config.Target, 0, len(targets))
	for _, c := range targets {
		job.Cert.Targets = append(job.Cert.Targets, c.tj.Config)
		if c.caps == nil {
			rep.Targets = append(rep.Targets, c.tr)
			continue
		}
		matchTarget(cert, ksCaps, c)
		rep.Targets = append(rep.Targets, c.tr)
		job.Targets = append(job.Targets, c.tj)
	}
	return job, rep
}

// matchTarget matches a checked target with the key store and resolves
// its then and verify settings.
func matchTarget(cert config.Certificate, ksCaps *plugin.KeyStoreCapabilities, c *checkedTarget) {
	tc, caps := c.tj.Config, *c.caps
	c.tj.Caps, c.tr.Caps = caps, c.caps
	if ksCaps != nil {
		match, rollbackUnavailable := plugin.Match, plugin.RollbackUnavailable
		if tc.KeyStoreDeployment {
			match, rollbackUnavailable = plugin.MatchKeyStoreDeployment, plugin.KeyStoreDeploymentRollbackUnavailable
		}
		if f, err := match(*ksCaps, caps, cert.KeyStore.KeyType); err != nil {
			var inc *plugin.IncompatibleError
			if errors.As(err, &inc) {
				for _, reason := range inc.Reasons {
					c.problem("with key store " + cert.KeyStore.Plugin + ": " + reason)
				}
			} else {
				c.problem(err.Error())
			}
		} else {
			c.tj.Format, c.tr.Format = f, f
			if why := rollbackUnavailable(*ksCaps, caps, f); why != "" && caps.SupportsRollback {
				c.tj.RollbackUnavailable, c.tr.RollbackUnavailable = why, why
				c.tr.Warnings = append(c.tr.Warnings, "rollback is unavailable: "+why+
					". If a deployment fails its checks, the connector still calls the target's rollback without the previous key; the target refuses it, the failed rollback is reported, and the target keeps the new certificate")
			}
		}
	}
	if tc.Then != nil {
		if p := execTarget.CommandProblem(tc.Then.Exec); p != "" {
			c.problem("then.exec: " + p)
		}
	}
	if v := tc.Verify; v != nil {
		c.tj.Window = v.Window
		if c.tj.Window == 0 {
			c.tj.Window = caps.DefaultVerifyWindow
		}
		if c.tj.Window == 0 {
			c.tj.Window = config.DefaultVerifyWindow
		}
		c.tr.Window = c.tj.Window
		if v.CAFile != "" {
			roots, err := verify.LoadRoots(v.CAFile)
			if err != nil {
				c.problem("verify.ca_file: " + err.Error())
			}
			c.tj.Roots = roots
		}
	}
}

// implicitSettings decodes the settings a key store gives its implicit
// target, keeping numbers as they were written.
func implicitSettings(raw json.RawMessage) (map[string]any, error) {
	m := map[string]any{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return m, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return map[string]any{}, fmt.Errorf("not a JSON object: %w", err)
	}
	return m, nil
}

// Connector runs passes over the configured certificates.
type Connector struct {
	Config   *config.Config
	Resolver Resolver
	Engine   *deploy.Engine
	Log      *slog.Logger
	// Reporter sends the deployment status after each pass. It is set only
	// for an enrolled connector: KrakenKey takes reports only with keys
	// issued to a connector.
	Reporter *Reporter
}

// RunOptions change one pass.
type RunOptions struct {
	Force  bool
	CertID int // 0 means all
}

// RunOnce runs one pass. Certificates are independent: one failing does
// not stop the others, except for an authentication failure or a rate
// limit the client could not wait out, which stop the pass at once.
func (c *Connector) RunOnce(ctx context.Context, opts RunOptions) error {
	runID := newRunID()
	log := c.Log.With("run_id", runID)
	log.Info("pass started", "certificates", len(c.Config.Certificates), "force", opts.Force, "only_certificate", opts.CertID)

	var errs []error
	// results holds every certificate this pass processed: its error, or
	// nil. The status report covers these certificates only.
	results := map[int]error{}
	// effective holds each processed certificate with the targets its
	// key store added, for the status report.
	effective := map[int]config.Certificate{}
	for _, cert := range c.Config.Certificates {
		if opts.CertID != 0 && cert.ID != opts.CertID {
			continue
		}
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		job, rep := BuildJob(ctx, cert, c.Resolver)
		effective[cert.ID] = job.Cert
		if !rep.OK() {
			err := &deploy.BlockedError{Err: fmt.Errorf("certificate %d: config problems, skipped (run validate for details): %s",
				cert.ID, firstProblem(rep))}
			log.Error("certificate skipped", "certificate_id", cert.ID, "error", err)
			errs = append(errs, err)
			results[cert.ID] = err
			continue
		}
		err := c.Engine.Process(ctx, job, deploy.Options{RunID: runID, Force: opts.Force})
		results[cert.ID] = err
		if err != nil {
			log.Error("certificate failed", "certificate_id", cert.ID, "error", err)
			errs = append(errs, err)
			if stopsPass(err) {
				break
			}
		}
	}
	if len(errs) == 0 {
		log.Info("pass finished")
	} else {
		log.Warn("pass finished with errors", "errors", len(errs))
	}
	err := errors.Join(errs...)
	c.report(ctx, log, results, effective, err)
	return err
}

// report sends the deployment status, if the connector is enrolled and the
// pass did not stop because KrakenKey refused the credentials or asked the
// connector to back off. It never changes the result of the pass.
func (c *Connector) report(ctx context.Context, log *slog.Logger, results map[int]error, certs map[int]config.Certificate, passErr error) {
	switch {
	case c.Reporter == nil:
		log.Debug("deployment status not reported: the connector is not enrolled")
	case stopsPass(passErr):
		log.Warn("deployment status not reported: the pass stopped early", "error", passErr)
	default:
		c.Reporter.Send(ctx, results, certs)
	}
}

// Run runs a pass now and then every check_interval until ctx is done or
// the API rejects the key or the connector's identity.
func (c *Connector) Run(ctx context.Context) error {
	for {
		err := c.RunOnce(ctx, RunOptions{})
		var authErr *api.AuthError
		var connAuthErr *api.ConnectorAuthError
		if errors.As(err, &connAuthErr) {
			return connAuthErr
		}
		if errors.As(err, &authErr) {
			return authErr
		}
		next := time.Now().Add(c.Config.CheckInterval)
		c.Log.Info("next pass scheduled", "at", next.Format(time.RFC3339))
		t := time.NewTimer(c.Config.CheckInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

// stopsPass reports whether err should end the pass: the API key or the
// connector's identity was rejected, or KrakenKey asked the connector to
// back off.
func stopsPass(err error) bool {
	var authErr *api.AuthError
	var connAuthErr *api.ConnectorAuthError
	var rl *api.RateLimitError
	return errors.As(err, &authErr) || errors.As(err, &connAuthErr) || errors.As(err, &rl)
}

func firstProblem(r *CertReport) string {
	if len(r.Problems) > 0 {
		return r.Problems[0]
	}
	for _, t := range r.Targets {
		if len(t.Problems) > 0 {
			return "target " + t.Label + ": " + t.Problems[0]
		}
	}
	return ""
}

func newRunID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}
