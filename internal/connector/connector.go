// Package connector wires the config, plugins, API client and deploy
// engine together for the run and validate commands.
package connector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/krakenkey/connector/internal/api"
	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/deploy"
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
}

// CertReport describes one certificate after resolving and checking its
// plugins.
type CertReport struct {
	ID           int
	KeyStore     string
	KeyStoreCaps *plugin.KeyStoreCapabilities
	Problems     []string // key store problems
	Targets      []TargetReport
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

// BuildJob resolves a certificate's plugins, runs Describe and Validate,
// and matches capabilities. The job is usable only if report.OK().
func BuildJob(ctx context.Context, cert config.Certificate, r Resolver) (deploy.Job, *CertReport) {
	rep := &CertReport{ID: cert.ID, KeyStore: cert.KeyStore.Plugin}
	job := deploy.Job{Cert: cert, KeyStoreName: cert.KeyStore.Plugin}

	var ksCaps *plugin.KeyStoreCapabilities
	ks, err := r.KeyStore(cert.KeyStore.Plugin)
	if err == nil {
		job.KeyStore = ks
		var caps plugin.KeyStoreCapabilities
		if caps, err = ks.Describe(ctx); err == nil {
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

	for _, tc := range cert.Targets {
		tr := TargetReport{Label: tc.Label, Plugin: tc.Plugin}
		tj := deploy.TargetJob{Config: tc}
		problem := func(s string) { tr.Problems = append(tr.Problems, s) }

		t, err := r.Target(tc.Plugin)
		if err != nil {
			problem(err.Error())
			rep.Targets = append(rep.Targets, tr)
			continue
		}
		tj.Plugin = t
		if tj.Settings, err = tc.SettingsJSON(); err != nil {
			problem(err.Error())
		}
		caps, err := t.Describe(ctx)
		if err != nil {
			problem(err.Error())
			rep.Targets = append(rep.Targets, tr)
			continue
		}
		tj.Caps, tr.Caps = caps, &caps

		if problems, err := t.Validate(ctx, tj.Settings); err != nil {
			problem(err.Error())
		} else {
			for _, p := range problems {
				problem(p)
			}
		}
		if ksCaps != nil {
			if f, err := plugin.Match(*ksCaps, caps, cert.KeyStore.KeyType); err != nil {
				var inc *plugin.IncompatibleError
				if errors.As(err, &inc) {
					for _, reason := range inc.Reasons {
						problem("with key store " + cert.KeyStore.Plugin + ": " + reason)
					}
				} else {
					problem(err.Error())
				}
			} else {
				tj.Format, tr.Format = f, f
			}
		}
		if v := tc.Verify; v != nil {
			tj.Window = v.Window
			if tj.Window == 0 {
				tj.Window = caps.DefaultVerifyWindow
			}
			if tj.Window == 0 {
				tj.Window = config.DefaultVerifyWindow
			}
			tr.Window = tj.Window
			if v.CAFile != "" {
				roots, err := verify.LoadRoots(v.CAFile)
				if err != nil {
					problem("verify.ca_file: " + err.Error())
				}
				tj.Roots = roots
			}
		}
		rep.Targets = append(rep.Targets, tr)
		job.Targets = append(job.Targets, tj)
	}
	return job, rep
}

// Connector runs passes over the configured certificates.
type Connector struct {
	Config   *config.Config
	Resolver Resolver
	Engine   *deploy.Engine
	Log      *slog.Logger
}

// RunOptions change one pass.
type RunOptions struct {
	Force  bool
	CertID int // 0 means all
}

// RunOnce runs one pass. Certificates are independent: one failing does
// not stop the others, except for an authentication failure, which stops
// the pass at once.
func (c *Connector) RunOnce(ctx context.Context, opts RunOptions) error {
	runID := newRunID()
	log := c.Log.With("run_id", runID)
	log.Info("pass started", "certificates", len(c.Config.Certificates), "force", opts.Force, "only_certificate", opts.CertID)

	var errs []error
	for _, cert := range c.Config.Certificates {
		if opts.CertID != 0 && cert.ID != opts.CertID {
			continue
		}
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		job, rep := BuildJob(ctx, cert, c.Resolver)
		if !rep.OK() {
			err := fmt.Errorf("certificate %d: config problems, skipped (run validate for details): %s",
				cert.ID, firstProblem(rep))
			log.Error("certificate skipped", "certificate_id", cert.ID, "error", err)
			errs = append(errs, err)
			continue
		}
		err := c.Engine.Process(ctx, job, deploy.Options{RunID: runID, Force: opts.Force})
		if err != nil {
			log.Error("certificate failed", "certificate_id", cert.ID, "error", err)
			errs = append(errs, err)
			var authErr *api.AuthError
			if errors.As(err, &authErr) {
				break
			}
		}
	}
	if len(errs) == 0 {
		log.Info("pass finished")
	} else {
		log.Warn("pass finished with errors", "errors", len(errs))
	}
	return errors.Join(errs...)
}

// Run runs a pass now and then every check_interval until ctx is done or
// the API rejects the key.
func (c *Connector) Run(ctx context.Context) error {
	for {
		err := c.RunOnce(ctx, RunOptions{})
		var authErr *api.AuthError
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
