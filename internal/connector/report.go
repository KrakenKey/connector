package connector

import (
	"context"
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/krakenkey/connector/internal/api"
	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/deploy"
	"github.com/krakenkey/connector/internal/redact"
)

// ReportSender is the API call the reporter uses.
type ReportSender interface {
	Report(ctx context.Context, r api.Report) (*api.ReportResult, error)
}

// ReportTimeout bounds sending a report. It runs even when the pass was
// cancelled, so a stopping connector still says where it left off.
const ReportTimeout = 10 * time.Second

// Reporter sends the deployment status of the certificates a pass
// processed, and all their targets, to KrakenKey. The state store is the
// source: what is deployed where, and how the last deployment ended.
//
// Failures on the connector's side that kept a certificate from being
// renewed or deployed (deploy.IsBlocked: key store errors, config
// problems, an issued certificate the checks rejected) show as failed on
// every target of that certificate, so KrakenKey alerts. Failures on
// KrakenKey's side, such as a failed issuance, leave targets pending with
// the error: KrakenKey alerts on those itself.
type Reporter struct {
	API    ReportSender
	State  *deploy.StateStore
	Config *config.Config
	Log    *slog.Logger
	// Version, OS and Arch describe the connector.
	Version, OS, Arch string
	// Now defaults to time.Now.
	Now func() time.Time
}

func (r *Reporter) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Send builds the reports and sends them. Failures are logged, never
// returned: reporting must not fail a pass. results holds every
// certificate the pass processed, with its error or nil.
func (r *Reporter) Send(ctx context.Context, results map[int]error) {
	reports := r.Build(results)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ReportTimeout)
	defer cancel()
	var rejected []int
	for _, rep := range reports {
		res, err := r.API.Report(ctx, rep)
		if err != nil {
			r.Log.Warn("could not report deployment status to KrakenKey", "error", err)
			return
		}
		if res != nil {
			rejected = append(rejected, res.RejectedCertificateIDs...)
		}
	}
	if len(rejected) > 0 {
		r.Log.Warn("KrakenKey did not take the status of some certificates: this connector is not allowed to manage them; "+
			"check the certificate ids in the config and the connector's restrictions in the dashboard",
			"certificate_ids", rejected)
	}
	r.Log.Debug("deployment status reported", "certificates", len(results))
}

// Build returns the reports for the certificates in results, in config
// order, split so that none has more than api.MaxReportCertificates
// certificates.
func (r *Reporter) Build(results map[int]error) []api.Report {
	var certs []api.ReportCertificate
	for _, cert := range r.Config.Certificates {
		certErr, processed := results[cert.ID]
		if !processed {
			continue
		}
		certs = append(certs, r.certificate(cert, certErr))
	}
	var reports []api.Report
	for len(certs) > 0 {
		n := min(len(certs), api.MaxReportCertificates)
		reports = append(reports, api.Report{Version: r.Version, OS: r.OS, Arch: r.Arch, Certificates: certs[:n]})
		certs = certs[n:]
	}
	return reports
}

func (r *Reporter) certificate(cert config.Certificate, certErr error) api.ReportCertificate {
	st, err := r.State.Load(cert.ID)
	if err != nil {
		r.Log.Warn("cannot read state for the status report", "certificate_id", cert.ID, "error", err)
		st = nil
	}
	if st == nil {
		st = &deploy.State{CertificateID: cert.ID}
	}
	targets := cert.Targets
	if len(targets) > api.MaxReportTargets {
		r.Log.Warn("the status report includes only the first targets of this certificate",
			"certificate_id", cert.ID, "targets", len(targets), "reported", api.MaxReportTargets)
		targets = targets[:api.MaxReportTargets]
	}
	rc := api.ReportCertificate{CertificateID: cert.ID, Targets: []api.ReportTarget{}}
	for _, tc := range targets {
		rc.Targets = append(rc.Targets, r.target(st, tc, certErr))
	}
	return rc
}

// target maps one target's state to the API's deployment states.
func (r *Reporter) target(st *deploy.State, tc config.Target, certErr error) api.ReportTarget {
	ts, known := st.Targets[tc.Label]
	rt := api.ReportTarget{Label: tc.Label, Serial: ts.Serial}
	updated := ts.UpdatedAt

	switch {
	case ts.Phase == deploy.PhaseStaged:
		rt.State, rt.Serial = api.DeployStaged, ts.DeployingSerial
	case ts.Phase == deploy.PhaseActivating || ts.Phase == deploy.PhaseActivated:
		rt.State, rt.Serial = api.DeployActivated, ts.DeployingSerial
	case ts.Outcome == deploy.OutcomeFailed || ts.Outcome == deploy.OutcomeRolledBack:
		rt.State, rt.Error = ts.Outcome, ts.LastError
	case ts.Serial == "":
		rt.State = api.DeployPending
	case st.Serial != "" && ts.Serial != st.Serial:
		// The target still serves an older certificate; the current one
		// is waiting to be deployed there.
		rt.State = api.DeployPending
	case ts.Outcome == deploy.OutcomeUnverifiable:
		rt.State, rt.Error = api.DeployActivatedUnverifiable, ts.LastError
	case ts.Outcome == deploy.OutcomeVerified:
		rt.State = api.DeployVerified
	case tc.Verify == nil:
		// State from before outcomes were recorded.
		rt.State = api.DeployActivatedUnverifiable
	default:
		rt.State = api.DeployVerified
	}
	switch {
	case certErr == nil:
	case deploy.IsBlocked(certErr) && rt.State != api.DeployStaged && rt.State != api.DeployActivated:
		// The certificate could not be renewed or deployed because of
		// something on the connector's side; the target keeps whatever it
		// has (rt.Serial).
		rt.State, rt.Error, updated = api.DeployFailed, certErr.Error(), r.now()
	case rt.State == api.DeployPending:
		rt.Error, updated = certErr.Error(), r.now()
	}
	if !known && updated.IsZero() {
		updated = st.UpdatedAt
	}
	if updated.IsZero() {
		updated = r.now()
	}
	rt.UpdatedAt = api.ReportTime(updated)
	if !serialRe.MatchString(rt.Serial) {
		rt.Serial = ""
	}
	rt.Error = SanitizeError(rt.Error, r.Config.DataDir)
	return rt
}

var serialRe = regexp.MustCompile(`^[0-9a-fA-F]{0,64}$`)

// SanitizeError makes error text fit for the status report: secrets
// removed (private keys, API keys, enrolment tokens), paths under the
// data directory shortened, control characters and runs of white space
// collapsed, and at most api.MaxReportError characters (UTF-16 code units,
// as the API counts them).
func SanitizeError(s, dataDir string) string {
	if s == "" {
		return ""
	}
	s = redact.String(s)
	if dataDir != "" {
		dir := filepath.Clean(dataDir)
		s = strings.ReplaceAll(s, dir+string(filepath.Separator), "<data_dir>"+string(filepath.Separator))
		s = strings.ReplaceAll(s, dir, "<data_dir>")
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")

	const ellipsis = "..."
	if utf16Len(s) <= api.MaxReportError {
		return s
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		w := utf16.RuneLen(r)
		if w < 1 {
			w = 1
		}
		if n+w > api.MaxReportError-len(ellipsis) {
			break
		}
		b.WriteRune(r)
		n += w
	}
	return strings.TrimRight(b.String(), " ") + ellipsis
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		w := utf16.RuneLen(r)
		if w < 1 {
			w = 1
		}
		n += w
	}
	return n
}
