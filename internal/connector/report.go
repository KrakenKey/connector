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
	Report(ctx context.Context, r api.Report) error
}

// ReportTimeout bounds sending a report. It runs even when the pass was
// cancelled, so a stopping connector still says where it left off.
const ReportTimeout = 10 * time.Second

// Reporter sends the deployment status of every configured certificate and
// target to KrakenKey after each pass. The state store is the source: what
// is deployed where, and how the last deployment ended.
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
// returned: reporting must not fail a pass. certErrs holds this pass's
// error per certificate, shown for targets that are still waiting for
// their first deployment.
func (r *Reporter) Send(ctx context.Context, certErrs map[int]error) {
	reports := r.Build(certErrs)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ReportTimeout)
	defer cancel()
	for _, rep := range reports {
		if err := r.API.Report(ctx, rep); err != nil {
			r.Log.Warn("could not report deployment status to KrakenKey", "error", err)
			return
		}
	}
	r.Log.Debug("deployment status reported", "certificates", len(r.Config.Certificates))
}

// Build returns the reports for every configured certificate, split so
// that none has more than api.MaxReportCertificates certificates.
func (r *Reporter) Build(certErrs map[int]error) []api.Report {
	var certs []api.ReportCertificate
	for _, cert := range r.Config.Certificates {
		certs = append(certs, r.certificate(cert, certErrs[cert.ID]))
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
	if rt.State == api.DeployPending && certErr != nil {
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
