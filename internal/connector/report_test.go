package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/krakenkey/connector/internal/api"
	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/deploy"
	"github.com/krakenkey/connector/internal/pluginhost"
)

type sentReports struct {
	mu      sync.Mutex
	reports []api.Report
	result  *api.ReportResult
	err     error
}

func (s *sentReports) Report(_ context.Context, r api.Report) (*api.ReportResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports = append(s.reports, r)
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

func reportConfig(t *testing.T, dataDir string) *config.Config {
	return writeConfig(t, fmt.Sprintf(`
data_dir: %s
certificates:
  - id: 1
    names: [api.example.com]
    targets:
      - { label: staged, plugin: exec, command: [/bin/true] }
      - { label: activating, plugin: exec, command: [/bin/true] }
      - { label: verified, plugin: exec, command: [/bin/true], verify: { host: api.example.com } }
      - { label: unverified, plugin: exec, command: [/bin/true] }
      - { label: rolled-back, plugin: exec, command: [/bin/true] }
      - { label: failed-first, plugin: exec, command: [/bin/true] }
      - { label: behind, plugin: exec, command: [/bin/true], verify: { host: api.example.com } }
      - { label: old-state, plugin: exec, command: [/bin/true], verify: { host: api.example.com } }
      - { label: new, plugin: exec, command: [/bin/true] }
  - id: 2
    names: [www.example.com]
    targets:
      - { label: web, plugin: exec, command: [/bin/true] }
`, dataDir))
}

func TestReportMapsState(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	cfg := reportConfig(t, dataDir)
	store, err := deploy.OpenStateStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 10, 14, 0, 0, 0, time.UTC)
	_ = store.Save(&deploy.State{CertificateID: 1, Serial: "0b", UpdatedAt: at, Targets: map[string]deploy.TargetState{
		"staged":       {Serial: "0a", Phase: deploy.PhaseStaged, DeployingSerial: "0b", UpdatedAt: at},
		"activating":   {Serial: "0a", Phase: deploy.PhaseActivating, DeployingSerial: "0b", UpdatedAt: at},
		"verified":     {Serial: "0b", Outcome: deploy.OutcomeVerified, UpdatedAt: at},
		"unverified":   {Serial: "0b", Outcome: deploy.OutcomeUnverifiable, UpdatedAt: at},
		"rolled-back":  {Serial: "0a", Outcome: deploy.OutcomeRolledBack, Failures: 1, LastError: "verify: wrong leaf", UpdatedAt: at},
		"failed-first": {Outcome: deploy.OutcomeFailed, Failures: 2, LastError: "stage: permission denied", UpdatedAt: at},
		"behind":       {Serial: "0a", Outcome: deploy.OutcomeVerified, UpdatedAt: at},
		"old-state":    {Serial: "0b", UpdatedAt: at},
		"gone":         {Serial: "0b", UpdatedAt: at},
	}})
	r := &Reporter{Config: cfg, State: store, Log: slog.New(slog.DiscardHandler), Version: "1.2.3", OS: "linux", Arch: "arm64",
		Now: func() time.Time { return at.Add(time.Hour) }}
	reports := r.Build(map[int]error{1: nil, 2: errors.New("certificate 2: KrakenKey API: not found")}, nil)
	if len(reports) != 1 {
		t.Fatalf("%d reports", len(reports))
	}

	// The wire format, as the API contract has it.
	data, _ := json.Marshal(reports[0])
	var got map[string]any
	_ = json.Unmarshal(data, &got)
	want := map[string]any{
		"version": "1.2.3", "os": "linux", "arch": "arm64",
		"certificates": []any{
			map[string]any{"certificateId": 1.0, "targets": []any{
				map[string]any{"label": "staged", "state": "staged", "serial": "0b", "updatedAt": "2026-10-10T14:00:00.000Z"},
				map[string]any{"label": "activating", "state": "activated", "serial": "0b", "updatedAt": "2026-10-10T14:00:00.000Z"},
				map[string]any{"label": "verified", "state": "verified", "serial": "0b", "updatedAt": "2026-10-10T14:00:00.000Z"},
				map[string]any{"label": "unverified", "state": "activated_unverifiable", "serial": "0b", "updatedAt": "2026-10-10T14:00:00.000Z"},
				map[string]any{"label": "rolled-back", "state": "rolled_back", "serial": "0a", "error": "verify: wrong leaf", "updatedAt": "2026-10-10T14:00:00.000Z"},
				map[string]any{"label": "failed-first", "state": "failed", "error": "stage: permission denied", "updatedAt": "2026-10-10T14:00:00.000Z"},
				map[string]any{"label": "behind", "state": "pending", "serial": "0a", "updatedAt": "2026-10-10T14:00:00.000Z"},
				map[string]any{"label": "old-state", "state": "verified", "serial": "0b", "updatedAt": "2026-10-10T14:00:00.000Z"},
				map[string]any{"label": "new", "state": "pending", "updatedAt": "2026-10-10T14:00:00.000Z"},
			}},
			map[string]any{"certificateId": 2.0, "targets": []any{
				map[string]any{"label": "web", "state": "pending", "error": "certificate 2: KrakenKey API: not found", "updatedAt": "2026-10-10T15:00:00.000Z"},
			}},
		},
	}
	gotJSON, _ := json.MarshalIndent(got, "", " ")
	wantJSON, _ := json.MarshalIndent(want, "", " ")
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("report:\n%s\nwant:\n%s", gotJSON, wantJSON)
	}
}

func TestSanitizeError(t *testing.T) {
	dataDir := "/var/lib/krakenkey-connector"
	in := "exec: exit 1: -----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMG\n-----END PRIVATE KEY-----\n" +
		"bearer kk_secretsecret123 token kkce_enrollenroll456 file " + filepath.Join(dataDir, "exec", "1043", "key.pem") +
		"\r\n\tdone\x00"
	out := SanitizeError(in, dataDir)
	for _, leak := range []string{"MIGHAgEAMBMG", "secretsecret123", "enrollenroll456", dataDir, "\n", "\t", "\x00"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q survived: %q", leak, out)
		}
	}
	if !strings.Contains(out, "<data_dir>/exec/1043/key.pem") || !strings.HasSuffix(out, "done") {
		t.Errorf("sanitised: %q", out)
	}

	// Length is counted in UTF-16 code units, as the API counts it.
	long := strings.Repeat("é😀x ", 100)
	out = SanitizeError(long, "")
	if n := len(utf16.Encode([]rune(out))); n > api.MaxReportError || n < api.MaxReportError-4 || !strings.HasSuffix(out, "...") {
		t.Errorf("truncated to %d units: %q", n, out)
	}
	if SanitizeError("", dataDir) != "" || SanitizeError("short", dataDir) != "short" {
		t.Error("short strings changed")
	}
}

func TestReportLimits(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	var b strings.Builder
	fmt.Fprintf(&b, "data_dir: %s\ncertificates:\n", dataDir)
	for id := 1; id <= 501; id++ {
		fmt.Fprintf(&b, "  - id: %d\n    names: [api.example.com]\n    targets:\n", id)
		n := 1
		if id == 1 {
			n = 51
		}
		for i := range n {
			fmt.Fprintf(&b, "      - { label: t%d, plugin: exec, command: [/bin/true] }\n", i)
		}
	}
	cfg := writeConfig(t, b.String())
	store, _ := deploy.OpenStateStore(dataDir)
	r := &Reporter{Config: cfg, State: store, Log: slog.New(slog.DiscardHandler)}
	all := map[int]error{}
	for _, c := range cfg.Certificates {
		all[c.ID] = nil
	}
	reports := r.Build(all, nil)
	if len(reports) != 2 || len(reports[0].Certificates) != 500 || len(reports[1].Certificates) != 1 {
		t.Fatalf("split into %d reports", len(reports))
	}
	if n := len(reports[0].Certificates[0].Targets); n != api.MaxReportTargets {
		t.Errorf("%d targets reported, want %d", n, api.MaxReportTargets)
	}
	if reports[1].Certificates[0].CertificateID != 501 {
		t.Errorf("second report holds %d", reports[1].Certificates[0].CertificateID)
	}
}

func TestReportIsSentAfterEveryPassButNeverFailsIt(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	cfg := writeConfig(t, fmt.Sprintf(`
data_dir: %s
certificates:
  - id: 1
    names: [api.example.com]
    targets: [{ label: hook, plugin: exec, command: [/bin/true] }]
`, dataDir))
	store, _ := deploy.OpenStateStore(dataDir)
	log := slog.New(slog.DiscardHandler)
	cases := map[string]struct {
		apiErr    error
		reportErr error
		reported  bool
	}{
		"failed pass":      {apiErr: &api.NotFoundError{Message: "x"}, reported: true},
		"report fails":     {apiErr: &api.NotFoundError{Message: "x"}, reportErr: errors.New("boom"), reported: true},
		"key refused":      {apiErr: &api.AuthError{Message: "x"}},
		"identity refused": {apiErr: &api.ConnectorAuthError{Message: "x"}},
		"rate limited":     {apiErr: &api.RateLimitError{RetryAfter: time.Hour}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			sent := &sentReports{err: c.reportErr}
			conn := &Connector{
				Config: cfg, Resolver: newResolver(t, cfg, log), Log: log,
				Engine:   &deploy.Engine{API: failingAPI{c.apiErr}, State: store, Log: log},
				Reporter: &Reporter{API: sent, Config: cfg, State: store, Log: log},
			}
			err := conn.RunOnce(context.Background(), RunOptions{})
			if !errors.Is(err, c.apiErr) {
				t.Errorf("pass result changed: %v", err)
			}
			if got := len(sent.reports) > 0; got != c.reported {
				t.Errorf("reported %v, want %v", got, c.reported)
			}
			if c.reported && sent.reports[0].Certificates[0].Targets[0].Error == "" {
				t.Error("pass error not in the report")
			}
		})
	}
}

func newResolver(t *testing.T, cfg *config.Config, log *slog.Logger) Resolver {
	h := pluginhost.New(cfg, log)
	t.Cleanup(h.Close)
	return h
}

// failingAPI fails every call with err.
type failingAPI struct{ err error }

func (f failingAPI) GetCert(context.Context, int) (*api.Cert, error) { return nil, f.err }
func (f failingAPI) RenewCert(context.Context, int, string) (*api.CertResponse, error) {
	return nil, f.err
}
func (f failingAPI) WaitForIssuance(context.Context, int, string) (*api.Cert, error) {
	return nil, f.err
}
func (f failingAPI) GetCertChain(context.Context, int) (*api.Chain, error) { return nil, f.err }

func TestReportBlockedFailures(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	cfg := writeConfig(t, fmt.Sprintf(`
data_dir: %s
certificates:
  - id: 1
    names: [api.example.com]
    targets:
      - { label: live, plugin: exec, command: [/bin/true] }
      - { label: staged, plugin: exec, command: [/bin/true] }
      - { label: none, plugin: exec, command: [/bin/true] }
  - id: 2
    names: [api.example.com]
    targets: [{ label: other, plugin: exec, command: [/bin/true] }]
`, dataDir))
	store, _ := deploy.OpenStateStore(dataDir)
	at := time.Date(2026, 10, 10, 14, 0, 0, 0, time.UTC)
	_ = store.Save(&deploy.State{CertificateID: 1, Serial: "0a", Targets: map[string]deploy.TargetState{
		"live":   {Serial: "0a", Outcome: deploy.OutcomeVerified, UpdatedAt: at},
		"staged": {Serial: "0a", Phase: deploy.PhaseStaged, DeployingSerial: "0b", UpdatedAt: at},
	}})
	r := &Reporter{Config: cfg, State: store, Log: slog.New(slog.DiscardHandler)}

	type want struct{ state, serial string }
	cases := map[string]struct {
		err  error
		want map[string]want
	}{
		"key store failure": {
			fmt.Errorf("certificate 1: %w", &deploy.BlockedError{Err: errors.New("key store: vault sealed")}),
			map[string]want{"live": {"failed", "0a"}, "staged": {"staged", "0b"}, "none": {"failed", ""}},
		},
		"issued certificate rejected": {
			fmt.Errorf("certificate 1: %w", &deploy.RejectedError{Reason: "wrong names"}),
			map[string]want{"live": {"failed", "0a"}, "staged": {"staged", "0b"}, "none": {"failed", ""}},
		},
		"issuance failed in KrakenKey": {
			fmt.Errorf("certificate 1: %w", &api.IssuanceFailedError{Reason: "CNAME missing"}),
			map[string]want{"live": {"verified", "0a"}, "staged": {"staged", "0b"}, "none": {"pending", ""}},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			reports := r.Build(map[int]error{1: c.err}, nil)
			if len(reports) != 1 || len(reports[0].Certificates) != 1 {
				t.Fatalf("report holds certificates that were not processed: %+v", reports)
			}
			for _, tg := range reports[0].Certificates[0].Targets {
				w := c.want[tg.Label]
				if tg.State != w.state || tg.Serial != w.serial {
					t.Errorf("%s: %s %q, want %s %q", tg.Label, tg.State, tg.Serial, w.state, w.serial)
				}
				if (tg.State == "failed" || tg.State == "pending") && tg.Error == "" {
					t.Errorf("%s: no error", tg.Label)
				}
			}
		})
	}
	if reports := r.Build(map[int]error{}, nil); len(reports) != 0 {
		t.Errorf("a pass that processed nothing reported %+v", reports)
	}
}
