// Package exec is the built-in target that hands a certificate to a
// command you provide.
//
// Stage writes the certificate, chain, full chain and key to a new
// directory under <data_dir>/exec/<certificate id>-<label>/ (mode 0700,
// files 0600). Activate runs the command with these environment variables:
//
//	KK_ACTION          deploy, or rollback when restoring the previous files
//	KK_CERT_FILE       leaf certificate, PEM
//	KK_CHAIN_FILE      intermediates, PEM
//	KK_FULLCHAIN_FILE  leaf and intermediates, PEM
//	KK_KEY_FILE        private key, PEM
//	KK_CERT_SERIAL     leaf serial number, lowercase hex
//	KK_CERT_ID         KrakenKey certificate id
//	KK_TARGET_LABEL    target label
//
// A non-zero exit fails the deployment; the command is then run again with
// the previous files (KK_ACTION=rollback), if there are any.
//
// Retention: the files of the current and the previous deployment are kept
// (each with its private key) so Rollback can run the command again with
// the previous files. Older deployment directories, and staged directories
// that were never activated, are removed at the next Stage or Activate.
package exec

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	osexec "os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/krakenkey/connector/internal/execx"
	"github.com/krakenkey/connector/internal/securefs"
	"github.com/krakenkey/connector/pkg/plugin"
)

// DefaultTimeout bounds one run of the command.
const DefaultTimeout = 5 * time.Minute

// Config is the exec target's settings.
type Config struct {
	// Command is the program and its arguments. No shell is involved. The
	// program is an absolute path or a bare name looked up in PATH.
	Command []string `json:"command"`
	// Timeout is a Go duration string such as "2m". Default 5m.
	Timeout string `json:"timeout,omitempty"`
	// Env adds environment variables for the command.
	Env map[string]string `json:"env,omitempty"`
}

// Target is the exec target.
type Target struct {
	root string // <data_dir>/exec
}

var _ plugin.Target = (*Target)(nil)

// New returns an exec target that keeps its files under dataDir/exec.
func New(dataDir string) *Target {
	return &Target{root: filepath.Join(dataDir, "exec")}
}

// Describe reports a PEM target with rollback.
func (t *Target) Describe(context.Context) (plugin.TargetCapabilities, error) {
	return plugin.TargetCapabilities{
		Accepts:            []plugin.KeyFormat{plugin.KeyFormatPEM},
		NeedsExportableKey: true,
		SupportsRollback:   true,
	}, nil
}

var (
	envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	labelRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	idRe      = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{9}Z-[0-9a-f]{6}$`)
	lookPath  = osexec.LookPath
)

type parsed struct {
	Config
	timeout time.Duration
}

// CommandProblem checks the program of a command line: an absolute path
// that exists, or a bare name found in PATH. Relative paths are refused.
func CommandProblem(argv []string) string {
	if len(argv) == 0 || argv[0] == "" {
		return "command is required"
	}
	prog := argv[0]
	switch {
	case filepath.IsAbs(prog):
		if _, err := os.Stat(prog); err != nil {
			return fmt.Sprintf("command: %v", err)
		}
	case strings.ContainsRune(prog, '/') || strings.ContainsRune(prog, filepath.Separator):
		return fmt.Sprintf("command %q is a relative path; use an absolute path or a name from PATH", prog)
	default:
		if _, err := lookPath(prog); err != nil {
			return fmt.Sprintf("command %q not found in PATH", prog)
		}
	}
	return ""
}

func parse(raw json.RawMessage) (*parsed, []string) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, []string{"settings: " + err.Error()}
	}
	p := &parsed{Config: c, timeout: DefaultTimeout}
	var problems []string
	if pr := CommandProblem(c.Command); pr != "" {
		problems = append(problems, pr)
	}
	if c.Timeout != "" {
		d, err := time.ParseDuration(c.Timeout)
		if err != nil || d <= 0 {
			problems = append(problems, fmt.Sprintf("timeout %q must be a positive duration such as \"2m\"", c.Timeout))
		} else {
			p.timeout = d
		}
	}
	for k := range c.Env {
		switch {
		case !envNameRe.MatchString(k):
			problems = append(problems, fmt.Sprintf("env: %q is not a valid variable name", k))
		case strings.HasPrefix(k, "KK_"):
			problems = append(problems, fmt.Sprintf("env: %s uses the reserved KK_ prefix", k))
		}
	}
	return p, problems
}

func mustParse(raw json.RawMessage) (*parsed, error) {
	p, problems := parse(raw)
	if len(problems) > 0 {
		return nil, fmt.Errorf("%w: exec target: %s", plugin.ErrPermanent, strings.Join(problems, "; "))
	}
	return p, nil
}

// Validate checks the settings.
func (t *Target) Validate(_ context.Context, req plugin.TargetValidateRequest) ([]string, error) {
	_, problems := parse(req.Config)
	return problems, nil
}

func (t *Target) base(certID, label string) (string, error) {
	if !labelRe.MatchString(label) || !labelRe.MatchString(certID) {
		return "", fmt.Errorf("%w: certificate id %q or label %q", plugin.ErrInvalid, certID, label)
	}
	return filepath.Join(t.root, certID+"-"+label), nil
}

// Current returns the serial of the last deployment the command accepted,
// or "" if there is none.
func (t *Target) Current(_ context.Context, req plugin.CurrentRequest) (string, error) {
	base, err := t.base(req.CertificateID, req.Label)
	if err != nil {
		return "", err
	}
	cur, err := readCurrent(base)
	if err != nil || cur == "" {
		return "", nil
	}
	return readSerial(cur), nil
}

type ref struct {
	// Dir is the deployment directory for Activate, or the previous one
	// for Rollback. Empty in a previous ref means nothing was deployed.
	Dir string `json:"dir"`
	// Prev is the deployment that was current when this one was staged.
	Prev   string `json:"prev,omitempty"`
	CertID string `json:"cert_id"`
	Label  string `json:"label"`
	Serial string `json:"serial"`
}

// Stage writes the files for the command into a new directory.
func (t *Target) Stage(_ context.Context, req plugin.StageRequest) (string, error) {
	if _, err := mustParse(req.Config); err != nil {
		return "", err
	}
	if req.Key.Format != plugin.KeyFormatPEM || len(req.Key.Data) == 0 {
		return "", fmt.Errorf("%w: exec target needs the private key as PEM", plugin.ErrPermanent)
	}
	base, err := t.base(req.CertificateID, req.Label)
	if err != nil {
		return "", err
	}
	for _, d := range []string{t.root, base} {
		if err := securefs.EnsurePrivateDir(d); err != nil {
			return "", err
		}
	}
	prev, _ := readCurrent(base)
	// Directories other than the current one are leftovers from earlier
	// deployments or from a stage that was never activated.
	prune(base, prev)

	id := time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + randomHex(3)
	dir := filepath.Join(base, id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	files := map[string][]byte{
		"cert.pem":      []byte(req.CertPEM),
		"chain.pem":     []byte(req.ChainPEM),
		"fullchain.pem": []byte(req.FullChainPEM),
		"key.pem":       req.Key.Data,
		"serial":        []byte(req.Serial),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			_ = os.RemoveAll(dir)
			return "", err
		}
	}
	r, _ := json.Marshal(ref{Dir: dir, Prev: prev, CertID: req.CertificateID, Label: req.Label, Serial: req.Serial})
	return string(r), nil
}

// Discard removes a staged directory that was not activated.
func (t *Target) Discard(_ context.Context, req plugin.DiscardRequest) error {
	r, err := t.parseRef(req.StagedRef, false)
	if err != nil {
		return err
	}
	if cur, _ := readCurrent(filepath.Dir(r.Dir)); cur == r.Dir {
		return nil // activated; nothing to discard
	}
	return os.RemoveAll(r.Dir)
}

// Activate runs the command with the staged files.
func (t *Target) Activate(ctx context.Context, req plugin.ActivateRequest) (string, error) {
	p, err := mustParse(req.Config)
	if err != nil {
		return "", err
	}
	r, err := t.parseRef(req.StagedRef, false)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(r.Dir); errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("%w: staged deployment %s", plugin.ErrNotFound, filepath.Base(r.Dir))
	}
	if err := t.run(ctx, p, r, "deploy"); err != nil {
		_ = os.RemoveAll(r.Dir)
		// The command may have applied part of the change. Run it again
		// with the previous files so the system is back where it was.
		if r.Prev != "" && t.inside(r.Prev) {
			prev := ref{Dir: r.Prev, CertID: r.CertID, Label: r.Label}
			if rbErr := t.run(context.WithoutCancel(ctx), p, prev, "rollback"); rbErr != nil {
				return "", errors.Join(err, fmt.Errorf("restoring the previous files also failed: %w", rbErr))
			}
			return "", fmt.Errorf("%w (previous files restored)", err)
		}
		return "", err
	}
	base := filepath.Dir(r.Dir)
	if err := writeCurrent(base, r.Dir); err != nil {
		return "", err
	}
	prune(base, r.Dir, r.Prev)
	prev, _ := json.Marshal(ref{Dir: r.Prev, CertID: r.CertID, Label: r.Label})
	return string(prev), nil
}

// Rollback runs the command again with the previous files. If nothing was
// deployed before, it cannot undo the command's effect and says so.
func (t *Target) Rollback(ctx context.Context, req plugin.RollbackRequest) error {
	p, err := mustParse(req.Config)
	if err != nil {
		return err
	}
	r, err := t.parseRef(req.PreviousRef, true)
	if err != nil {
		return err
	}
	if r.Dir == "" {
		return fmt.Errorf("%w: exec target: nothing was deployed before, so there is nothing to roll back to", plugin.ErrPermanent)
	}
	if _, err := os.Stat(r.Dir); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: previous deployment %s", plugin.ErrNotFound, filepath.Base(r.Dir))
	}
	if err := t.run(ctx, p, r, "rollback"); err != nil {
		return err
	}
	return writeCurrent(filepath.Dir(r.Dir), r.Dir)
}

func (t *Target) parseRef(s string, allowEmpty bool) (ref, error) {
	var r ref
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		return r, fmt.Errorf("%w: ref %q", plugin.ErrInvalid, s)
	}
	if r.Dir == "" && allowEmpty {
		return r, nil
	}
	if !t.inside(r.Dir) {
		return r, fmt.Errorf("%w: ref directory %q is not a deployment under %s", plugin.ErrInvalid, r.Dir, t.root)
	}
	return r, nil
}

// inside reports whether dir is <root>/<cert>-<label>/<id>.
func (t *Target) inside(dir string) bool {
	rel, err := filepath.Rel(t.root, dir)
	if err != nil {
		return false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	return len(parts) == 2 && labelRe.MatchString(parts[0]) && idRe.MatchString(parts[1])
}

func (t *Target) run(ctx context.Context, p *parsed, r ref, action string) error {
	serial := r.Serial
	if serial == "" {
		serial = readSerial(r.Dir)
	}
	env := []string{
		"KK_ACTION=" + action,
		"KK_CERT_FILE=" + filepath.Join(r.Dir, "cert.pem"),
		"KK_CHAIN_FILE=" + filepath.Join(r.Dir, "chain.pem"),
		"KK_FULLCHAIN_FILE=" + filepath.Join(r.Dir, "fullchain.pem"),
		"KK_KEY_FILE=" + filepath.Join(r.Dir, "key.pem"),
		"KK_CERT_SERIAL=" + serial,
		"KK_CERT_ID=" + r.CertID,
		"KK_TARGET_LABEL=" + r.Label,
	}
	for k, v := range p.Env {
		env = append(env, k+"="+v)
	}
	if err := execx.Run(ctx, p.Command, execx.Env(env...), p.timeout); err != nil {
		return fmt.Errorf("exec target (%s): %w", action, err)
	}
	return nil
}

func readSerial(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "serial"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readCurrent(base string) (string, error) {
	b, err := os.ReadFile(filepath.Join(base, "current"))
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(string(b))
	if !idRe.MatchString(name) {
		return "", fmt.Errorf("bad current marker %q", name)
	}
	return filepath.Join(base, name), nil
}

func writeCurrent(base, dir string) error {
	return securefs.WriteFile(filepath.Join(base, "current"), []byte(filepath.Base(dir)+"\n"))
}

// prune removes deployment directories other than keep.
func prune(base string, keep ...string) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, e := range entries {
		full := filepath.Join(base, e.Name())
		if e.IsDir() && idRe.MatchString(e.Name()) && !slices.Contains(keep, full) {
			_ = os.RemoveAll(full)
		}
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
