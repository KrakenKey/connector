// Package pluginhost resolves plugin names from the config to key store
// and target implementations: built-in ones in process, external ones as
// go-plugin subprocesses.
//
// External plugin binaries must be regular files (not symlinks) owned by
// root or the connector's user, not writable by group or others, in
// directories with the same properties up to the data directory (or up to
// / for an explicit path). Root-owned directories with the sticky bit, such
// as /tmp, are accepted along the way. The checksum is computed from the
// opened file, and on Linux that same open file is executed through
// /proc/self/fd, so the binary cannot be swapped between check and start.
// Elsewhere the binary is executed by path after the check, which leaves a
// small window; the ownership checks above are what close it.
package pluginhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"

	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/keystore/local"
	"github.com/krakenkey/connector/internal/securefs"
	execTarget "github.com/krakenkey/connector/internal/target/exec"
	fileTarget "github.com/krakenkey/connector/internal/target/file"
	"github.com/krakenkey/connector/pkg/plugin"
)

// quickCallLimit bounds calls that should never take long (Describe,
// Validate, Current, PublicKey, Release, Discard), whatever call_timeout
// says.
const quickCallLimit = time.Minute

// BinaryName returns the file name of an external plugin's executable.
func BinaryName(name string) string {
	n := "krakenkey-connector-plugin-" + name
	if runtime.GOOS == "windows" {
		n += ".exe"
	}
	return n
}

// Host owns plugin instances for one connector run.
type Host struct {
	dataDir string
	specs   map[string]config.PluginSpec
	log     *slog.Logger

	mu      sync.Mutex
	local   *local.Store
	clients map[string]*goplugin.Client
}

// New returns a host. Nothing starts until a plugin is requested.
func New(cfg *config.Config, log *slog.Logger) *Host {
	return &Host{dataDir: cfg.DataDir, specs: cfg.Plugins, log: log, clients: map[string]*goplugin.Client{}}
}

// KeyStore returns the key store called name. External key stores are
// started now, so start problems show up here, and restarted later if they
// exit.
func (h *Host) KeyStore(name string) (plugin.KeyStore, error) {
	if name == config.BuiltinLocal {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.local == nil {
			s, err := local.Open(h.dataDir)
			if err != nil {
				return nil, fmt.Errorf("local key store: %w", err)
			}
			h.local = s
		}
		return h.local, nil
	}
	r := &remoteKeyStore{remote: remote{h: h, name: name, timeout: h.timeout(name)}}
	if _, err := r.get(); err != nil {
		return nil, err
	}
	return r, nil
}

// Target returns the target called name.
func (h *Host) Target(name string) (plugin.Target, error) {
	switch name {
	case config.BuiltinFile:
		return fileTarget.New(), nil
	case config.BuiltinExec:
		return execTarget.New(h.dataDir), nil
	}
	r := &remoteTarget{remote: remote{h: h, name: name, timeout: h.timeout(name)}}
	if _, err := r.get(); err != nil {
		return nil, err
	}
	return r, nil
}

func (h *Host) timeout(name string) time.Duration {
	if t := h.specs[name].CallTimeout; t > 0 {
		return t
	}
	return config.DefaultCallTimeout
}

// BinaryPath returns where the executable for an external plugin is
// expected, and the directory up to which its parents are checked.
func (h *Host) BinaryPath(name string) (path, stop string, err error) {
	spec, ok := h.specs[name]
	if !ok {
		return "", "", fmt.Errorf("plugin %q is not declared under plugins", name)
	}
	if spec.Path != "" {
		return spec.Path, string(filepath.Separator), nil
	}
	return filepath.Join(h.dataDir, "plugins", name, spec.Version, BinaryName(name)), h.dataDir, nil
}

// rpc returns a running client for the plugin, starting it, or restarting
// it if it has exited.
func (h *Host) rpc(name string) (goplugin.ClientProtocol, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := h.clients[name]; ok {
		if !c.Exited() {
			return c.Client()
		}
		h.log.Warn("plugin exited; restarting it", "plugin", name)
		c.Kill()
		delete(h.clients, name)
	}
	client, err := h.start(name)
	if err != nil {
		return nil, err
	}
	rpc, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("start plugin %s: %w", name, err)
	}
	h.clients[name] = client
	return rpc, nil
}

func (h *Host) start(name string) (*goplugin.Client, error) {
	path, stop, err := h.BinaryPath(name)
	if err != nil {
		return nil, err
	}
	f, err := OpenBinary(path, stop)
	if err != nil {
		return nil, fmt.Errorf("plugin %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()

	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return nil, fmt.Errorf("plugin %s: hash %s: %w", name, path, err)
	}
	got := sum.Sum(nil)
	if want := h.specs[name].SHA256; want != "" {
		wantBytes, _ := hex.DecodeString(want)
		if !bytes.Equal(got, wantBytes) {
			return nil, fmt.Errorf("plugin %s: checksum mismatch for %s: sha256 is %x, config says %s", name, path, got, want)
		}
	}

	cmdPath := path
	if runtime.GOOS == "linux" {
		// Run exactly the file that was checked and hashed.
		cmdPath = fmt.Sprintf("/proc/self/fd/%d", f.Fd())
	}
	cmd := exec.Command(cmdPath)
	cmd.Args[0] = path
	cmd.Env = PluginEnv(os.Environ())
	cfg := plugin.ClientConfig(cmd, hclog.New(&hclog.LoggerOptions{
		Name:   "plugin." + name,
		Output: os.Stderr,
		Level:  hclog.Info,
	}))
	// cmd.Env is the whole environment; do not let go-plugin add the
	// connector's own back.
	cfg.SkipHostEnv = true
	client := goplugin.NewClient(cfg)
	if _, err := client.Start(); err != nil {
		client.Kill()
		return nil, fmt.Errorf("start plugin %s (%s): %w", name, path, err)
	}
	h.log.Debug("plugin started", "plugin", name, "path", path, "sha256", hex.EncodeToString(got))
	return client, nil
}

// connectorSecretEnv lists environment variables that carry the
// connector's own KrakenKey credentials. Plugins never need them.
var connectorSecretEnv = []string{"KK_API_KEY", "KK_API_KEY_FILE", "CREDENTIALS_DIRECTORY"}

// PluginEnv returns the environment for a plugin process: the connector's,
// without its KrakenKey API key, enrollment token and systemd credentials
// directory. Everything else is kept, since cloud SDKs read their
// credentials and settings from the environment.
func PluginEnv(environ []string) []string {
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if slices.Contains(connectorSecretEnv, name) || strings.HasPrefix(name, "KK_ENROLLMENT_TOKEN") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// OpenBinary checks a plugin executable and its parent directories, then
// opens it. See the package documentation for the rules.
func OpenBinary(path, stop string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%s is not an absolute path", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := checkOwned(path, info, false); err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o100 == 0 {
		return nil, fmt.Errorf("%s is not executable", path)
	}
	if err := checkParents(filepath.Dir(path), stop); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	// Make sure the file opened is the one checked.
	opened, err := f.Stat()
	if err != nil || !os.SameFile(opened, info) {
		_ = f.Close()
		return nil, fmt.Errorf("%s changed while it was being checked", path)
	}
	return f, nil
}

func checkParents(dir, stop string) error {
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	realStop, err := filepath.EvalSymlinks(stop)
	if err != nil {
		return err
	}
	for d := realDir; ; d = filepath.Dir(d) {
		info, err := os.Lstat(d)
		if err != nil {
			return err
		}
		if err := checkOwned(d, info, true); err != nil {
			return err
		}
		if d == realStop || d == filepath.Dir(d) {
			return nil
		}
	}
}

// checkOwned requires path to be owned by root or the connector's user and
// not writable by group or others. Root-owned sticky directories are
// allowed.
func checkOwned(path string, info fs.FileInfo, isDirCheck bool) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; point the config at the real file", path)
	}
	uid, _ := securefs.Owner(info)
	if uid != 0 && uid != os.Geteuid() {
		return fmt.Errorf("%s is owned by uid %d, not root or the user running the connector", path, uid)
	}
	if info.Mode().Perm()&0o022 != 0 {
		if isDirCheck && uid == 0 && info.Mode()&fs.ModeSticky != 0 {
			return nil
		}
		return fmt.Errorf("%s is writable by group or others (mode %04o); run: chmod go-w %s", path, info.Mode().Perm(), path)
	}
	return nil
}

// Close stops every external plugin.
func (h *Host) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for name, c := range h.clients {
		c.Kill()
		delete(h.clients, name)
	}
}

// remote holds what both wrappers need: which plugin, and the call timeout.
type remote struct {
	h       *Host
	name    string
	timeout time.Duration
}

func (r remote) ctx(ctx context.Context, quick bool) (context.Context, context.CancelFunc) {
	t := r.timeout
	if quick {
		t = min(t, quickCallLimit)
	}
	return context.WithTimeout(ctx, t)
}

// remoteKeyStore forwards to an external key store with a timeout on every
// call, restarting the plugin if it has exited.
type remoteKeyStore struct{ remote }

func (r *remoteKeyStore) get() (plugin.KeyStore, error) {
	rpc, err := r.h.rpc(r.name)
	if err != nil {
		return nil, err
	}
	return plugin.DispenseKeyStore(rpc)
}

func (r *remoteKeyStore) Describe(ctx context.Context) (plugin.KeyStoreCapabilities, error) {
	ctx, cancel := r.ctx(ctx, true)
	defer cancel()
	ks, err := r.get()
	if err != nil {
		return plugin.KeyStoreCapabilities{}, err
	}
	return ks.Describe(ctx)
}

func (r *remoteKeyStore) Validate(ctx context.Context, req plugin.KeyStoreValidateRequest) ([]string, error) {
	ctx, cancel := r.ctx(ctx, true)
	defer cancel()
	ks, err := r.get()
	if err != nil {
		return nil, err
	}
	return ks.Validate(ctx, req)
}

// ValidateCapabilities forwards to the plugin, keeping the capabilities it
// returns for these settings.
func (r *remoteKeyStore) ValidateCapabilities(ctx context.Context, req plugin.KeyStoreValidateRequest) (plugin.KeyStoreValidation, error) {
	ctx, cancel := r.ctx(ctx, true)
	defer cancel()
	ks, err := r.get()
	if err != nil {
		return plugin.KeyStoreValidation{}, err
	}
	return plugin.ValidateKeyStore(ctx, ks, req)
}

func (r *remoteKeyStore) CreateCSR(ctx context.Context, req plugin.CSRRequest) (plugin.CSR, error) {
	ctx, cancel := r.ctx(ctx, false)
	defer cancel()
	ks, err := r.get()
	if err != nil {
		return plugin.CSR{}, err
	}
	return ks.CreateCSR(ctx, req)
}

func (r *remoteKeyStore) PublicKey(ctx context.Context, req plugin.PublicKeyRequest) ([]byte, error) {
	ctx, cancel := r.ctx(ctx, true)
	defer cancel()
	ks, err := r.get()
	if err != nil {
		return nil, err
	}
	return ks.PublicKey(ctx, req)
}

func (r *remoteKeyStore) Complete(ctx context.Context, req plugin.CompleteRequest) (string, error) {
	ctx, cancel := r.ctx(ctx, false)
	defer cancel()
	ks, err := r.get()
	if err != nil {
		return "", err
	}
	return ks.Complete(ctx, req)
}

func (r *remoteKeyStore) Export(ctx context.Context, req plugin.ExportRequest) (plugin.KeyMaterial, error) {
	ctx, cancel := r.ctx(ctx, false)
	defer cancel()
	ks, err := r.get()
	if err != nil {
		return plugin.KeyMaterial{}, err
	}
	return ks.Export(ctx, req)
}

func (r *remoteKeyStore) Release(ctx context.Context, req plugin.ReleaseRequest) error {
	ctx, cancel := r.ctx(ctx, true)
	defer cancel()
	ks, err := r.get()
	if err != nil {
		return err
	}
	return ks.Release(ctx, req)
}

// remoteTarget forwards to an external target with a timeout on every
// call, restarting the plugin if it has exited.
type remoteTarget struct{ remote }

func (r *remoteTarget) get() (plugin.Target, error) {
	rpc, err := r.h.rpc(r.name)
	if err != nil {
		return nil, err
	}
	return plugin.DispenseTarget(rpc)
}

func (r *remoteTarget) Describe(ctx context.Context) (plugin.TargetCapabilities, error) {
	ctx, cancel := r.ctx(ctx, true)
	defer cancel()
	t, err := r.get()
	if err != nil {
		return plugin.TargetCapabilities{}, err
	}
	return t.Describe(ctx)
}

func (r *remoteTarget) Validate(ctx context.Context, req plugin.TargetValidateRequest) ([]string, error) {
	ctx, cancel := r.ctx(ctx, true)
	defer cancel()
	t, err := r.get()
	if err != nil {
		return nil, err
	}
	return t.Validate(ctx, req)
}

func (r *remoteTarget) Current(ctx context.Context, req plugin.CurrentRequest) (string, error) {
	ctx, cancel := r.ctx(ctx, true)
	defer cancel()
	t, err := r.get()
	if err != nil {
		return "", err
	}
	return t.Current(ctx, req)
}

// CallTimeout is the plugin's call_timeout. The engine gives a rollback at
// least this long.
func (r *remoteTarget) CallTimeout() time.Duration { return r.timeout }

func (r *remoteTarget) Stage(ctx context.Context, req plugin.StageRequest) (string, error) {
	ctx, cancel := r.ctx(ctx, false)
	defer cancel()
	t, err := r.get()
	if err != nil {
		return "", err
	}
	return t.Stage(ctx, req)
}

func (r *remoteTarget) Activate(ctx context.Context, req plugin.ActivateRequest) (string, error) {
	ctx, cancel := r.ctx(ctx, false)
	defer cancel()
	t, err := r.get()
	if err != nil {
		return "", err
	}
	return t.Activate(ctx, req)
}

func (r *remoteTarget) Rollback(ctx context.Context, req plugin.RollbackRequest) error {
	ctx, cancel := r.ctx(ctx, false)
	defer cancel()
	t, err := r.get()
	if err != nil {
		return err
	}
	return t.Rollback(ctx, req)
}

func (r *remoteTarget) Discard(ctx context.Context, req plugin.DiscardRequest) error {
	ctx, cancel := r.ctx(ctx, true)
	defer cancel()
	t, err := r.get()
	if err != nil {
		return err
	}
	return t.Discard(ctx, req)
}

var (
	_ plugin.KeyStore = (*remoteKeyStore)(nil)
	_ plugin.Target   = (*remoteTarget)(nil)
)
