// Package pluginhost resolves plugin names from the config to key store
// and target implementations: built-in ones in process, external ones as
// go-plugin subprocesses.
package pluginhost

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"

	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/keystore/local"
	execTarget "github.com/krakenkey/connector/internal/target/exec"
	fileTarget "github.com/krakenkey/connector/internal/target/file"
	"github.com/krakenkey/connector/pkg/plugin"
)

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

// KeyStore returns the key store called name.
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
	rpc, err := h.start(name)
	if err != nil {
		return nil, err
	}
	return plugin.DispenseKeyStore(rpc)
}

// Target returns the target called name.
func (h *Host) Target(name string) (plugin.Target, error) {
	switch name {
	case config.BuiltinFile:
		return fileTarget.New(), nil
	case config.BuiltinExec:
		return execTarget.New(h.dataDir), nil
	}
	rpc, err := h.start(name)
	if err != nil {
		return nil, err
	}
	return plugin.DispenseTarget(rpc)
}

// BinaryPath returns where the executable for an external plugin is
// expected.
func (h *Host) BinaryPath(name string) (string, error) {
	spec, ok := h.specs[name]
	if !ok {
		return "", fmt.Errorf("plugin %q is not declared under plugins", name)
	}
	if spec.Path != "" {
		return spec.Path, nil
	}
	return filepath.Join(h.dataDir, "plugins", name, spec.Version, BinaryName(name)), nil
}

func (h *Host) start(name string) (goplugin.ClientProtocol, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := h.clients[name]; ok {
		return c.Client()
	}
	path, err := h.BinaryPath(name)
	if err != nil {
		return nil, err
	}
	if err := checkBinary(path); err != nil {
		return nil, fmt.Errorf("plugin %s: %w", name, err)
	}
	cfg := plugin.ClientConfig(exec.Command(path), hclog.New(&hclog.LoggerOptions{
		Name:   "plugin." + name,
		Output: os.Stderr,
		Level:  hclog.Info,
	}))
	if sum := h.specs[name].SHA256; sum != "" {
		want, _ := hex.DecodeString(sum)
		cfg.SecureConfig = &goplugin.SecureConfig{Checksum: want, Hash: sha256.New()}
	}
	client := goplugin.NewClient(cfg)
	rpc, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("start plugin %s (%s): %w", name, path, err)
	}
	h.clients[name] = client
	h.log.Debug("plugin started", "plugin", name, "path", path)
	return rpc, nil
}

// checkBinary refuses executables that other users could replace.
func checkBinary(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others (mode %04o); run: chmod go-w %s",
			path, info.Mode().Perm(), path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o100 == 0 {
		return fmt.Errorf("%s is not executable", path)
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
