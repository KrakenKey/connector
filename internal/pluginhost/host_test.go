package pluginhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/testplugin"
	"github.com/krakenkey/connector/pkg/plugin"
)

const servePluginEnv = "KRAKENKEY_CONNECTOR_PLUGINHOST_TEST"

// TestMain lets the test binary act as an external plugin.
func TestMain(m *testing.M) {
	if os.Getenv(servePluginEnv) == "1" {
		plugin.Serve(plugin.ServeOpts{KeyStore: testplugin.NewKeyStore(), Target: testplugin.NewTarget()})
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestBuiltins(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	h := New(&config.Config{DataDir: dataDir}, quiet())
	defer h.Close()
	if _, err := h.KeyStore("local"); err != nil {
		t.Fatalf("local: %v", err)
	}
	for _, name := range []string{"file", "exec"} {
		if _, err := h.Target(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := h.Target("missing"); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Errorf("undeclared plugin: %v", err)
	}
}

func selfBinary(t *testing.T) (string, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return exe, hex.EncodeToString(sum[:])
}

func TestExternalPlugin(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a subprocess")
	}
	t.Setenv(servePluginEnv, "1")
	exe, sum := selfBinary(t)
	h := New(&config.Config{
		DataDir: t.TempDir(),
		Plugins: map[string]config.PluginSpec{"mem": {Path: exe, SHA256: sum}},
	}, quiet())
	defer h.Close()

	ks, err := h.KeyStore("mem")
	if err != nil {
		t.Fatalf("KeyStore: %v", err)
	}
	tg, err := h.Target("mem") // same process, second role
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	ksCaps, err := ks.Describe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tCaps, err := tg.Describe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Match(ksCaps, tCaps, plugin.KeyTypeECDSAP256); err != nil {
		t.Errorf("Match: %v", err)
	}
}

func TestExternalPluginChecksumMismatch(t *testing.T) {
	t.Setenv(servePluginEnv, "1")
	exe, _ := selfBinary(t)
	h := New(&config.Config{
		DataDir: t.TempDir(),
		Plugins: map[string]config.PluginSpec{"mem": {Path: exe, SHA256: strings.Repeat("0", 64)}},
	}, quiet())
	defer h.Close()
	if _, err := h.Target("mem"); err == nil || !strings.Contains(strings.ToLower(err.Error()), "checksum") {
		t.Fatalf("err = %v, want a checksum error", err)
	}
}

func TestExternalPluginBinaryChecks(t *testing.T) {
	dataDir := t.TempDir()
	h := New(&config.Config{
		DataDir: dataDir,
		Plugins: map[string]config.PluginSpec{"azure-keyvault": {Version: "0.1.0"}},
	}, quiet())
	defer h.Close()

	want := filepath.Join(dataDir, "plugins", "azure-keyvault", "0.1.0", BinaryName("azure-keyvault"))
	if p, _ := h.BinaryPath("azure-keyvault"); p != want {
		t.Errorf("BinaryPath = %s, want %s", p, want)
	}
	if _, err := h.KeyStore("azure-keyvault"); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("missing binary: %v", err)
	}

	if runtime.GOOS == "windows" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want, []byte("#!/bin/sh\n"), 0o775); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(want, 0o775)
	if _, err := h.KeyStore("azure-keyvault"); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("group-writable binary: %v", err)
	}
	_ = os.Chmod(want, 0o644)
	if _, err := h.KeyStore("azure-keyvault"); err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Errorf("non-executable binary: %v", err)
	}
}
