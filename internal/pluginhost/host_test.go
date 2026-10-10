package pluginhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/testplugin"
	"github.com/krakenkey/connector/pkg/plugin"
)

const servePluginEnv = "KRAKENKEY_CONNECTOR_PLUGINHOST_TEST"

// TestMain lets the test binary act as an external plugin.
func TestMain(m *testing.M) {
	switch os.Getenv(servePluginEnv) {
	case "1":
		plugin.Serve(plugin.ServeOpts{KeyStore: testplugin.NewKeyStore(), Target: testplugin.NewTarget()})
		os.Exit(0)
	case "env":
		plugin.Serve(plugin.ServeOpts{Target: envTarget{Target: testplugin.NewTarget()}})
		os.Exit(0)
	case "slow":
		plugin.Serve(plugin.ServeOpts{Target: slowTarget{Target: testplugin.NewTarget()}})
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// envTarget reports, as Validate problems, which environment variables it
// can see from a fixed list.
type envTarget struct{ *testplugin.Target }

func (envTarget) Validate(context.Context, plugin.TargetValidateRequest) ([]string, error) {
	var seen []string
	for _, k := range []string{"KK_API_KEY", "KK_API_KEY_FILE", "CREDENTIALS_DIRECTORY", "KK_ENROLLMENT_TOKEN", "KK_ENROLLMENT_TOKEN_FILE", "AWS_REGION", "KK_PLUGIN_TEST_KEEP"} {
		if _, ok := os.LookupEnv(k); ok {
			seen = append(seen, k)
		}
	}
	return seen, nil
}

type slowTarget struct{ *testplugin.Target }

func (s slowTarget) Validate(ctx context.Context, _ plugin.TargetValidateRequest) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(10 * time.Second):
		return nil, nil
	}
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
	exe, _ = filepath.EvalSymlinks(exe)
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
	ctx := context.Background()
	ksCaps, err := ks.Describe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tCaps, err := tg.Describe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Match(ksCaps, tCaps, plugin.KeyTypeECDSAP256); err != nil {
		t.Errorf("Match: %v", err)
	}

	// A plugin that exits is started again on the next call.
	h.mu.Lock()
	h.clients["mem"].Kill()
	h.mu.Unlock()
	if _, err := tg.Describe(ctx); err != nil {
		t.Fatalf("Describe after the plugin exited: %v", err)
	}
	if _, err := ks.Validate(ctx, plugin.KeyStoreValidateRequest{}); err != nil {
		t.Fatalf("key store after restart: %v", err)
	}
}

func TestCallTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a subprocess")
	}
	t.Setenv(servePluginEnv, "slow")
	exe, _ := selfBinary(t)
	h := New(&config.Config{
		DataDir: t.TempDir(),
		Plugins: map[string]config.PluginSpec{"slow": {Path: exe, CallTimeout: 300 * time.Millisecond}},
	}, quiet())
	defer h.Close()
	tg, err := h.Target("slow")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = tg.Validate(context.Background(), plugin.TargetValidateRequest{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want a deadline error", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("call timeout not applied")
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
	if _, err := h.Target("mem"); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("err = %v, want a checksum error", err)
	}
}

func TestExternalPluginBinaryChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits")
	}
	dataDir := t.TempDir()
	h := New(&config.Config{
		DataDir: dataDir,
		Plugins: map[string]config.PluginSpec{"azure-keyvault": {Version: "0.1.0", SHA256: strings.Repeat("0", 64)}},
	}, quiet())
	defer h.Close()

	want := filepath.Join(dataDir, "plugins", "azure-keyvault", "0.1.0", BinaryName("azure-keyvault"))
	if _, err := h.KeyStore("azure-keyvault"); err == nil || !strings.Contains(err.Error(), want+" does not exist") {
		t.Errorf("missing binary: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	check := func(name, wantErr string) {
		t.Helper()
		_, err := h.KeyStore("azure-keyvault")
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("%s: err = %v, want %q", name, err, wantErr)
		}
	}

	if loc, stop, err := h.find("azure-keyvault", h.specs["azure-keyvault"]); err != nil || loc.Path != want || loc.Source != SourceDataDir || stop != dataDir {
		t.Errorf("find = %+v (stop %s), %v; want %s", loc, stop, err, want)
	}

	check("well-formed binary with the wrong checksum", "checksum mismatch")

	_ = os.Chmod(want, 0o775)
	check("group-writable binary", "writable by group or others")
	_ = os.Chmod(want, 0o644)
	check("non-executable binary", "not executable")
	_ = os.Chmod(want, 0o755)

	_ = os.Chmod(filepath.Dir(want), 0o777)
	check("world-writable parent dir", "writable by group or others")
	_ = os.Chmod(filepath.Dir(want), 0o755)

	real := want + ".real"
	_ = os.Rename(want, real)
	_ = os.Symlink(real, want)
	check("symlinked binary", "is a symlink")
	_ = os.Remove(want)
	_ = os.Rename(real, want)

	if os.Geteuid() == 0 {
		_ = os.Chown(want, 4242, 4242)
		check("binary owned by another user", "owned by uid 4242")
		_ = os.Chown(want, 0, 0)
	}
}

func TestPluginEnv(t *testing.T) {
	got := PluginEnv([]string{
		"PATH=/bin", "KK_API_KEY=kk_secret", "KK_API_KEY_FILE=/run/k", "CREDENTIALS_DIRECTORY=/run/credentials/x",
		"KK_ENROLLMENT_TOKEN=tok", "KK_ENROLLMENT_TOKEN_FILE=/run/t", "AWS_REGION=eu-west-1", "KK_API_URL=https://api",
	})
	want := []string{"PATH=/bin", "AWS_REGION=eu-west-1", "KK_API_URL=https://api"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("PluginEnv = %v, want %v", got, want)
	}
}

func TestExternalPluginDoesNotSeeConnectorSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a subprocess")
	}
	exe, sum := selfBinary(t)
	for _, k := range []string{"KK_API_KEY", "KK_API_KEY_FILE", "CREDENTIALS_DIRECTORY", "KK_ENROLLMENT_TOKEN", "KK_ENROLLMENT_TOKEN_FILE"} {
		t.Setenv(k, "secret")
	}
	t.Setenv("AWS_REGION", "eu-west-1")
	t.Setenv("KK_PLUGIN_TEST_KEEP", "1")
	t.Setenv(servePluginEnv, "env")
	h := New(&config.Config{DataDir: t.TempDir(), Plugins: map[string]config.PluginSpec{
		"envcheck": {Path: exe, SHA256: sum, CallTimeout: time.Minute},
	}}, quiet())
	defer h.Close()
	tg, err := h.Target("envcheck")
	if err != nil {
		t.Fatal(err)
	}
	seen, err := tg.Validate(context.Background(), plugin.TargetValidateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(seen, ",") != "AWS_REGION,KK_PLUGIN_TEST_KEEP" {
		t.Errorf("plugin sees %v, want only AWS_REGION and KK_PLUGIN_TEST_KEEP", seen)
	}
}
