package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, &out, &errOut); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(out.String(), "krakenkey-connector dev (") {
		t.Errorf("output %q", out.String())
	}
}

func TestUsageErrors(t *testing.T) {
	cases := map[string][]string{
		"no command":         nil,
		"unknown command":    {"deploy"},
		"force without once": {"run", "--force"},
		"cert without once":  {"run", "--cert", "5"},
		"bad flag":           {"run", "--nope"},
		"bad log format":     {"run", "--once", "--log-format", "xml"},
		"extra args":         {"run", "--once", "now"},
		"missing config":     {"run", "--once", "--config", "/does/not/exist.yaml"},
		"validate bad flag":  {"validate", "--nope"},
		"validate log level": {"validate", "--log-level", "loud"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(args, &out, &errOut); code != exitUsage {
				t.Errorf("exit %d, want %d; stderr %s", code, exitUsage, errOut.String())
			}
		})
	}
}

func writeConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := `
data_dir: ` + filepath.Join(dir, "data") + `
certificates:
  - id: 7
    names: [api.example.com]
    targets:
      - { label: hook, plugin: exec, command: [/bin/true] }
`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunNeedsAPIKey(t *testing.T) {
	t.Setenv("KK_API_KEY", "")
	t.Setenv("KK_API_URL", "")
	var out, errOut bytes.Buffer
	code := run([]string{"run", "--once", "--config", writeConfig(t)}, &out, &errOut)
	if code != exitUsage || !strings.Contains(errOut.String(), "KK_API_KEY is not set") {
		t.Errorf("exit %d, stderr %s", code, errOut.String())
	}
}

func TestRunCertMustBeConfigured(t *testing.T) {
	t.Setenv("KK_API_KEY", "kk_x")
	t.Setenv("KK_API_URL", "")
	var out, errOut bytes.Buffer
	code := run([]string{"run", "--once", "--cert", "99", "--config", writeConfig(t)}, &out, &errOut)
	if code != exitUsage || !strings.Contains(errOut.String(), "--cert is not in the config") {
		t.Errorf("exit %d, stderr %s", code, errOut.String())
	}
}

func TestValidateOffline(t *testing.T) {
	t.Setenv("KK_API_KEY", "kk_should_be_removed")
	t.Setenv("KK_API_URL", "")
	var out, errOut bytes.Buffer
	code := run([]string{"validate", "--offline", "--config", writeConfig(t)}, &out, &errOut)
	if code != exitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out.String(), errOut.String())
	}
	for _, want := range []string{"API key:    not checked (--offline)", "Certificate 7 [api.example.com]", "0 problem(s), 1 warning(s)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not contain %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String()+errOut.String(), "kk_should_be_removed") {
		t.Error("API key printed")
	}
	if os.Getenv("KK_API_KEY") != "" {
		t.Error("KK_API_KEY left in the environment for child processes")
	}
}

func TestValidateInvalidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	_ = os.WriteFile(path, []byte("certificates: []\n"), 0o600)
	var out, errOut bytes.Buffer
	if code := run([]string{"validate", "--config", path}, &out, &errOut); code != exitFailed {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(out.String(), "INVALID") {
		t.Errorf("output %q", out.String())
	}
}
