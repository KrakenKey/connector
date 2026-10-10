//go:build unix

package exec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/krakenkey/connector/pkg/plugin"
)

// script writes a shell script that appends one line per run to log and
// fails when the cert file contains FAIL.
func script(t *testing.T, dir string) (path, log string) {
	t.Helper()
	log = filepath.Join(dir, "runs.log")
	path = filepath.Join(dir, "hook.sh")
	body := `#!/bin/sh
echo "$KK_ACTION serial=$KK_CERT_SERIAL id=$KK_CERT_ID label=$KK_TARGET_LABEL extra=$EXTRA apikey=${KK_API_KEY:-unset} cert=$(cat "$KK_CERT_FILE") key=$(cat "$KK_KEY_FILE") chain=$(cat "$KK_CHAIN_FILE") full=$(cat "$KK_FULLCHAIN_FILE")" >> "` + log + `"
if grep -q FAIL "$KK_CERT_FILE"; then echo "deploy refused" >&2; exit 3; fi
`
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path, log
}

func stage(t *testing.T, tg *Target, cfg json.RawMessage, serial, cert string) string {
	t.Helper()
	ref, err := tg.Stage(context.Background(), plugin.StageRequest{
		Config: cfg, CertificateID: "12", Label: "hook",
		CertPEM: cert, ChainPEM: "CHAIN", FullChainPEM: cert + "CHAIN",
		Key:    plugin.KeyMaterial{Format: plugin.KeyFormatPEM, Data: []byte("KEY" + serial)},
		Serial: serial,
	})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	return ref
}

func lines(t *testing.T, log string) []string {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func TestExecDeployAndRollback(t *testing.T) {
	t.Setenv("KK_API_KEY", "kk_must_not_leak")
	ctx := context.Background()
	dir := t.TempDir()
	hook, log := script(t, dir)
	tg := New(filepath.Join(dir, "data"))
	cfg := json.RawMessage(fmt.Sprintf(`{"command":[%q],"env":{"EXTRA":"yes"},"timeout":"30s"}`, hook))

	if problems, _ := tg.Validate(ctx, cfg); len(problems) > 0 {
		t.Fatalf("Validate: %q", problems)
	}

	prev1, err := tg.Activate(ctx, cfg, stage(t, tg, cfg, "0a", "CERT1"))
	if err != nil {
		t.Fatalf("Activate 1: %v", err)
	}
	if err := tg.Rollback(ctx, cfg, prev1); err == nil || !strings.Contains(err.Error(), "nothing to roll back to") {
		t.Errorf("rollback of first deploy: %v", err)
	}

	prev2, err := tg.Activate(ctx, cfg, stage(t, tg, cfg, "0b", "CERT2"))
	if err != nil {
		t.Fatalf("Activate 2: %v", err)
	}
	if err := tg.Rollback(ctx, cfg, prev2); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	got := lines(t, log)
	want := []string{
		"deploy serial=0a id=12 label=hook extra=yes apikey=unset cert=CERT1 key=KEY0a chain=CHAIN full=CERT1CHAIN",
		"deploy serial=0b id=12 label=hook extra=yes apikey=unset cert=CERT2 key=KEY0b chain=CHAIN full=CERT2CHAIN",
		"rollback serial=0a id=12 label=hook extra=yes apikey=unset cert=CERT1 key=KEY0a chain=CHAIN full=CERT1CHAIN",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("runs:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// Files are private and only the current and previous deployments are kept.
	base := filepath.Join(dir, "data", "exec", "12-hook")
	entries, _ := os.ReadDir(base)
	dirs := 0
	for _, e := range entries {
		if e.IsDir() {
			dirs++
			info, _ := os.Stat(filepath.Join(base, e.Name(), "key.pem"))
			if info.Mode().Perm() != 0o600 {
				t.Errorf("key.pem mode %o", info.Mode().Perm())
			}
		}
	}
	if dirs != 2 {
		t.Errorf("%d deployment dirs kept, want 2", dirs)
	}
}

func TestExecFailureRestoresPrevious(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	hook, log := script(t, dir)
	tg := New(filepath.Join(dir, "data"))
	cfg := json.RawMessage(fmt.Sprintf(`{"command":[%q]}`, hook))

	if _, err := tg.Activate(ctx, cfg, stage(t, tg, cfg, "01", "GOOD")); err != nil {
		t.Fatal(err)
	}
	_, err := tg.Activate(ctx, cfg, stage(t, tg, cfg, "02", "FAIL"))
	if err == nil {
		t.Fatal("non-zero exit was not an error")
	}
	for _, w := range []string{"exit status 3", "deploy refused", "previous files restored"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q does not mention %q", err, w)
		}
	}
	got := lines(t, log)
	if len(got) != 3 || !strings.HasPrefix(got[2], "rollback serial=01") || !strings.Contains(got[2], "cert=GOOD") {
		t.Errorf("runs = %q", got)
	}
}

func TestExecValidate(t *testing.T) {
	tg := New(t.TempDir())
	cases := map[string]string{
		`{}`:                                    "command is required",
		`{"command":["no-such-command-kk"]}`:    "not found in PATH",
		`{"command":["/no/such/file"]}`:         "/no/such/file",
		`{"command":["sh"],"timeout":"soon"}`:   "positive duration",
		`{"command":["sh"],"env":{"KK_X":"1"}}`: "reserved KK_ prefix",
		`{"command":["sh"],"env":{"1X":"1"}}`:   "not a valid variable name",
		`{"command":["sh"],"shell":true}`:       `unknown field "shell"`,
	}
	for cfg, want := range cases {
		problems, _ := tg.Validate(context.Background(), json.RawMessage(cfg))
		if !strings.Contains(strings.Join(problems, "\n"), want) {
			t.Errorf("%s: problems %q, want %q", cfg, problems, want)
		}
	}
}

func TestExecRejectsForeignRefs(t *testing.T) {
	dir := t.TempDir()
	tg := New(filepath.Join(dir, "data"))
	cfg := json.RawMessage(`{"command":["sh","-c","true"]}`)
	for _, ref := range []string{`{"dir":"/etc"}`, `{"dir":"` + dir + `/data/exec/../../x"}`, `nope`} {
		if _, err := tg.Activate(context.Background(), cfg, ref); err == nil {
			t.Errorf("Activate accepted %s", ref)
		}
		if err := tg.Rollback(context.Background(), cfg, ref); err == nil {
			t.Errorf("Rollback accepted %s", ref)
		}
	}
}
