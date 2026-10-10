package file

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/krakenkey/connector/internal/certutil"
	"github.com/krakenkey/connector/internal/testca"
	"github.com/krakenkey/connector/pkg/plugin"
)

type bundle struct {
	serial string
	req    plugin.StageRequest
}

func newBundle(t *testing.T, ca *testca.CA, settings json.RawMessage) bundle {
	t.Helper()
	key := testca.Key(t)
	leaf, leafPEM := ca.Issue(t, key.Public(), []string{"api.example.com"}, 0)
	return bundle{
		serial: certutil.SerialHex(leaf.SerialNumber),
		req: plugin.StageRequest{
			Config:        settings,
			CertificateID: "1",
			Label:         "web",
			CertPEM:       leafPEM,
			ChainPEM:      ca.IntermediatePEM,
			FullChainPEM:  leafPEM + ca.IntermediatePEM,
			Key:           plugin.KeyMaterial{Format: plugin.KeyFormatPEM, Data: []byte("KEY-" + leaf.SerialNumber.String())},
			Serial:        certutil.SerialHex(leaf.SerialNumber),
		},
	}
}

func settings(t *testing.T, dir string, extra string) json.RawMessage {
	t.Helper()
	s := fmt.Sprintf(`{"dir":%q,"files":{"cert":"cert.pem","chain":"chain.pem","fullchain":"fullchain.pem","key":"key.pem"}%s}`, dir, extra)
	return json.RawMessage(s)
}

func deploy(t *testing.T, tg Target, b bundle) string {
	t.Helper()
	ctx := context.Background()
	staged, err := tg.Stage(ctx, b.req)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	prev, err := tg.Activate(ctx, b.req.Config, staged)
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	return prev
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestValidate(t *testing.T) {
	dir := t.TempDir()
	tg := New()
	cases := []struct {
		cfg  string
		want []string
	}{
		{fmt.Sprintf(`{"dir":%q,"files":{"fullchain":"f.pem","key":"k.pem"}}`, dir), nil},
		{`{"dir":"rel","files":{"key":"k"}}`, []string{"must be an absolute path", "needs cert or fullchain"}},
		{`{"dir":"/does/not/exist","files":{"cert":"c","key":"k"}}`, []string{"/does/not/exist"}},
		{fmt.Sprintf(`{"dir":%q,"files":{"cert":"../c","key":"k/x"}}`, dir), []string{`files.cert "../c"`, `files.key "k/x"`}},
		{fmt.Sprintf(`{"dir":%q,"files":{"cert":"same","key":"same"}}`, dir), []string{"used for two files"}},
		{fmt.Sprintf(`{"dir":%q,"files":{"cert":"c"}}`, dir), []string{"files.key is required"}},
		{fmt.Sprintf(`{"dir":%q,"files":{"cert":"c","key":"k"},"mode":"0644"}`, dir), []string{"gives other users access"}},
		{fmt.Sprintf(`{"dir":%q,"files":{"cert":"c","key":"k"},"mode":"rw"}`, dir), []string{"octal file mode"}},
		{fmt.Sprintf(`{"dir":%q,"files":{"cert":"c","key":"k"},"mode":"0040"}`, dir), []string{"does not let the owner read"}},
		{fmt.Sprintf(`{"dir":%q,"files":{"cert":"c","key":"k"},"owner":"no-such-user-kk"}`, dir), []string{`unknown user "no-such-user-kk"`}},
		{fmt.Sprintf(`{"dir":%q,"files":{"cert":"c","key":"k"},"permissions":"x"}`, dir), []string{`unknown field "permissions"`}},
	}
	for _, c := range cases {
		problems, err := tg.Validate(context.Background(), json.RawMessage(c.cfg))
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(problems, "\n")
		if len(c.want) == 0 && len(problems) > 0 {
			t.Errorf("%s: unexpected problems %q", c.cfg, problems)
		}
		for _, w := range c.want {
			if !strings.Contains(joined, w) {
				t.Errorf("%s: problems %q do not mention %q", c.cfg, problems, w)
			}
		}
	}
}

func TestDeployWritesFilesAtomically(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ca := testca.New(t)
	tg := New()
	cfg := settings(t, dir, `,"mode":"0640"`)
	b := newBundle(t, ca, cfg)

	if s, err := tg.Current(ctx, cfg); err != nil || s != "" {
		t.Fatalf("Current before deploy = %q, %v", s, err)
	}

	staged, err := tg.Stage(ctx, b.req)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing is live until Activate.
	if _, err := os.Stat(filepath.Join(dir, "cert.pem")); !os.IsNotExist(err) {
		t.Fatalf("cert.pem exists after Stage: %v", err)
	}
	if _, err := tg.Activate(ctx, cfg, staged); err != nil {
		t.Fatal(err)
	}

	if got := read(t, filepath.Join(dir, "cert.pem")); got != b.req.CertPEM {
		t.Error("cert.pem content wrong")
	}
	if got := read(t, filepath.Join(dir, "chain.pem")); got != b.req.ChainPEM {
		t.Error("chain.pem content wrong")
	}
	if got := read(t, filepath.Join(dir, "fullchain.pem")); got != b.req.FullChainPEM {
		t.Error("fullchain.pem content wrong")
	}
	if got := read(t, filepath.Join(dir, "key.pem")); got != string(b.req.Key.Data) {
		t.Error("key.pem content wrong")
	}
	if runtime.GOOS != "windows" {
		for name, want := range map[string]os.FileMode{"key.pem": 0o640, "cert.pem": 0o644, "fullchain.pem": 0o644} {
			info, _ := os.Stat(filepath.Join(dir, name))
			if info.Mode().Perm() != want {
				t.Errorf("%s mode %o, want %o", name, info.Mode().Perm(), want)
			}
		}
	}
	if s, err := tg.Current(ctx, cfg); err != nil || s != b.serial {
		t.Errorf("Current = %q, %v; want %s", s, err, b.serial)
	}

	// No temp files are left behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".kk-") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
}

func TestRollbackRestoresPreviousFiles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ca := testca.New(t)
	tg := New()
	cfg := settings(t, dir, "")

	first := newBundle(t, ca, cfg)
	deploy(t, tg, first)
	second := newBundle(t, ca, cfg)
	prev := deploy(t, tg, second)

	if s, _ := tg.Current(ctx, cfg); s != second.serial {
		t.Fatalf("Current = %s, want second %s", s, second.serial)
	}
	if err := tg.Rollback(ctx, cfg, prev); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if s, _ := tg.Current(ctx, cfg); s != first.serial {
		t.Fatalf("Current after rollback = %s, want first %s", s, first.serial)
	}
	if got := read(t, filepath.Join(dir, "key.pem")); got != string(first.req.Key.Data) {
		t.Error("key.pem not restored")
	}
	if got := read(t, filepath.Join(dir, "fullchain.pem")); got != first.req.FullChainPEM {
		t.Error("fullchain.pem not restored")
	}
}

func TestRollbackOfFirstDeployRemovesFiles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	tg := New()
	cfg := settings(t, dir, "")
	// A file that existed before stays; files that did not are removed.
	if err := os.WriteFile(filepath.Join(dir, "chain.pem"), []byte("pre-existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := deploy(t, tg, newBundle(t, testca.New(t), cfg))
	if err := tg.Rollback(ctx, cfg, prev); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cert.pem", "fullchain.pem", "key.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s still present: %v", name, err)
		}
	}
	if got := read(t, filepath.Join(dir, "chain.pem")); got != "pre-existing" {
		t.Errorf("chain.pem = %q", got)
	}
}

func TestBackupsArePruned(t *testing.T) {
	dir := t.TempDir()
	ca := testca.New(t)
	tg := New()
	cfg := settings(t, dir, "")
	for range 5 {
		deploy(t, tg, newBundle(t, ca, cfg))
	}
	entries, err := os.ReadDir(filepath.Join(dir, BackupDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != keepBackups {
		t.Errorf("%d backup sets, want %d", len(entries), keepBackups)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(filepath.Join(dir, BackupDir, entries[0].Name()))
		if info.Mode().Perm() != 0o700 {
			t.Errorf("backup dir mode %o, want 700", info.Mode().Perm())
		}
	}
}

func TestStageNeedsPEMKey(t *testing.T) {
	dir := t.TempDir()
	b := newBundle(t, testca.New(t), settings(t, dir, ""))
	b.req.Key = plugin.KeyMaterial{Format: plugin.KeyFormatVaultRef, Ref: "vault://x"}
	if _, err := New().Stage(context.Background(), b.req); err == nil {
		t.Fatal("Stage accepted a vault reference")
	}
}

func TestInvalidRefs(t *testing.T) {
	dir := t.TempDir()
	cfg := settings(t, dir, "")
	for _, ref := range []string{"", "{}", `{"id":"../x"}`, "not json"} {
		if _, err := New().Activate(context.Background(), cfg, ref); err == nil {
			t.Errorf("Activate accepted %q", ref)
		}
		if err := New().Rollback(context.Background(), cfg, ref); err == nil {
			t.Errorf("Rollback accepted %q", ref)
		}
	}
}
