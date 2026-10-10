package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/krakenkey/connector/internal/fakekk"
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
	if code != exitUsage || !strings.Contains(errOut.String(), "no API key") {
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

func TestAPIKeySources(t *testing.T) {
	t.Setenv("KK_API_KEY", "kk_from_env")
	t.Setenv("KK_API_KEY_FILE", "")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	key, src, err := loadAPIKey(nil)
	if err != nil || key != "kk_from_env" || src != "KK_API_KEY" {
		t.Errorf("env: %q %q %v", key, src, err)
	}
	if os.Getenv("KK_API_KEY") != "" {
		t.Error("KK_API_KEY left in the environment")
	}

	dir := t.TempDir()
	cred := filepath.Join(dir, "kk_api_key")
	_ = os.WriteFile(cred, []byte("kk_from_credential\n"), 0o400)
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	t.Setenv("KK_API_KEY", "kk_from_env")
	key, src, err = loadAPIKey(nil)
	if err != nil || key != "kk_from_credential" || !strings.Contains(src, cred) {
		t.Errorf("credential: %q %q %v", key, src, err)
	}

	file := filepath.Join(t.TempDir(), "key")
	_ = os.WriteFile(file, []byte(" kk_from_file "), 0o600)
	t.Setenv("KK_API_KEY_FILE", file)
	key, _, err = loadAPIKey(nil)
	if err != nil || key != "kk_from_file" {
		t.Errorf("file: %q %v", key, err)
	}

	_ = os.Chmod(file, 0o644)
	if _, _, err := loadAPIKey(nil); err == nil || !strings.Contains(err.Error(), "readable by other users") {
		t.Errorf("world-readable key file: %v", err)
	}
	t.Setenv("KK_API_KEY_FILE", filepath.Join(dir, "missing"))
	if _, _, err := loadAPIKey(nil); err == nil {
		t.Error("missing key file accepted")
	}
}

func TestRunOnceExitCodes(t *testing.T) {
	cases := map[string]struct {
		status int
		header map[string]string
		want   int
	}{
		"certificate error": {http.StatusNotFound, nil, exitFailed},
		"key rejected":      {http.StatusUnauthorized, nil, exitAuth},
		"rate limited":      {http.StatusTooManyRequests, map[string]string{"Retry-After": "86400"}, exitRateLimit},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for k, v := range c.header {
					w.Header().Set(k, v)
				}
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(`{"statusCode":` + strconv.Itoa(c.status) + `,"message":"x"}`))
			}))
			defer srv.Close()
			t.Setenv("KK_API_KEY", "kk_test")
			t.Setenv("KK_API_KEY_FILE", "")
			t.Setenv("CREDENTIALS_DIRECTORY", "")
			t.Setenv("KK_API_URL", srv.URL)
			var out, errOut bytes.Buffer
			code := run([]string{"run", "--once", "--config", writeConfig(t)}, &out, &errOut)
			if code != c.want {
				t.Errorf("exit %d, want %d\n%s", code, c.want, errOut.String())
			}
		})
	}
}

// enrolEnv clears every credential variable and points the API at srv.
func enrolEnv(t *testing.T, srv *fakekk.Server) {
	t.Helper()
	for _, v := range []string{"KK_API_KEY", "KK_API_KEY_FILE", "CREDENTIALS_DIRECTORY",
		"KK_ENROLMENT_TOKEN", "KK_ENROLMENT_TOKEN_FILE"} {
		t.Setenv(v, "")
	}
	t.Setenv("KK_API_URL", srv.URL)
}

// certsNeedConnectorKey answers certificate requests with 404 when the
// bearer is a key the fake issued to a connector, and 401 otherwise.
func certsNeedConnectorKey(srv *fakekk.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if srv.Authorized(r) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"statusCode":401,"message":"Invalid API key"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"statusCode":404,"message":"Certificate not found"}`))
	})
}

// connectorID reads the enrolled connector id from the data dir.
func connectorID(t *testing.T, dataDir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dataDir, "identity", "connector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		ConnectorID string `json:"connector_id"`
	}
	if err := json.Unmarshal(data, &meta); err != nil || meta.ConnectorID == "" {
		t.Fatalf("connector.json: %v", err)
	}
	return meta.ConnectorID
}

func enrolOK(t *testing.T, srv *fakekk.Server, cfg string) string {
	t.Helper()
	srv.AddEnrolmentToken("kkce_cmd_token_0123456789abcdef", "edge-1")
	t.Setenv("KK_ENROLMENT_TOKEN", "kkce_cmd_token_0123456789abcdef")
	var out, errOut bytes.Buffer
	if code := run([]string{"enrol", "--config", cfg}, &out, &errOut); code != exitOK {
		t.Fatalf("enrol: exit %d\n%s", code, errOut.String())
	}
	return out.String()
}

func TestEnrolCommand(t *testing.T) {
	srv := fakekk.New(t)
	enrolEnv(t, srv)
	cfg := writeConfig(t)
	var out, errOut bytes.Buffer

	// No token.
	if code := run([]string{"enrol", "--config", cfg}, &out, &errOut); code != exitUsage || !strings.Contains(errOut.String(), "no enrolment token") {
		t.Errorf("no token: exit %d\n%s", code, errOut.String())
	}
	// Not an enrolment token.
	t.Setenv("KK_ENROLMENT_TOKEN", "kk_api_key_by_mistake")
	errOut.Reset()
	if code := run([]string{"enrol", "--config", cfg}, &out, &errOut); code != exitUsage || strings.Contains(errOut.String(), "by_mistake") {
		t.Errorf("API key as token: exit %d\n%s", code, errOut.String())
	}
	// A token file other users can read.
	tokenFile := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tokenFile, []byte("kkce_file_token_0123456789\n"), 0o644)
	t.Setenv("KK_ENROLMENT_TOKEN_FILE", tokenFile)
	errOut.Reset()
	if code := run([]string{"enrol", "--config", cfg}, &out, &errOut); code != exitUsage || !strings.Contains(errOut.String(), "readable by other users") {
		t.Errorf("world-readable token file: exit %d\n%s", code, errOut.String())
	}
	// A token KrakenKey does not know.
	_ = os.Chmod(tokenFile, 0o600)
	errOut.Reset()
	if code := run([]string{"enrol", "--config", cfg}, &out, &errOut); code != exitAuth || strings.Contains(errOut.String(), "kkce_file_token") {
		t.Errorf("unknown token: exit %d\n%s", code, errOut.String())
	}
	// The file wins over the environment, and the token works once.
	srv.AddEnrolmentToken("kkce_file_token_0123456789", "edge-file")
	t.Setenv("KK_ENROLMENT_TOKEN", "kkce_env_token_0123456789")
	out.Reset()
	errOut.Reset()
	if code := run([]string{"enrol", "--config", cfg}, &out, &errOut); code != exitOK {
		t.Fatalf("enrol: exit %d\n%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `Enrolled as connector "edge-file" (id `) {
		t.Errorf("output %q", out.String())
	}
	if os.Getenv("KK_ENROLMENT_TOKEN") != "" {
		t.Error("KK_ENROLMENT_TOKEN left in the environment")
	}
	if strings.Contains(out.String()+errOut.String(), "kkce_") {
		t.Error("token printed")
	}
	// A second enrolment is refused without --force.
	errOut.Reset()
	if code := run([]string{"enrol", "--config", cfg}, &out, &errOut); code != exitUsage || !strings.Contains(errOut.String(), "already enrolled") {
		t.Errorf("re-enrol: exit %d\n%s", code, errOut.String())
	}
	// --force with a new token keeps a backup.
	srv.AddEnrolmentToken("kkce_file_token_0123456789", "edge-new")
	out.Reset()
	if code := run([]string{"enrol", "--force", "--config", cfg}, &out, &errOut); code != exitOK || !strings.Contains(out.String(), "Kept the previous identity file") {
		t.Errorf("forced re-enrol: exit %d\n%s\n%s", code, out.String(), errOut.String())
	}
}

func TestRunWithIdentity(t *testing.T) {
	srv := fakekk.New(t)
	srv.Fallback = certsNeedConnectorKey(srv)
	enrolEnv(t, srv)
	cfg := writeConfig(t)
	enrolOK(t, srv, cfg)

	t.Setenv("KK_API_KEY", "kk_ignored_because_enrolled")
	var out, errOut bytes.Buffer
	// The fake has no certificate 7, so the pass fails with 404 after
	// authenticating with a connector-issued key (a 401 would exit 3).
	if code := run([]string{"run", "--once", "--config", cfg}, &out, &errOut); code != exitFailed {
		t.Errorf("exit %d\n%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "the API key is ignored") {
		t.Errorf("no warning about the ignored API key:\n%s", errOut.String())
	}
	if strings.Contains(errOut.String(), "kk_ignored") || srv.TokenCalls() != 1 {
		t.Errorf("token calls %d\n%s", srv.TokenCalls(), errOut.String())
	}
}

func TestRunWithRevokedIdentity(t *testing.T) {
	srv := fakekk.New(t)
	srv.Fallback = certsNeedConnectorKey(srv)
	enrolEnv(t, srv)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	_ = os.WriteFile(cfg, []byte(`
data_dir: `+filepath.Join(dir, "data")+`
certificates:
  - id: 7
    names: [api.example.com]
    targets: [{ label: a, plugin: exec, command: [/bin/true] }]
  - id: 8
    names: [www.example.com]
    targets: [{ label: b, plugin: exec, command: [/bin/true] }]
`), 0o600)
	enrolOK(t, srv, cfg)
	srv.Revoke(connectorID(t, filepath.Join(dir, "data")))

	var out, errOut bytes.Buffer
	if code := run([]string{"run", "--once", "--config", cfg}, &out, &errOut); code != exitIdentity {
		t.Errorf("exit %d, want %d\n%s", code, exitIdentity, errOut.String())
	}
	if n := srv.TokenCalls(); n != 1 {
		t.Errorf("%d token requests after a 401, want 1", n)
	}
	for _, r := range srv.Requests() {
		if strings.Contains(r, "/certs/") {
			t.Errorf("called %s without a key", r)
		}
	}
}

func TestValidateShowsEnrolment(t *testing.T) {
	srv := fakekk.New(t)
	srv.Fallback = certsNeedConnectorKey(srv)
	enrolEnv(t, srv)
	cfg := writeConfig(t)
	var out, errOut bytes.Buffer
	_ = run([]string{"validate", "--offline", "--config", cfg}, &out, &errOut)
	if !strings.Contains(out.String(), "Identity:   not enrolled") {
		t.Errorf("not enrolled:\n%s", out.String())
	}

	enrolOK(t, srv, cfg)
	out.Reset()
	_ = run([]string{"validate", "--config", cfg}, &out, &errOut)
	for _, want := range []string{`Identity:   enrolled as connector "edge-1" (id `, "Token:      exchange works (short-lived key valid until "} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}

	srv.Revoke(connectorID(t, filepath.Join(filepath.Dir(cfg), "data")))
	out.Reset()
	if code := run([]string{"validate", "--config", cfg}, &out, &errOut); code != exitFailed || !strings.Contains(out.String(), "Token:      PROBLEM: token exchange failed") {
		t.Errorf("revoked: exit %d\n%s", code, out.String())
	}
}

func TestRotateIdentityCommand(t *testing.T) {
	srv := fakekk.New(t)
	enrolEnv(t, srv)
	cfg := writeConfig(t)
	var out, errOut bytes.Buffer
	_ = os.MkdirAll(filepath.Join(filepath.Dir(cfg), "data"), 0o700)
	if code := run([]string{"rotate-identity", "--config", cfg}, &out, &errOut); code != exitUsage || !strings.Contains(errOut.String(), "not enrolled") {
		t.Errorf("not enrolled: exit %d\n%s", code, errOut.String())
	}
	enrolOK(t, srv, cfg)
	keyPath := filepath.Join(filepath.Dir(cfg), "data", "identity", "identity.key")
	before, _ := os.ReadFile(keyPath)
	out.Reset()
	if code := run([]string{"rotate-identity", "--config", cfg}, &out, &errOut); code != exitOK {
		t.Fatalf("rotate: exit %d\n%s", code, errOut.String())
	}
	after, _ := os.ReadFile(keyPath)
	if bytes.Equal(before, after) || srv.RotateCalls() != 1 || !strings.Contains(out.String(), "Rotated the identity key") {
		t.Errorf("rotation: %d calls, output %q", srv.RotateCalls(), out.String())
	}
	if strings.Contains(out.String()+errOut.String(), "PRIVATE KEY") {
		t.Error("key printed")
	}
	// The rotated identity still gets tokens.
	out.Reset()
	if code := run([]string{"validate", "--config", cfg}, &out, &errOut); !strings.Contains(out.String(), "exchange works") {
		t.Errorf("after rotation: exit %d\n%s", code, out.String())
	}
}

func TestRunReportsStatusWhenEnrolled(t *testing.T) {
	srv := fakekk.New(t)
	srv.Fallback = certsNeedConnectorKey(srv)
	enrolEnv(t, srv)
	cfg := writeConfig(t)

	// With a plain API key, nothing is reported.
	srv.Fallback = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	t.Setenv("KK_API_KEY", "kk_plain_key_for_test")
	var out, errOut bytes.Buffer
	_ = run([]string{"run", "--once", "--log-level", "debug", "--config", cfg}, &out, &errOut)
	if len(srv.Reports()) != 0 || !strings.Contains(errOut.String(), "not enrolled") {
		t.Errorf("reported without enrolment\n%s", errOut.String())
	}

	srv.Fallback = certsNeedConnectorKey(srv)
	t.Setenv("KK_API_KEY", "")
	enrolOK(t, srv, cfg)
	errOut.Reset()
	// Certificate 7 does not exist, so the pass fails; the report still goes out.
	if code := run([]string{"run", "--once", "--config", cfg}, &out, &errOut); code != exitFailed {
		t.Fatalf("exit %d\n%s", code, errOut.String())
	}
	reports := srv.Reports()
	if len(reports) != 1 {
		t.Fatalf("%d reports\n%s", len(reports), errOut.String())
	}
	var rep struct {
		Version, OS, Arch string
		Certificates      []struct {
			CertificateID int
			Targets       []struct{ Label, State, Error string }
		}
	}
	_ = json.Unmarshal(reports[0], &rep)
	if rep.Version != "dev" || len(rep.Certificates) != 1 || rep.Certificates[0].CertificateID != 7 {
		t.Fatalf("report %s", reports[0])
	}
	tg := rep.Certificates[0].Targets
	if len(tg) != 1 || tg[0].Label != "hook" || tg[0].State != "pending" || !strings.Contains(tg[0].Error, "not found") {
		t.Errorf("targets %+v", tg)
	}

	// A report KrakenKey refuses does not change the exit code.
	srv.ReportStatus = http.StatusInternalServerError
	errOut.Reset()
	if code := run([]string{"run", "--once", "--config", cfg}, &out, &errOut); code != exitFailed {
		t.Errorf("exit %d after a failed report\n%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "could not report deployment status") {
		t.Errorf("no warning\n%s", errOut.String())
	}
}
