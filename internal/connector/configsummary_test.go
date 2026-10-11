package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/krakenkey/connector/internal/api"
	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/deploy"
	"github.com/krakenkey/connector/internal/pluginhost"
	"github.com/krakenkey/connector/pkg/plugin"
)

// sentConfigs records config summary calls.
type sentConfigs struct {
	puts    []api.ConfigSummary
	hashes  []string
	deletes int
	err     error
}

func (s *sentConfigs) PutConfigSummary(_ context.Context, hash string, sum api.ConfigSummary) error {
	s.puts = append(s.puts, sum)
	s.hashes = append(s.hashes, hash)
	return s.err
}

func (s *sentConfigs) DeleteConfigSummary(context.Context) error {
	s.deletes++
	return s.err
}

// locations is a PluginLocator with fixed answers; built-in plugins are
// found as the host finds them.
type locations map[string]pluginhost.Location

func (l locations) Locate(name string) pluginhost.Location {
	if name == config.BuiltinLocal || name == config.BuiltinFile || name == config.BuiltinExec {
		return pluginhost.Location{Source: pluginhost.SourceBuiltin}
	}
	return l[name]
}

// secretConfig sets every setting the summary must leave out to a value
// containing "SECRET".
func secretConfig(t *testing.T) *config.Config {
	return writeConfig(t, fmt.Sprintf(`
data_dir: %s
check_interval: 1h
plugins:
  azure-keyvault: { path: /opt/SECRET/kv, sha256: %s }
  azure-appgateway: { version: 0.2.0 }
  aws-acm: {}
  third-party: { path: /opt/tp }
certificates:
  - id: 42
    names: [www.example.com]
    key_store: { plugin: azure-keyvault, vault: kv-prod, certificate_name: www, reuse_key: true, client_secret: SECRET-ks }
    targets:
      - label: nginx-main
        plugin: file
        dir: /etc/nginx/certs
        files: { fullchain: site.pem, key: site.key }
        owner: SECRET-owner
        mode: "0640"
        then: { exec: [/usr/sbin/nginx, -s, reload, SECRET-then] }
        verify: { host: www.example.com, port: 8443 }
      - label: hook
        plugin: exec
        command: [/usr/local/bin/SECRET-cmd]
        env: { TOKEN: SECRET-env }
        verify: { host: www.example.com, address: "SECRET.internal:443", ca_file: /etc/SECRET/ca.pem }
      - label: kv-dr
        plugin: azure-keyvault
        vault: kv-dr
        certificate_name: www
        tags: { team: SECRET-tag }
      - label: appgw
        plugin: azure-appgateway
        subscription_id: SECRET-sub
        resource_group: rg-web
        gateway: agw-prod
        ssl_certificate: www
        replace_uploaded_certificate: true
      - label: acm
        plugin: aws-acm
        region: us-east-1
        certificate_arn: "arn:aws:acm:us-east-1:SECRET:certificate/x"
        verify: { host: www.example.com, skip_chain_validation: true }
      - label: other
        plugin: third-party
        api_token: SECRET-tp
        region: us-west-2
`, filepath.Join(t.TempDir(), "data"), strings.Repeat("ab", 32)))
}

func secretLocations() locations {
	return locations{
		"azure-keyvault":   {Source: pluginhost.SourcePath, Path: "/opt/SECRET/kv"},
		"azure-appgateway": {Source: pluginhost.SourceDataDir, Version: "0.2.0", Path: "/var/lib/SECRET"},
		"aws-acm":          {Source: pluginhost.SourcePluginDir, Version: "0.2.0", Bundled: true, SHA256: "SECRET"},
		"third-party":      {Source: pluginhost.SourcePath},
	}
}

func TestConfigSummaryAllowlist(t *testing.T) {
	cfg := secretConfig(t)
	s := &ConfigSharer{Config: cfg, Plugins: secretLocations(), Version: "0.3.0", Log: slog.New(slog.DiscardHandler)}
	sum, cut := s.Build()
	if len(cut) != 0 || sum.Truncated {
		t.Errorf("cut %v", cut)
	}
	b, _ := json.Marshal(sum)
	if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "0640") {
		t.Fatalf("summary leaks settings: %s", b)
	}

	want := `{"version":"0.3.0","checkIntervalSeconds":3600,"plugins":[` +
		`{"name":"aws-acm","version":"0.2.0","source":"bundled"},` +
		`{"name":"azure-appgateway","version":"0.2.0","source":"data_dir"},` +
		`{"name":"azure-keyvault","version":null,"source":"path"},` +
		`{"name":"exec","version":"0.3.0","source":"builtin"},` +
		`{"name":"file","version":"0.3.0","source":"builtin"},` +
		`{"name":"third-party","version":null,"source":"path"}],` +
		`"certificates":[{"certificateId":42,"names":["www.example.com"],` +
		`"keyStore":{"plugin":"azure-keyvault","keyType":"ecdsa-p256","settings":{"certificate_name":"www","reuse_key":true,"vault":"kv-prod"}},` +
		`"targets":[` +
		`{"label":"nginx-main","plugin":"file","implicit":false,"runsCommand":true,"verify":{"host":"www.example.com","port":8443,"skipChainValidation":false},` +
		`"settings":{"dir":"/etc/nginx/certs","fullchain":"site.pem","key":"site.key"}},` +
		`{"label":"hook","plugin":"exec","implicit":false,"runsCommand":true,"verify":{"host":"www.example.com","port":null,"skipChainValidation":false},"settings":{}},` +
		`{"label":"kv-dr","plugin":"azure-keyvault","implicit":false,"runsCommand":false,"verify":null,"settings":{"certificate_name":"www","vault":"kv-dr"}},` +
		`{"label":"appgw","plugin":"azure-appgateway","implicit":false,"runsCommand":false,"verify":null,` +
		`"settings":{"gateway":"agw-prod","replace_uploaded_certificate":true,"resource_group":"rg-web","ssl_certificate":"www"}},` +
		`{"label":"acm","plugin":"aws-acm","implicit":false,"runsCommand":false,"verify":{"host":"www.example.com","port":443,"skipChainValidation":true},"settings":{"region":"us-east-1"}},` +
		`{"label":"other","plugin":"third-party","implicit":false,"runsCommand":false,"verify":null,"settings":{}}]}],` +
		`"truncated":false}`
	if string(b) != want {
		t.Errorf("summary\n got %s\nwant %s", b, want)
	}
}

func TestConfigSummaryHashAndResend(t *testing.T) {
	cfg := secretConfig(t)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	sent := &sentConfigs{}
	s := &ConfigSharer{API: sent, Config: cfg, Plugins: secretLocations(), Version: "0.3.0",
		Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return now }}

	s.Share(context.Background())
	if len(sent.puts) != 1 {
		t.Fatalf("%d summaries sent", len(sent.puts))
	}
	first := sent.hashes[0]
	if want, _ := api.ConfigSummaryHash(sent.puts[0]); first != want || len(first) != 64 {
		t.Errorf("hash %s, want %s", first, want)
	}
	// The same config gives the same hash, whatever the map order.
	for range 20 {
		sum, _ := s.Build()
		if h, _ := api.ConfigSummaryHash(sum); h != first {
			t.Fatalf("hash changed without a config change: %s", h)
		}
	}

	// Unchanged: not sent again within 24 hours, sent again after.
	now = now.Add(23 * time.Hour)
	s.Share(context.Background())
	if len(sent.puts) != 1 {
		t.Errorf("unchanged summary sent again after 23h")
	}
	now = now.Add(time.Hour)
	s.Share(context.Background())
	if len(sent.puts) != 2 || sent.hashes[1] != first {
		t.Errorf("unchanged summary not sent again after 24h: %d", len(sent.puts))
	}

	// A pass that resolves different targets changes the hash.
	cert := cfg.Certificates[0]
	cert.Targets = append([]config.Target{{Label: "azure-keyvault", Plugin: "azure-keyvault", Implicit: true, KeyStoreDeployment: true,
		Settings: map[string]any{"vault": "kv-prod", "certificate_name": "www", "tags": map[string]any{"a": "SECRET"}}}}, cert.Targets...)
	s.Remember(map[int]config.Certificate{42: cert})
	s.Share(context.Background())
	if len(sent.puts) != 3 || sent.hashes[2] == first {
		t.Fatalf("changed summary not sent: %d", len(sent.puts))
	}
	got := sent.puts[2].Certificates[0].Targets[0]
	if !got.Implicit || got.Label != "azure-keyvault" || got.RunsCommand || len(got.Settings) != 2 {
		t.Errorf("implicit target %+v", got)
	}

	// A failed send is retried on the next pass.
	cfg.CheckInterval = 2 * time.Hour
	sent.err = errors.New("boom")
	s.Share(context.Background())
	sent.err = nil
	s.Share(context.Background())
	if len(sent.puts) != 5 || sent.hashes[3] != sent.hashes[4] {
		t.Errorf("failed send not retried: %d", len(sent.puts))
	}
}

func TestConfigSummaryStopsOnMissingRoute(t *testing.T) {
	for name, err := range map[string]error{
		"404": &api.NotFoundError{Message: "Cannot PUT /connectors/config"},
		"405": &api.APIError{StatusCode: http.StatusMethodNotAllowed},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := secretConfig(t)
			sent := &sentConfigs{err: err}
			s := &ConfigSharer{API: sent, Config: cfg, Plugins: secretLocations(), Log: slog.New(slog.DiscardHandler)}
			for range 3 {
				s.Share(context.Background())
			}
			if len(sent.puts) != 1 {
				t.Errorf("%d summaries sent", len(sent.puts))
			}
		})
	}
	// Other errors are retried.
	sent := &sentConfigs{err: &api.APIError{StatusCode: http.StatusInternalServerError}}
	s := &ConfigSharer{API: sent, Config: secretConfig(t), Plugins: secretLocations(), Log: slog.New(slog.DiscardHandler)}
	s.Share(context.Background())
	s.Share(context.Background())
	if len(sent.puts) != 2 {
		t.Errorf("%d summaries sent after a 500", len(sent.puts))
	}
}

func TestConfigSummaryShareConfigOff(t *testing.T) {
	cfg := secretConfig(t)
	off := false
	cfg.KrakenKey.ShareConfig = &off
	for _, err := range []error{nil, errors.New("boom"), &api.NotFoundError{}} {
		sent := &sentConfigs{err: err}
		s := &ConfigSharer{API: sent, Config: cfg, Plugins: secretLocations(), Log: slog.New(slog.DiscardHandler)}
		for range 3 {
			s.Share(context.Background())
		}
		if sent.deletes != 1 || len(sent.puts) != 0 {
			t.Errorf("error %v: %d deletes, %d summaries", err, sent.deletes, len(sent.puts))
		}
	}
}

func TestConfigSummaryLimits(t *testing.T) {
	cfg := &config.Config{CheckInterval: 30 * 24 * time.Hour, Plugins: map[string]config.PluginSpec{}}
	for i := range 60 {
		cfg.Plugins[fmt.Sprintf("p%02d", i)] = config.PluginSpec{}
	}
	for i := range api.MaxReportCertificates + 1 {
		cfg.Certificates = append(cfg.Certificates, config.Certificate{ID: i + 1, Names: []string{"a.example.com"},
			KeyStore: config.KeyStore{Plugin: "local", KeyType: plugin.KeyTypeECDSAP256},
			Targets:  []config.Target{{Label: "t", Plugin: "exec"}}})
	}
	big := &cfg.Certificates[0]
	big.Names, big.Targets = nil, nil
	for i := range api.MaxConfigNames + 5 {
		big.Names = append(big.Names, fmt.Sprintf("n%d.example.com", i))
	}
	for i := range api.MaxReportTargets + 5 {
		big.Targets = append(big.Targets, config.Target{Label: fmt.Sprintf("t%d", i), Plugin: "file",
			Settings: map[string]any{"dir": "/srv/" + strings.Repeat("d\x01", 200), "files": map[string]any{"key": "k.pem"}}})
	}
	loc := locations{}
	for name := range cfg.Plugins {
		loc[name] = pluginhost.Location{Source: pluginhost.SourcePluginDir, Version: "1.0.0"}
	}
	s := &ConfigSharer{Config: cfg, Plugins: loc, Version: "dev"}
	sum, cut := s.Build()
	if !sum.Truncated || len(cut) != 4+api.MaxReportTargets || cut[4] != "certificate 1: target t0: setting dir" {
		t.Errorf("cut %q", cut)
	}
	if len(sum.Plugins) != api.MaxConfigPlugins || len(sum.Certificates) != api.MaxReportCertificates ||
		len(sum.Certificates[0].Names) != api.MaxConfigNames || len(sum.Certificates[0].Targets) != api.MaxReportTargets {
		t.Errorf("plugins %d, certificates %d, names %d, targets %d", len(sum.Plugins), len(sum.Certificates),
			len(sum.Certificates[0].Names), len(sum.Certificates[0].Targets))
	}
	if sum.CheckIntervalSeconds != nil {
		t.Errorf("check interval %d over the API's limit", *sum.CheckIntervalSeconds)
	}
	dir := sum.Certificates[0].Targets[0].Settings["dir"].(string)
	if len(dir) != api.MaxConfigSettingValue || strings.ContainsRune(dir, '\x01') || !strings.HasPrefix(dir, "/srv/d d ") {
		t.Errorf("dir %q", dir)
	}
}

func TestConfigSummaryValues(t *testing.T) {
	out := allowedSettings("azure-keyvault", map[string]any{
		"vault": "kv", "exportable": false, "reuse_key": json.Number("1"), "adopt": map[string]any{"x": 1},
		"certificate_name": nil,
	}, "", new([]string))
	if fmt.Sprint(out) != "map[exportable:false reuse_key:1 vault:kv]" {
		t.Errorf("settings %v", out)
	}
	if out := allowedSettings("file", map[string]any{"files": "not a map"}, "", new([]string)); len(out) != 0 {
		t.Errorf("settings %v", out)
	}
}

// TestConfigSummaryImplicitTargetAfterPass checks that the summary has
// the configured targets before a certificate's first pass, and the
// target its key store added after it, also on later passes for other
// certificates.
func TestConfigSummaryImplicitTargetAfterPass(t *testing.T) {
	e := newVaultEnv(t)
	cfg := e.config("")
	sent := &sentConfigs{}
	e.sharer = &ConfigSharer{API: sent, Config: cfg, Plugins: locations{"vault": {Source: pluginhost.SourcePath}},
		Version: "dev", Log: slog.New(slog.DiscardHandler)}
	if sum, _ := e.sharer.Build(); len(sum.Certificates[0].Targets) != 0 {
		t.Errorf("targets before the first pass: %+v", sum.Certificates[0].Targets)
	}
	if err := e.run(cfg, false); err != nil {
		t.Fatal(err)
	}
	if len(sent.puts) != 1 {
		t.Fatalf("%d summaries sent", len(sent.puts))
	}
	tg := sent.puts[0].Certificates[0].Targets
	if len(tg) != 1 || tg[0].Label != "vault" || tg[0].Plugin != "vault" || !tg[0].Implicit || len(tg[0].Settings) != 0 {
		t.Errorf("targets %+v", tg)
	}
	// A pass for another certificate keeps what this one resolved.
	e.sharer.Remember(map[int]config.Certificate{})
	if sum, _ := e.sharer.Build(); len(sum.Certificates[0].Targets) != 1 {
		t.Errorf("implicit target forgotten: %+v", sum.Certificates[0].Targets)
	}
	// Unchanged after a second pass: nothing new is sent.
	if err := e.run(cfg, false); err != nil {
		t.Fatal(err)
	}
	if len(sent.puts) != 1 {
		t.Errorf("%d summaries sent", len(sent.puts))
	}
}

func TestConfigSummaryNotSentWhenPassStops(t *testing.T) {
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
	for name, c := range map[string]struct {
		err  error
		sent bool
	}{
		"failed pass":  {&api.NotFoundError{Message: "x"}, true},
		"key refused":  {&api.AuthError{Message: "x"}, false},
		"rate limited": {&api.RateLimitError{RetryAfter: time.Hour}, false},
	} {
		t.Run(name, func(t *testing.T) {
			sent := &sentConfigs{}
			conn := &Connector{
				Config: cfg, Resolver: newResolver(t, cfg, log), Log: log,
				Engine:       &deploy.Engine{API: failingAPI{c.err}, State: store, Log: log},
				ConfigSharer: &ConfigSharer{API: sent, Config: cfg, Plugins: locations{}, Log: log},
			}
			if err := conn.RunOnce(context.Background(), RunOptions{}); !errors.Is(err, c.err) {
				t.Errorf("pass result changed: %v", err)
			}
			if got := len(sent.puts) > 0; got != c.sent {
				t.Errorf("sent %v, want %v", got, c.sent)
			}
		})
	}
}
