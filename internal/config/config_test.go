package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/krakenkey/connector/pkg/plugin"
)

const example = `
krakenkey:
  api_url: https://api.krakenkey.io
check_interval: 6h
data_dir: /var/lib/krakenkey-connector
audit_log: /var/log/krakenkey-connector/audit.jsonl
plugins:
  azure-keyvault: { version: 0.1.0 }
certificates:
  - id: 1043
    names: [api.example.com]
    key_store: { plugin: local, key_type: ecdsa-p256 }
    targets:
      - label: example-nginx
        plugin: file
        dir: /etc/nginx/tls/api
        files: { cert: cert.pem, chain: chain.pem, fullchain: fullchain.pem, key: key.pem }
        owner: "root:nginx"
        mode: "0640"
        then: { exec: [systemctl, reload, nginx] }
        verify: { host: api.example.com, port: 443, window: 10m }
      - label: local-dev
        plugin: file
        dir: /srv/tls
        files: { fullchain: fullchain.pem, key: key.pem }
        verify: { host: api.example.com, address: "127.0.0.1:8443", skip_chain_validation: true }
`

func TestParseExample(t *testing.T) {
	t.Setenv("KK_API_URL", "")
	cfg, err := Parse(strings.NewReader(example))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.CheckInterval != 6*time.Hour || cfg.AuditLog != "/var/log/krakenkey-connector/audit.jsonl" {
		t.Errorf("top level = %+v", cfg)
	}
	if cfg.Plugins["azure-keyvault"].Version != "0.1.0" {
		t.Errorf("plugins = %+v", cfg.Plugins)
	}
	c := cfg.Certificates[0]
	if c.ID != 1043 || c.KeyStore.Plugin != "local" || c.KeyStore.KeyType != plugin.KeyTypeECDSAP256 {
		t.Errorf("certificate = %+v", c)
	}

	nginx := c.Targets[0]
	if nginx.Then == nil || strings.Join(nginx.Then.Exec, " ") != "systemctl reload nginx" || nginx.Then.Timeout != DefaultThenTimeout {
		t.Errorf("then = %+v", nginx.Then)
	}
	if nginx.Verify.DialAddress() != "api.example.com:443" || nginx.Verify.Window != 10*time.Minute {
		t.Errorf("verify = %+v", nginx.Verify)
	}

	// Plugin settings exclude the fields the core owns.
	raw, err := nginx.SettingsJSON()
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	_ = json.Unmarshal(raw, &settings)
	for _, k := range []string{"label", "plugin", "then", "verify"} {
		if _, ok := settings[k]; ok {
			t.Errorf("settings include core field %q", k)
		}
	}
	if settings["dir"] != "/etc/nginx/tls/api" || settings["mode"] != "0640" || settings["owner"] != "root:nginx" {
		t.Errorf("settings = %v", settings)
	}
	if files, _ := settings["files"].(map[string]any); files["fullchain"] != "fullchain.pem" {
		t.Errorf("files = %v", settings["files"])
	}

	dev := c.Targets[1]
	if dev.Verify.DialAddress() != "127.0.0.1:8443" || dev.Verify.Host != "api.example.com" || !dev.Verify.SkipChainValidation {
		t.Errorf("dev verify = %+v", dev.Verify)
	}

	if w := cfg.Warnings(); len(w) != 1 || !strings.Contains(w[0], "local-dev skips chain validation") {
		t.Errorf("warnings = %q", w)
	}
}

func TestDefaults(t *testing.T) {
	t.Setenv("KK_API_URL", "")
	cfg, err := Parse(strings.NewReader(`
certificates:
  - id: 7
    names: [Example.COM]
    targets:
      - { label: a, plugin: exec, command: [/bin/true] }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.KrakenKey.APIURL != DefaultAPIURL || cfg.CheckInterval != DefaultCheckInterval ||
		cfg.DataDir != DefaultDataDir || cfg.AuditLog != DefaultDataDir+"/audit.jsonl" {
		t.Errorf("defaults = %+v", cfg)
	}
	c := cfg.Certificates[0]
	if c.KeyStore.Plugin != BuiltinLocal || c.KeyStore.KeyType != DefaultKeyType {
		t.Errorf("key store defaults = %+v", c.KeyStore)
	}
	if c.Names[0] != "example.com" {
		t.Errorf("names not lowercased: %v", c.Names)
	}
	if w := cfg.Warnings(); len(w) != 1 || !strings.Contains(w[0], "no verify block") {
		t.Errorf("warnings = %q", w)
	}
}

func TestAPIURLFromEnv(t *testing.T) {
	t.Setenv("KK_API_URL", "https://api-dev.krakenkey.io/")
	cfg, err := Parse(strings.NewReader(example))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KrakenKey.APIURL != "https://api-dev.krakenkey.io" {
		t.Errorf("api_url = %q", cfg.KrakenKey.APIURL)
	}
}

func TestValidationErrors(t *testing.T) {
	t.Setenv("KK_API_URL", "")
	tests := []struct {
		name string
		yaml string
		want []string
	}{
		{"empty", ``, []string{"config is empty"}},
		{"unknown top-level field", "certificate: []\n", []string{"field certificate not found"}},
		{"no certificates", "check_interval: 6h\n", []string{"at least one certificate"}},
		{"http api url", `
krakenkey: { api_url: "http://api.example.com" }
certificates: [{ id: 1, names: [a.example.com], targets: [{ label: x, plugin: file }] }]
`, []string{"must use https"}},
		{"http allowed on localhost", `
krakenkey: { api_url: "http://localhost:8080" }
certificates: [{ id: 1, names: [a.example.com], targets: [{ label: x, plugin: file }] }]
`, nil},
		{"many problems at once", `
check_interval: 10s
data_dir: relative/dir
plugins:
  file: { version: 1.0.0 }
  Bad_Name: { path: /x }
  nover: {}
  badsum: { version: 1.0.0, sha256: abc }
certificates:
  - id: 0
    names: []
    targets: []
  - id: 5
    names: [ok.example.com, ok.example.com, "bad name", localhost]
    key_store: { plugin: vault, key_type: rsa-1024 }
    targets:
      - { label: "", plugin: file }
      - { label: t, plugin: nope }
      - { label: t, plugin: file, then: { exec: [] } }
      - { label: v1, plugin: file, verify: { port: 70000 } }
      - { label: v2, plugin: file, verify: { host: a.example.com, address: "nohostport" } }
      - { label: v3, plugin: file, verify: { host: a.example.com, address: "h:1", port: 2 } }
      - { label: v4, plugin: file, verify: { host: a.example.com, ca_file: /ca.pem, skip_chain_validation: true } }
      - { label: v5, plugin: file, verify: { host: a.example.com, ca_file: ca.pem, window: -1s } }
  - id: 5
    names: [b.example.com]
    targets: [{ label: x, plugin: exec }]
`, []string{
			"check_interval 10s is shorter",
			`data_dir "relative/dir" must be an absolute path`,
			`plugins.file: "file" is a built-in plugin`,
			"plugins.Bad_Name: name must be lowercase",
			"plugins.nover: set version or path",
			"plugins.badsum: sha256 must be 64 hex characters",
			"certificates[0]: id must be a positive",
			"certificates[0]: names must list at least one",
			"certificates[0]: targets must list at least one",
			`certificate 5: name "ok.example.com" is listed twice`,
			`certificate 5: "bad name" is not a valid DNS name`,
			`certificate 5: "localhost" is not a valid DNS name`,
			`key_store plugin "vault" is not built in and not declared`,
			`unknown key type "rsa-1024"`,
			`targets[0]: label "" must be`,
			`target t: plugin "nope" is not built in`,
			"target t: label is used twice",
			"target t: then.exec needs a command",
			"target v1: verify: host is required",
			"target v1: verify: port 70000 is out of range",
			`target v2: verify: address "nohostport" must be host:port`,
			"target v3: verify: set address or port, not both",
			"target v4: verify: ca_file and skip_chain_validation cannot both be set",
			"target v5: verify: window must not be negative",
			"target v5: verify: ca_file must be an absolute path",
			"certificate 5: listed more than once",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tt.yaml))
			if len(tt.want) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error does not mention %q:\n%v", w, err)
				}
			}
		})
	}
}

func TestWildcardAndKeyTypes(t *testing.T) {
	t.Setenv("KK_API_URL", "")
	for _, kt := range []string{"ecdsa-p256", "RSA-2048", "rsa-3072"} {
		_, err := Parse(strings.NewReader(`
certificates:
  - id: 1
    names: ["*.example.com", example.com]
    key_store: { key_type: ` + kt + ` }
    targets: [{ label: x, plugin: file }]
`))
		if err != nil {
			t.Errorf("key type %s: %v", kt, err)
		}
	}
}
