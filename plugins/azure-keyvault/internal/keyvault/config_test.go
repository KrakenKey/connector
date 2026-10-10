package keyvault

import (
	"errors"
	"strings"
	"testing"

	"github.com/krakenkey/connector/pkg/plugin"
)

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name       string
		config     string
		vault      string
		exportable bool
		reuse      bool
		problem    string
	}{
		{name: "vault name", config: `{"vault":"My-Vault1","certificate_name":"web"}`,
			vault: "https://my-vault1.vault.azure.net", exportable: true},
		{name: "vault URL", config: `{"vault":"https://kv.vault.azure.cn/","certificate_name":"web"}`,
			vault: "https://kv.vault.azure.cn", exportable: true},
		{name: "vault URL with default port", config: `{"vault":"https://KV1.vault.azure.net:443","certificate_name":"web"}`,
			vault: "https://kv1.vault.azure.net", exportable: true},
		{name: "vault URL with port", config: `{"vault":"https://127.0.0.1:8443","certificate_name":"web"}`,
			vault: "https://127.0.0.1:8443", exportable: true},
		{name: "not exportable, reuse key", config: `{"vault":"kv1","certificate_name":"web","exportable":false,"reuse_key":true}`,
			vault: "https://kv1.vault.azure.net", reuse: true},
		{name: "empty config", config: ``, problem: "vault is required"},
		{name: "missing name", config: `{"vault":"kv1"}`, problem: "certificate_name is required"},
		{name: "bad name", config: `{"vault":"kv1","certificate_name":"web_cert"}`, problem: "not a valid Key Vault object name"},
		{name: "short vault name", config: `{"vault":"kv","certificate_name":"web"}`, problem: "not a valid vault name"},
		{name: "double hyphen", config: `{"vault":"my--vault","certificate_name":"web"}`, problem: "not a valid vault name"},
		{name: "http URL", config: `{"vault":"http://kv1.vault.azure.net","certificate_name":"web"}`, problem: "must use https"},
		{name: "URL with path", config: `{"vault":"https://kv1.vault.azure.net/certificates","certificate_name":"web"}`, problem: "vault URL alone"},
		{name: "URL with credentials", config: `{"vault":"https://u:p@kv1.vault.azure.net","certificate_name":"web"}`, problem: "credentials"},
		{name: "unknown key", config: `{"vault":"kv1","certificate_name":"web","exportible":true}`, problem: "unknown field"},
		{name: "wrong type", config: `{"vault":"kv1","certificate_name":"web","exportable":"yes"}`, problem: "key_store settings"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, problems := parseConfig([]byte(tt.config))
			if tt.problem != "" {
				if !strings.Contains(strings.Join(problems, "|"), tt.problem) {
					t.Fatalf("problems = %q, want one containing %q", problems, tt.problem)
				}
				return
			}
			if len(problems) > 0 {
				t.Fatalf("unexpected problems: %q", problems)
			}
			if s.vaultURL != tt.vault || s.exportable != tt.exportable || s.reuseKey != tt.reuse || s.name == "" {
				t.Errorf("settings = %+v", s)
			}
		})
	}
}

func TestParseConfigReportsEveryProblem(t *testing.T) {
	_, problems := parseConfig([]byte(`{"vault":"x","certificate_name":"a b"}`))
	if len(problems) != 2 {
		t.Fatalf("problems = %q, want two", problems)
	}
}

func TestKeyParams(t *testing.T) {
	for _, kt := range plugin.AllKeyTypes {
		kp, err := keyParams(kt)
		if err != nil {
			t.Fatalf("%s: %v", kt, err)
		}
		switch {
		case kt.IsRSA() && (string(*kp.KeyType) != "RSA" || kp.KeySize == nil || kp.Curve != nil):
			t.Errorf("%s: %+v", kt, kp)
		case kt.IsECDSA() && (string(*kp.KeyType) != "EC" || kp.Curve == nil || kp.KeySize != nil):
			t.Errorf("%s: %+v", kt, kp)
		}
	}
	if _, err := keyParams("ed25519"); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("ed25519: err = %v, want ErrPermanent", err)
	}
}

func TestCheckNames(t *testing.T) {
	for _, ok := range [][]string{{"example.com"}, {"*.example.com", "example.com"}, {"a-b.c1.example"}, {"localhost"}} {
		if err := checkNames(ok); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
	}
	for _, bad := range [][]string{nil, {""}, {"a,b.example.com"}, {"CN=x"}, {"a b"}, {"*.*.example.com"}, {"ex*.com"}, {"-a.example.com"}} {
		if err := checkNames(bad); !errors.Is(err, plugin.ErrInvalid) {
			t.Errorf("%q: err = %v, want ErrInvalid", bad, err)
		}
	}
}

func TestRefs(t *testing.T) {
	spki := strings.Repeat("ab", 32)
	pending := keyRef{vaultURL: "https://kv1.vault.azure.net", name: "web", spki: spki, certID: "1043"}
	if got := pending.String(); got != "https://kv1.vault.azure.net/certificates/web/pending?certificate_id=1043&spki_sha256="+spki {
		t.Errorf("pending ref = %s", got)
	}
	done := keyRef{vaultURL: "https://kv1.vault.azure.net", name: "web", version: "0123abcd"}
	if got := done.String(); got != "https://kv1.vault.azure.net/certificates/web/0123abcd" {
		t.Errorf("completed ref = %s", got)
	}
	if got := done.secretID(); got != "https://kv1.vault.azure.net/secrets/web/0123abcd" {
		t.Errorf("secret id = %s", got)
	}
	for _, r := range []keyRef{pending, done} {
		back, err := parseRef(r.String())
		if err != nil || back != r {
			t.Errorf("parseRef(%s) = %+v, %v", r, back, err)
		}
	}
	// Key Vault ids may carry the default port; refs compare without it.
	if r, err := parseRef("https://KV1.vault.azure.net:443/certificates/web/0123abcd"); err != nil || r != done {
		t.Errorf("parseRef with :443 = %+v, %v", r, err)
	}
	for _, bad := range []string{
		"", "local/abc",
		"https://kv1.vault.azure.net/certificates/web/pending?spki_sha256=" + spki,
		"https://kv1.vault.azure.net/certificates/web/pending?certificate_id=a%20b&spki_sha256=" + spki, "http://kv1.vault.azure.net/certificates/web/v1",
		"https://kv1.vault.azure.net/secrets/web/v1",
		"https://kv1.vault.azure.net/certificates/web",
		"https://kv1.vault.azure.net/certificates/web/pending",
		"https://kv1.vault.azure.net/certificates/web/pending?spki_sha256=xyz",
		"https://kv1.vault.azure.net/certificates/we_b/v1",
		"https://kv1.vault.azure.net/certificates/web/v1?x=1",
		"https://kv1.vault.azure.net/certificates/web/v1#frag",
	} {
		if _, err := parseRef(bad); !errors.Is(err, plugin.ErrInvalid) {
			t.Errorf("parseRef(%q) err = %v, want ErrInvalid", bad, err)
		}
	}
}
