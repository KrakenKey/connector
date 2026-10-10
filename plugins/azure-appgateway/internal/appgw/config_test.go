package appgw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/krakenkey/connector/pkg/plugin"
	"github.com/krakenkey/connector/plugins/azure-appgateway/internal/fakearm"
)

func TestParseConfig(t *testing.T) {
	c, err := ParseConfig(cfg(map[string]any{"replace_uploaded_certificate": true}))
	if err != nil {
		t.Fatal(err)
	}
	if c.SubscriptionID != sub || c.ResourceGroup != rg || c.Gateway != gwName || c.SSLCertificate != certName || !c.ReplaceUploadedCertificate {
		t.Errorf("parsed %+v", c)
	}
	if c, err := ParseConfig(cfg(nil)); err != nil || c.ReplaceUploadedCertificate {
		t.Errorf("replace_uploaded_certificate should default to false: %+v %v", c, err)
	}

	bad := []struct {
		name string
		raw  []byte
		want string
	}{
		{"empty", nil, "subscription_id is required"},
		{"unknown key", cfg(map[string]any{"vault": "x"}), `unknown field "vault"`},
		{"not a guid", cfg(map[string]any{"subscription_id": "prod"}), "not a subscription id"},
		{"no resource group", cfg(map[string]any{"resource_group": nil}), "resource_group is required"},
		{"resource group ends with period", cfg(map[string]any{"resource_group": "rg."}), "not a valid resource group"},
		{"no gateway", cfg(map[string]any{"gateway": nil}), "gateway is required"},
		{"bad gateway", cfg(map[string]any{"gateway": "-agw"}), "not a valid Application Gateway name"},
		{"no cert", cfg(map[string]any{"ssl_certificate": nil}), "ssl_certificate is required"},
		{"bad cert", cfg(map[string]any{"ssl_certificate": "a/b"}), "not a valid certificate name"},
		{"wrong type", cfg(map[string]any{"replace_uploaded_certificate": "yes"}), "replace_uploaded_certificate"},
		// Dropped: a new entry has no listener, so verification could never pass.
		{"create_if_missing", cfg(map[string]any{"create_if_missing": true}), `unknown field "create_if_missing"`},
		{"not an object", []byte(`[]`), "settings"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConfig(tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if !errors.Is(err, plugin.ErrPermanent) {
				t.Errorf("err %v is not ErrPermanent", err)
			}
		})
	}
}

func TestParseSecretID(t *testing.T) {
	good := []struct {
		in        string
		canonical string
		versioned bool
	}{
		{secret(verNew), secret(verNew), true},
		{"https://KV-Test.vault.azure.net/secrets/app-cert/" + strings.ToUpper(verNew), secret(verNew), true},
		{"https://kv-test.vault.azure.net:443/secrets/app-cert/" + verNew, secret(verNew), true},
		{"https://kv-test.vault.azure.net/secrets/app-cert/", "https://kv-test.vault.azure.net/secrets/app-cert/", false},
		{"https://kv-test.vault.azure.net/secrets/app-cert", "https://kv-test.vault.azure.net/secrets/app-cert/", false},
	}
	for _, tc := range good {
		id, err := ParseSecretID(tc.in)
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		if id.String() != tc.canonical || id.Versioned() != tc.versioned {
			t.Errorf("%s: got %s versioned=%v", tc.in, id, id.Versioned())
		}
	}
	bad := []string{
		"",
		"http://kv-test.vault.azure.net/secrets/app-cert/" + verNew,
		"https://example.com/secrets/app-cert/" + verNew,
		"https://kv-test.vault.azure.net/keys/app-cert/" + verNew,
		"https://kv-test.vault.azure.net/certificates/app-cert/" + verNew,
		"https://kv-test.vault.azure.net/secrets/app-cert/notahexversion",
		"https://kv-test.vault.azure.net/secrets/app_cert/" + verNew,
		"https://kv-test.vault.azure.net/secrets/app-cert/" + verNew + "/extra",
		"https://kv-test.vault.azure.net/secrets/app-cert/" + verNew + "?sig=abc",
		"https://user@kv-test.vault.azure.net/secrets/app-cert/" + verNew,
		"https://kv-test.vault.azure.net:8443/secrets/app-cert/" + verNew,
		"https://x.vault.azure.net/secrets/app-cert/" + verNew,
		// Public cloud only.
		"https://kv-gov.vault.usgovcloudapi.net/secrets/app-cert/" + verNew,
		"https://kv-cn.vault.azure.cn/secrets/app-cert/" + verNew,
	}
	for _, in := range bad {
		if _, err := ParseSecretID(in); err == nil {
			t.Errorf("%q: accepted", in)
		} else if strings.Contains(err.Error(), "sig=abc") {
			t.Errorf("error echoes the query string: %v", err)
		}
	}
	a, _ := ParseSecretID(secret(verNew))
	b, _ := ParseSecretID(strings.ToUpper(secret(verNew)[:8]) + secret(verNew)[8:])
	if !a.Equal(b) {
		t.Error("IDs differing only in case should be equal")
	}
}

func makeCert(t *testing.T, serial int64, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func TestLeafSerial(t *testing.T) {
	root, rootKey := makeCert(t, 1, "Root", true, nil, nil)
	inter, interKey := makeCert(t, 2, "Intermediate", true, root, rootKey)
	leaf, _ := makeCert(t, 0xdeadbeef, "app.example.com", false, inter, interKey)
	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

	cases := map[string]string{
		// Not leaf first: the leaf is picked by structure, not position.
		"pkcs7 chain":  b64(fakearm.PKCS7(root.Raw, inter.Raw, leaf.Raw)),
		"pkcs7 leaf":   b64(fakearm.PKCS7(leaf.Raw)),
		"der":          b64(leaf.Raw),
		"pem chain":    b64(append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})...)),
		"pem pkcs7":    b64(pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: fakearm.PKCS7(inter.Raw, leaf.Raw)})),
		"intermediate": b64(fakearm.PKCS7(inter.Raw, leaf.Raw)),
	}
	for name, data := range cases {
		got, err := leafSerial(data)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got != "deadbeef" {
			t.Errorf("%s: serial %s, want deadbeef", name, got)
		}
	}
	for _, bad := range []string{"!!", b64([]byte("not asn1")), b64(fakearm.PKCS7())} {
		if _, err := leafSerial(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}
