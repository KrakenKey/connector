package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestConfigSummaryRoutes(t *testing.T) {
	port := 443
	s := ConfigSummary{
		Version: "1.2.3",
		Plugins: []ConfigPlugin{{Name: "file", Source: PluginSourceBuiltin}},
		Certificates: []ConfigCertificate{{
			CertificateID: 1, Names: []string{"a.example.com"},
			KeyStore: ConfigKeyStore{Plugin: "local", Settings: map[string]any{}},
			Targets: []ConfigTarget{{Label: "web", Plugin: "file", Verify: &ConfigVerify{Port: &port},
				Settings: map[string]any{"key": "k.pem", "dir": "/etc/x"}}},
		}},
	}
	hash, err := ConfigSummaryHash(s)
	if err != nil {
		t.Fatal(err)
	}
	var body string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connectors/config" || r.Header.Get("Authorization") != "Bearer "+testKey {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		body = r.Method + " " + string(b)
		w.WriteHeader(http.StatusNoContent)
	})
	if err := c.PutConfigSummary(context.Background(), hash, s); err != nil {
		t.Fatal(err)
	}
	// The hash comes first and covers the rest of the body, with settings
	// keys sorted.
	prefix := `PUT {"hash":"` + hash + `",`
	rest, ok := strings.CutPrefix(body, prefix)
	if !ok {
		t.Fatalf("body %s", body)
	}
	if sum := sha256.Sum256([]byte("{" + rest)); hex.EncodeToString(sum[:]) != hash {
		t.Errorf("hash does not cover the body: %s", body)
	}
	if !strings.Contains(rest, `"settings":{"dir":"/etc/x","key":"k.pem"}`) || !strings.Contains(rest, `"checkIntervalSeconds":null`) ||
		!strings.Contains(rest, `"verify":{"host":null,"port":443,"skipChainValidation":false}`) {
		t.Errorf("body %s", body)
	}
	if again, _ := ConfigSummaryHash(s); again != hash {
		t.Errorf("hash changed: %s, %s", hash, again)
	}

	if err := c.DeleteConfigSummary(context.Background()); err != nil || body != "DELETE " {
		t.Errorf("delete: %v, %q", err, body)
	}
}

func TestIsMissingRoute(t *testing.T) {
	for status, want := range map[int]bool{404: true, 405: true, 403: false, 500: false} {
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"statusCode":1,"message":"x"}`))
		})
		err := c.DeleteConfigSummary(context.Background())
		if err == nil || IsMissingRoute(err) != want {
			t.Errorf("%d: %v, missing route %v", status, err, IsMissingRoute(err))
		}
	}
	if IsMissingRoute(nil) {
		t.Error("nil is a missing route")
	}
}
