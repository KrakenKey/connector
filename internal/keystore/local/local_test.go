package local

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/krakenkey/connector/internal/certutil"
	"github.com/krakenkey/connector/internal/testca"
	"github.com/krakenkey/connector/pkg/plugin"
)

func perm(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestOpenCreatesPrivateDirs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits")
	}
	dataDir := filepath.Join(t.TempDir(), "data")
	if _, err := Open(dataDir); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{dataDir, filepath.Join(dataDir, "keys")} {
		if p := perm(t, d); p != 0o700 {
			t.Errorf("%s mode %o, want 700", d, p)
		}
	}
}

func TestOpenRefusesLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits")
	}
	t.Run("data dir", func(t *testing.T) {
		dataDir := t.TempDir()
		if err := os.Chmod(dataDir, 0o755); err != nil {
			t.Fatal(err)
		}
		_, err := Open(dataDir)
		if !errors.Is(err, ErrInsecurePermissions) || !strings.Contains(err.Error(), "chmod 700") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("key file", func(t *testing.T) {
		dataDir := t.TempDir()
		_ = os.Chmod(dataDir, 0o700)
		s, err := Open(dataDir)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := s.CreateCSR(context.Background(), plugin.CSRRequest{CertificateID: "1", Names: []string{"a.example.com"}, KeyType: plugin.KeyTypeECDSAP256})
		if err != nil {
			t.Fatal(err)
		}
		keyPath, _ := s.path(csr.KeyRef, ".key")
		if err := os.Chmod(keyPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dataDir); !errors.Is(err, ErrInsecurePermissions) || !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("Open err = %v", err)
		}
		if _, err := s.Export(context.Background(), plugin.ExportRequest{KeyRef: csr.KeyRef, Format: plugin.KeyFormatPEM}); !errors.Is(err, ErrInsecurePermissions) {
			t.Fatalf("Export err = %v", err)
		}
	})
	t.Run("cert dir", func(t *testing.T) {
		dataDir := t.TempDir()
		_ = os.Chmod(dataDir, 0o700)
		if err := os.MkdirAll(filepath.Join(dataDir, "keys", "9"), 0o700); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(filepath.Join(dataDir, "keys"), 0o700)
		_ = os.Chmod(filepath.Join(dataDir, "keys", "9"), 0o750)
		if _, err := Open(dataDir); !errors.Is(err, ErrInsecurePermissions) {
			t.Fatalf("err = %v", err)
		}
	})
}

func open(t *testing.T) *Store {
	t.Helper()
	dataDir := t.TempDir()
	_ = os.Chmod(dataDir, 0o700)
	s, err := Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestKeyLifecycle(t *testing.T) {
	ctx := context.Background()
	ca := testca.New(t)
	tests := []struct {
		kt    plugin.KeyType
		check func(any) bool
	}{
		{plugin.KeyTypeECDSAP256, func(k any) bool { e, ok := k.(*ecdsa.PrivateKey); return ok && e.Curve == elliptic.P256() }},
		{plugin.KeyTypeECDSAP384, func(k any) bool { e, ok := k.(*ecdsa.PrivateKey); return ok && e.Curve == elliptic.P384() }},
		{plugin.KeyTypeRSA2048, func(k any) bool { r, ok := k.(*rsa.PrivateKey); return ok && r.N.BitLen() == 2048 }},
		{plugin.KeyTypeRSA3072, func(k any) bool { r, ok := k.(*rsa.PrivateKey); return ok && r.N.BitLen() == 3072 }},
	}
	for _, tt := range tests {
		t.Run(string(tt.kt), func(t *testing.T) {
			s := open(t)
			names := []string{"api.example.com", "www.example.com"}
			csr, err := s.CreateCSR(ctx, plugin.CSRRequest{Config: json.RawMessage(`{}`), CertificateID: "1043", Names: names, KeyType: tt.kt})
			if err != nil {
				t.Fatalf("CreateCSR: %v", err)
			}
			req, err := certutil.ParseCSR(csr.PEM)
			if err != nil {
				t.Fatal(err)
			}
			if !certutil.SameNames(certutil.CSRNames(req), names) || req.Subject.CommonName != "api.example.com" {
				t.Errorf("CSR names %v, CN %q", req.DNSNames, req.Subject.CommonName)
			}

			keyPath, err := s.path(csr.KeyRef, ".key")
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" {
				if p := perm(t, keyPath); p != 0o600 {
					t.Errorf("key file mode %o, want 600", p)
				}
				if p := perm(t, filepath.Dir(keyPath)); p != 0o700 {
					t.Errorf("cert key dir mode %o, want 700", p)
				}
			}

			mat, err := s.Export(ctx, plugin.ExportRequest{KeyRef: csr.KeyRef, Format: plugin.KeyFormatPEM})
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(mat.Data)
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if !tt.check(key) {
				t.Errorf("key is %T, not %s", key, tt.kt)
			}
			if !certutil.SamePublicKey(key.(crypto.Signer).Public(), req.PublicKey) {
				t.Error("exported key does not match the CSR")
			}

			_, leafPEM := ca.Issue(t, req.PublicKey, names, 0)
			ref, err := s.Complete(ctx, plugin.CompleteRequest{KeyRef: csr.KeyRef, CertPEM: leafPEM, ChainPEM: ca.IntermediatePEM})
			if err != nil || ref != csr.KeyRef {
				t.Fatalf("Complete = %q, %v", ref, err)
			}
			if _, err := os.Stat(strings.TrimSuffix(keyPath, ".key") + ".crt"); err != nil {
				t.Errorf("certificate not stored: %v", err)
			}

			if err := s.Release(ctx, plugin.ReleaseRequest{KeyRef: csr.KeyRef}); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
				t.Errorf("key still present after Release: %v", err)
			}
			if err := s.Release(ctx, plugin.ReleaseRequest{KeyRef: csr.KeyRef}); err != nil {
				t.Errorf("second Release: %v", err)
			}
		})
	}
}

func TestCompleteRejectsOtherKey(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	ca := testca.New(t)
	csr, err := s.CreateCSR(ctx, plugin.CSRRequest{CertificateID: "1", Names: []string{"a.example.com"}, KeyType: plugin.KeyTypeECDSAP256})
	if err != nil {
		t.Fatal(err)
	}
	_, otherPEM := ca.Issue(t, testca.Key(t).Public(), []string{"a.example.com"}, 0)
	if _, err := s.Complete(ctx, plugin.CompleteRequest{KeyRef: csr.KeyRef, CertPEM: otherPEM}); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err = %v", err)
	}
}

func TestRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	for _, ref := range []string{"", "1", "../../etc/passwd", "1/../../x", "1/20260101T000000Z-abcd", "a b/20260101T000000Z-0123abcd"} {
		if _, err := s.Export(ctx, plugin.ExportRequest{KeyRef: ref, Format: plugin.KeyFormatPEM}); err == nil {
			t.Errorf("Export accepted ref %q", ref)
		}
		if err := s.Release(ctx, plugin.ReleaseRequest{KeyRef: ref}); err == nil {
			t.Errorf("Release accepted ref %q", ref)
		}
	}
	if _, err := s.CreateCSR(ctx, plugin.CSRRequest{CertificateID: "../x", Names: []string{"a.example.com"}, KeyType: plugin.KeyTypeECDSAP256}); err == nil {
		t.Error("CreateCSR accepted a path in the certificate id")
	}
	if _, err := s.CreateCSR(ctx, plugin.CSRRequest{CertificateID: "1", Names: []string{"a.example.com"}, KeyType: plugin.KeyTypeRSA4096}); err == nil {
		t.Error("CreateCSR accepted rsa-4096")
	}
	if _, err := s.CreateCSR(ctx, plugin.CSRRequest{Config: json.RawMessage(`{"vault":"x"}`), CertificateID: "1", Names: []string{"a.example.com"}, KeyType: plugin.KeyTypeECDSAP256}); err == nil {
		t.Error("CreateCSR accepted unknown settings")
	}
	csr, _ := s.CreateCSR(ctx, plugin.CSRRequest{CertificateID: "1", Names: []string{"a.example.com"}, KeyType: plugin.KeyTypeECDSAP256})
	if _, err := s.Export(ctx, plugin.ExportRequest{KeyRef: csr.KeyRef, Format: plugin.KeyFormatPFX}); err == nil {
		t.Error("Export returned pfx")
	}
}

func TestDescribe(t *testing.T) {
	caps, _ := open(t).Describe(context.Background())
	if !caps.Exportable || len(caps.Provides) != 1 || caps.Provides[0] != plugin.KeyFormatPEM || len(caps.KeyTypes) != 4 {
		t.Errorf("caps = %+v", caps)
	}
}
