package verify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krakenkey/connector/internal/testca"
)

// server starts a TLS server that serves whatever cert holds at handshake
// time and records the SNI it was asked for.
func server(t *testing.T, cert *atomic.Pointer[tls.Certificate], sni *atomic.Value) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if sni != nil {
				sni.Store(hello.ServerName)
			}
			return cert.Load(), nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func fast() *Verifier {
	return &Verifier{DialTimeout: 2 * time.Second, MinBackoff: 20 * time.Millisecond, MaxBackoff: 50 * time.Millisecond}
}

func TestVerifyDialsAddressWithSNIHost(t *testing.T) {
	ca := testca.New(t)
	tc, leaf := ca.TLSCert(t, []string{"api.example.com"}, 0)
	var cur atomic.Pointer[tls.Certificate]
	cur.Store(&tc)
	var sni atomic.Value
	srv := server(t, &cur, &sni)

	// The dial target (127.0.0.1:port) and the SNI name differ, as when
	// testing a local server that serves a real hostname.
	err := fast().Verify(context.Background(), Request{
		Host:     "api.example.com",
		Address:  srv.Listener.Addr().String(),
		Expected: leaf,
		Roots:    ca.Pool(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := sni.Load(); got != "api.example.com" {
		t.Errorf("server saw SNI %q, want api.example.com", got)
	}
}

func TestVerifyChainValidationOnByDefault(t *testing.T) {
	ca := testca.New(t) // not in the system roots
	tc, leaf := ca.TLSCert(t, []string{"api.example.com"}, 0)
	var cur atomic.Pointer[tls.Certificate]
	cur.Store(&tc)
	srv := server(t, &cur, nil)

	start := time.Now()
	err := fast().Verify(context.Background(), Request{
		Host:     "api.example.com",
		Address:  srv.Listener.Addr().String(),
		Expected: leaf,
		Window:   time.Minute,
	})
	var chainErr *ChainError
	if !errors.As(err, &chainErr) {
		t.Fatalf("err = %v, want ChainError", err)
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Errorf("err = %v, want an unknown authority error", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Error("chain failure should be returned at once, not retried for the window")
	}
}

func TestVerifySkipChainValidation(t *testing.T) {
	ca := testca.New(t)
	tc, leaf := ca.TLSCert(t, []string{"api.example.com"}, 0)
	var cur atomic.Pointer[tls.Certificate]
	cur.Store(&tc)
	srv := server(t, &cur, nil)

	err := fast().Verify(context.Background(), Request{
		Host:                "api.example.com",
		Address:             srv.Listener.Addr().String(),
		Expected:            leaf,
		SkipChainValidation: true,
	})
	if err != nil {
		t.Fatalf("Verify with skip_chain_validation: %v", err)
	}
}

func TestVerifyChainMustCoverHost(t *testing.T) {
	ca := testca.New(t)
	tc, leaf := ca.TLSCert(t, []string{"other.example.com"}, 0)
	var cur atomic.Pointer[tls.Certificate]
	cur.Store(&tc)
	srv := server(t, &cur, nil)

	err := fast().Verify(context.Background(), Request{
		Host:     "api.example.com",
		Address:  srv.Listener.Addr().String(),
		Expected: leaf,
		Roots:    ca.Pool(),
	})
	var hostErr x509.HostnameError
	if !errors.As(err, &hostErr) {
		t.Fatalf("err = %v, want a hostname error", err)
	}
}

func TestVerifyWaitsForNewCertificate(t *testing.T) {
	ca := testca.New(t)
	oldCert, _ := ca.TLSCert(t, []string{"api.example.com"}, 0)
	newCert, newLeaf := ca.TLSCert(t, []string{"api.example.com"}, 0)
	var cur atomic.Pointer[tls.Certificate]
	cur.Store(&oldCert)
	srv := server(t, &cur, nil)

	go func() {
		time.Sleep(100 * time.Millisecond)
		cur.Store(&newCert)
	}()
	err := fast().Verify(context.Background(), Request{
		Host:     "api.example.com",
		Address:  srv.Listener.Addr().String(),
		Expected: newLeaf,
		Window:   5 * time.Second,
		Roots:    ca.Pool(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyMismatchUntilWindowEnds(t *testing.T) {
	ca := testca.New(t)
	oldCert, oldLeaf := ca.TLSCert(t, []string{"api.example.com"}, 0)
	_, newLeaf := ca.TLSCert(t, []string{"api.example.com"}, 0)
	var cur atomic.Pointer[tls.Certificate]
	cur.Store(&oldCert)
	srv := server(t, &cur, nil)

	start := time.Now()
	err := fast().Verify(context.Background(), Request{
		Host:     "api.example.com",
		Address:  srv.Listener.Addr().String(),
		Expected: newLeaf,
		Window:   300 * time.Millisecond,
		Roots:    ca.Pool(),
	})
	var mm *MismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("err = %v, want MismatchError", err)
	}
	if mm.ServedSerial != oldLeaf.SerialNumber.Text(16) || mm.SameSerial {
		t.Errorf("mismatch = %+v", mm)
	}
	if !strings.Contains(err.Error(), "still serves serial") {
		t.Errorf("message = %q", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Error("window not respected")
	}
}

func TestVerifySameSerialDifferentKeyIsAMismatch(t *testing.T) {
	ca := testca.New(t)
	served, _ := ca.TLSCert(t, []string{"api.example.com"}, 0x77)
	_, expected := ca.TLSCert(t, []string{"api.example.com"}, 0x77)
	var cur atomic.Pointer[tls.Certificate]
	cur.Store(&served)
	srv := server(t, &cur, nil)

	err := fast().Verify(context.Background(), Request{
		Host:                "api.example.com",
		Address:             srv.Listener.Addr().String(),
		Expected:            expected,
		SkipChainValidation: true,
	})
	var mm *MismatchError
	if !errors.As(err, &mm) || !mm.SameSerial {
		t.Fatalf("err = %v, want a same-serial mismatch", err)
	}
	if !strings.Contains(err.Error(), "different public key") {
		t.Errorf("message = %q", err)
	}
}

func TestVerifyUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	ca := testca.New(t)
	_, leaf := ca.TLSCert(t, []string{"api.example.com"}, 0)
	err = fast().Verify(context.Background(), Request{
		Host: "api.example.com", Address: addr, Expected: leaf, Window: 100 * time.Millisecond,
	})
	var mm *MismatchError
	if !errors.As(err, &mm) || mm.LastErr == nil {
		t.Fatalf("err = %v, want MismatchError with a dial error", err)
	}
	if !strings.Contains(err.Error(), "could not check") {
		t.Errorf("message = %q", err)
	}
}

func TestVerifyStopsOnCancel(t *testing.T) {
	ca := testca.New(t)
	oldCert, _ := ca.TLSCert(t, []string{"api.example.com"}, 0)
	_, newLeaf := ca.TLSCert(t, []string{"api.example.com"}, 0)
	var cur atomic.Pointer[tls.Certificate]
	cur.Store(&oldCert)
	srv := server(t, &cur, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := fast().Verify(ctx, Request{
		Host: "api.example.com", Address: srv.Listener.Addr().String(), Expected: newLeaf, Window: time.Hour,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context deadline", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Error("did not stop on cancel")
	}
}

func TestLoadRoots(t *testing.T) {
	ca := testca.New(t)
	path := t.TempDir() + "/roots.pem"
	if err := writeFile(path, ca.RootPEM); err != nil {
		t.Fatal(err)
	}
	pool, err := LoadRoots(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Intermediate.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("pool does not trust the root: %v", err)
	}
	bad := t.TempDir() + "/empty.pem"
	_ = writeFile(bad, "not pem")
	if _, err := LoadRoots(bad); err == nil {
		t.Error("LoadRoots accepted a file without certificates")
	}
}

func writeFile(path, s string) error { return os.WriteFile(path, []byte(s), 0o600) }
