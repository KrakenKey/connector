// Package verify checks that an endpoint serves a given certificate. The
// core runs it itself after each target is activated; it is not a plugin
// call.
package verify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/krakenkey/connector/internal/certutil"
)

// Request says what to check.
type Request struct {
	// Host is the SNI name and the name the certificate must be valid for.
	Host string
	// Address is the host:port to dial.
	Address string
	// Expected is the issued leaf. The served leaf must be identical to it
	// (same DER bytes, so the same serial number and public key).
	Expected *x509.Certificate
	// Window is how long to keep retrying while the old certificate is
	// still served or the endpoint is unreachable. Zero means one attempt.
	Window time.Duration
	// Roots are trusted for chain validation. Nil means the system roots.
	Roots *x509.CertPool
	// SkipChainValidation turns chain validation off. The leaf is still
	// compared with Expected.
	SkipChainValidation bool
}

// MismatchError means the endpoint never served the expected leaf within
// the window.
type MismatchError struct {
	Address      string
	Host         string
	WantSerial   string
	ServedSerial string // empty if the last attempt did not connect
	SameSerial   bool   // serial matched but the public key did not
	LastErr      error
}

func (e *MismatchError) Error() string {
	switch {
	case e.SameSerial:
		return fmt.Sprintf("%s (SNI %s) serves serial %s, but not the issued certificate (different contents or public key)",
			e.Address, e.Host, e.ServedSerial)
	case e.ServedSerial != "":
		return fmt.Sprintf("%s (SNI %s) still serves serial %s, want %s", e.Address, e.Host, e.ServedSerial, e.WantSerial)
	case e.LastErr != nil:
		return fmt.Sprintf("could not check %s (SNI %s): %v", e.Address, e.Host, e.LastErr)
	}
	return fmt.Sprintf("%s (SNI %s) does not serve serial %s", e.Address, e.Host, e.WantSerial)
}

func (e *MismatchError) Unwrap() error { return e.LastErr }

// ChainError means the expected leaf is served, but its chain does not
// validate. Waiting does not fix this, so it is returned at once.
type ChainError struct {
	Host string
	Err  error
}

func (e *ChainError) Error() string {
	return fmt.Sprintf("served certificate for %s does not validate: %v", e.Host, e.Err)
}

func (e *ChainError) Unwrap() error { return e.Err }

// Verifier dials endpoints.
type Verifier struct {
	// DialTimeout bounds one connection attempt.
	DialTimeout time.Duration
	// MinBackoff and MaxBackoff bound the wait between attempts.
	MinBackoff, MaxBackoff time.Duration
}

// New returns a Verifier with the default timings: 10s per attempt, waits
// growing from 2s to 30s.
func New() *Verifier {
	return &Verifier{DialTimeout: 10 * time.Second, MinBackoff: 2 * time.Second, MaxBackoff: 30 * time.Second}
}

// LoadRoots reads a PEM file of trusted roots.
func LoadRoots(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s holds no PEM certificates", path)
	}
	return pool, nil
}

// Verify connects to req.Address until it serves req.Expected or the
// window ends. Once the expected leaf is seen, the chain is validated
// unless req.SkipChainValidation is set.
func (v *Verifier) Verify(ctx context.Context, req Request) error {
	if req.Expected == nil {
		return errors.New("verify: no expected certificate")
	}
	deadline := time.Now().Add(req.Window)
	backoff := v.MinBackoff
	want := certutil.SerialHex(req.Expected.SerialNumber)
	mismatch := &MismatchError{Address: req.Address, Host: req.Host, WantSerial: want}

	for {
		chain, err := v.fetch(ctx, req)
		mismatch.LastErr, mismatch.ServedSerial, mismatch.SameSerial = err, "", false
		if err == nil {
			leaf := chain[0]
			served := certutil.SerialHex(leaf.SerialNumber)
			// The served leaf must be byte for byte the issued certificate,
			// which also pins its serial number and public key.
			if bytes.Equal(leaf.Raw, req.Expected.Raw) {
				if req.SkipChainValidation {
					return nil
				}
				if err := validateChain(req, chain); err != nil {
					return &ChainError{Host: req.Host, Err: err}
				}
				return nil
			}
			mismatch.ServedSerial = served
			mismatch.SameSerial = served == want
		}

		if ctx.Err() != nil {
			mismatch.LastErr = ctx.Err()
			return mismatch
		}
		if !time.Now().Add(backoff).Before(deadline) {
			return mismatch
		}
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			mismatch.LastErr = ctx.Err()
			return mismatch
		case <-t.C:
		}
		backoff = min(backoff*2, v.MaxBackoff)
	}
}

func (v *Verifier) fetch(ctx context.Context, req Request) ([]*x509.Certificate, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: v.DialTimeout},
		Config: &tls.Config{
			ServerName: req.Host,
			// The leaf is identified by serial and key below, and the chain
			// is validated separately, so the handshake itself must not
			// reject a certificate that is not trusted yet.
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}
	dctx, cancel := context.WithTimeout(ctx, v.DialTimeout)
	defer cancel()
	conn, err := dialer.DialContext(dctx, "tcp", req.Address)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("server sent no certificate")
	}
	return certs, nil
}

func validateChain(req Request, chain []*x509.Certificate) error {
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		DNSName:       req.Host,
		Roots:         req.Roots,
		Intermediates: inter,
	})
	return err
}
