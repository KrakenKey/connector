// Package testca is a throwaway certificate authority for tests.
package testca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// CA signs test certificates with a root and one intermediate.
type CA struct {
	Root            *x509.Certificate
	RootPEM         string
	Intermediate    *x509.Certificate
	IntermediatePEM string
	interKey        crypto.Signer
	serial          atomic.Int64
}

// New creates a CA.
func New(t testing.TB) *CA {
	t.Helper()
	rootKey := Key(t)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	interKey := Key(t)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, interKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(interDER)

	ca := &CA{
		Root:            root,
		RootPEM:         PEM(rootDER),
		Intermediate:    inter,
		IntermediatePEM: PEM(interDER),
		interKey:        interKey,
	}
	ca.serial.Store(0x1000)
	return ca
}

// Key returns a new ECDSA P-256 key.
func Key(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// PEM encodes DER as a CERTIFICATE block.
func PEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// Pool returns a pool holding the root.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Root)
	return p
}

// Issue signs a leaf for pub covering names (DNS names or IP addresses).
// A serial of 0 picks the next one.
func (ca *CA) Issue(t testing.TB, pub crypto.PublicKey, names []string, serial int64) (*x509.Certificate, string) {
	t.Helper()
	if serial == 0 {
		serial = ca.serial.Add(1)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if len(names) > 0 {
		tmpl.Subject = pkix.Name{CommonName: names[0]}
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Intermediate, pub, ca.interKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, PEM(der)
}

// TLSCert issues a leaf for a new key and returns it as a tls.Certificate
// with the intermediate attached.
func (ca *CA) TLSCert(t testing.TB, names []string, serial int64) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key := Key(t)
	leaf, _ := ca.Issue(t, key.Public(), names, serial)
	return tls.Certificate{
		Certificate: [][]byte{leaf.Raw, ca.Intermediate.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, leaf
}
