// Package testcert issues throwaway certificates for tests.
package testcert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// CA is a root and an intermediate that sign leaves.
type CA struct {
	key             crypto.Signer
	cert            *x509.Certificate
	IntermediatePEM string
}

// Leaf is an issued certificate with its key.
type Leaf struct {
	Cert    *x509.Certificate
	CertPEM string
	KeyPEM  []byte // PKCS#8
	Serial  string // lowercase hex
}

// Options change a leaf.
type Options struct {
	// Key is "ecdsa-p256" (default), "ecdsa-p384", "rsa-2048", ...
	Key       string
	NotBefore time.Time
	NotAfter  time.Time
	KeyUsage  x509.KeyUsage
	ExtUsage  []x509.ExtKeyUsage
}

// NewCA creates a root and intermediate.
func NewCA(t testing.TB) *CA {
	t.Helper()
	rootKey := NewKey(t, "ecdsa-p256")
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ = x509.ParseCertificate(rootDER)
	interKey := NewKey(t, "ecdsa-p256")
	inter := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, inter, root, interKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ = x509.ParseCertificate(interDER)
	return &CA{key: interKey, cert: inter, IntermediatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER}))}
}

// NewKey generates a key of the given type.
func NewKey(t testing.TB, kind string) crypto.Signer {
	t.Helper()
	var (
		k   crypto.Signer
		err error
	)
	switch kind {
	case "", "ecdsa-p256":
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		k, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa-2048":
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-3072":
		k, err = rsa.GenerateKey(rand.Reader, 3072)
	default:
		t.Fatalf("unknown key type %q", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Issue signs a leaf for names.
func (ca *CA) Issue(t testing.TB, names []string, o Options) Leaf {
	t.Helper()
	key := NewKey(t, o.Key)
	if o.NotBefore.IsZero() {
		o.NotBefore = time.Now().Add(-time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	if o.KeyUsage == 0 {
		o.KeyUsage = x509.KeyUsageDigitalSignature
	}
	if o.ExtUsage == nil {
		o.ExtUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: o.NotBefore, NotAfter: o.NotAfter, KeyUsage: o.KeyUsage, ExtKeyUsage: o.ExtUsage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return Leaf{
		Cert:    cert,
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		Serial:  fmt.Sprintf("%x", serial),
	}
}
