// Package certutil holds small certificate helpers shared by the core and
// the built-in targets.
package certutil

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
)

// SerialHex formats a certificate serial number as lowercase hex, the form
// used across the plugin protocol and the audit log.
func SerialHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	return fmt.Sprintf("%x", n)
}

// ParseCerts decodes every CERTIFICATE block in data.
func ParseCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate found in PEM data")
	}
	return certs, nil
}

// ParseLeaf returns the first certificate in PEM data.
func ParseLeaf(pemData string) (*x509.Certificate, error) {
	certs, err := ParseCerts([]byte(pemData))
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// ParseCSR decodes a PEM certificate request and checks its signature.
func ParseCSR(pemData string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("CSR is not a PEM CERTIFICATE REQUEST")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := req.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature: %w", err)
	}
	return req, nil
}

// SamePublicKey reports whether two public keys are equal.
func SamePublicKey(a, b crypto.PublicKey) bool {
	ak, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ak.Equal(b)
}

// NormalizeNames lowercases, trims and sorts names and drops duplicates.
func NormalizeNames(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// SameNames reports whether two name lists hold the same set of names,
// ignoring case and order.
func SameNames(a, b []string) bool {
	return slices.Equal(NormalizeNames(a), NormalizeNames(b))
}

// CertNames returns the names a certificate covers: its DNS SANs and IP
// SANs. The subject common name is ignored, as browsers do.
func CertNames(c *x509.Certificate) []string {
	names := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		names = append(names, ip.String())
	}
	return names
}

// CSRNames is CertNames for a certificate request.
func CSRNames(r *x509.CertificateRequest) []string {
	names := append([]string{}, r.DNSNames...)
	for _, ip := range r.IPAddresses {
		names = append(names, ip.String())
	}
	return names
}
