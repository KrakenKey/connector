package appgw

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// oidSignedData is the PKCS#7 signedData content type.
var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// leafSerial returns the lowercase hex serial of the leaf certificate in an
// sslCertificates entry's publicCertData. ARM returns that field base64
// encoded; the payload is a PKCS#7 (degenerate signedData) bundle of the
// certificate chain. A bare DER certificate and PEM are accepted too.
func leafSerial(publicCertData string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicCertData))
	if err != nil {
		return "", fmt.Errorf("publicCertData is not base64: %w", err)
	}
	certs, err := parseCertBundle(raw)
	if err != nil {
		return "", err
	}
	leaf := pickLeaf(certs)
	return fmt.Sprintf("%x", leaf.SerialNumber), nil
}

func parseCertBundle(raw []byte) ([]*x509.Certificate, error) {
	if block, _ := pem.Decode(raw); block != nil {
		var certs []*x509.Certificate
		for rest := raw; ; {
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			switch block.Type {
			case "CERTIFICATE":
				c, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, err
				}
				certs = append(certs, c)
			case "PKCS7":
				cs, err := parsePKCS7Certs(block.Bytes)
				if err != nil {
					return nil, err
				}
				certs = append(certs, cs...)
			}
		}
		if len(certs) == 0 {
			return nil, errors.New("publicCertData holds no certificate")
		}
		return certs, nil
	}
	if c, err := x509.ParseCertificate(raw); err == nil {
		return []*x509.Certificate{c}, nil
	}
	return parsePKCS7Certs(raw)
}

// parsePKCS7Certs extracts the certificates field of a PKCS#7 signedData
// ContentInfo. Signatures are not checked: the bundle is only a container.
func parsePKCS7Certs(der []byte) ([]*x509.Certificate, error) {
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("publicCertData is not a certificate or PKCS#7 bundle: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("publicCertData is PKCS#7 of type %s, not signedData", ci.ContentType)
	}
	// SignedData ::= SEQUENCE { version, digestAlgorithms, contentInfo,
	//   certificates [0] IMPLICIT OPTIONAL, crls [1] IMPLICIT OPTIONAL,
	//   signerInfos }
	var sd asn1.RawValue
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil || sd.Tag != asn1.TagSequence {
		return nil, errors.New("publicCertData: bad PKCS#7 signedData")
	}
	var certBytes []byte
	for rest := sd.Bytes; len(rest) > 0; {
		var el asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &el); err != nil {
			return nil, fmt.Errorf("publicCertData: bad PKCS#7 signedData: %w", err)
		}
		if el.Class == asn1.ClassContextSpecific && el.Tag == 0 {
			certBytes = el.Bytes
			break
		}
	}
	if len(certBytes) == 0 {
		return nil, errors.New("publicCertData: PKCS#7 bundle holds no certificate")
	}
	certs, err := x509.ParseCertificates(certBytes)
	if err != nil {
		return nil, fmt.Errorf("publicCertData: %w", err)
	}
	if len(certs) == 0 {
		return nil, errors.New("publicCertData: PKCS#7 bundle holds no certificate")
	}
	return certs, nil
}

// pickLeaf returns the certificate that issued none of the others,
// preferring one that is not a CA. Bundles are not always leaf first.
func pickLeaf(certs []*x509.Certificate) *x509.Certificate {
	issuesOther := func(c *x509.Certificate) bool {
		for _, o := range certs {
			if o != c && string(o.RawIssuer) == string(c.RawSubject) && string(o.RawSubject) != string(o.RawIssuer) {
				return true
			}
		}
		return false
	}
	for _, c := range certs {
		if !c.IsCA && !issuesOther(c) {
			return c
		}
	}
	for _, c := range certs {
		if !issuesOther(c) {
			return c
		}
	}
	return certs[0]
}
