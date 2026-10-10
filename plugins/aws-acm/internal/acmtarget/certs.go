package acmtarget

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/acm/types"
)

// maxKeyBytes is ACM's limit on the private key it imports.
const maxKeyBytes = 5120

// material is a certificate, its chain and key, checked and encoded the
// way ImportCertificate wants them.
type material struct {
	leaf     *x509.Certificate
	certPEM  []byte
	chainPEM []byte // nil when there are no intermediates
	keyPEM   []byte
	serial   string
}

// wipe overwrites the key bytes.
func (m *material) wipe() {
	if m == nil {
		return
	}
	clear(m.keyPEM)
	m.keyPEM = nil
}

// parseMaterial checks that the certificate, chain and key are well
// formed, that the key belongs to the certificate, and that ACM will accept
// them at time now. Errors never include key bytes.
func parseMaterial(certPEM, chainPEM string, keyPEM []byte, now time.Time) (*material, error) {
	certs, err := parseCerts([]byte(certPEM))
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	if len(certs) == 0 {
		return nil, errors.New("certificate: no PEM CERTIFICATE block")
	}
	leaf := certs[0]
	chain, err := parseCerts([]byte(chainPEM))
	if err != nil {
		return nil, fmt.Errorf("chain: %w", err)
	}
	// ACM wants the leaf on its own and the chain without it.
	chain = slices.DeleteFunc(chain, func(c *x509.Certificate) bool { return c.Equal(leaf) })

	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate %s is valid from %s to %s; ACM only imports a certificate inside its validity period",
			serialHex(leaf.SerialNumber), leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if _, err := keyAlgorithm(leaf); err != nil {
		return nil, err
	}

	if len(keyPEM) > maxKeyBytes {
		return nil, fmt.Errorf("private key is %d bytes; ACM accepts at most %d", len(keyPEM), maxKeyBytes)
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	if !publicKeysEqual(key.Public(), leaf.PublicKey) {
		return nil, fmt.Errorf("private key does not belong to certificate %s", serialHex(leaf.SerialNumber))
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}

	m := &material{
		leaf:    leaf,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		serial:  serialHex(leaf.SerialNumber),
	}
	clear(der)
	for _, c := range chain {
		m.chainPEM = append(m.chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return m, nil
}

func parseCerts(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(bytes.TrimSpace(data)) > 0 {
		return nil, errors.New("trailing data after the last PEM block")
	}
	return out, nil
}

// parseKey reads an unencrypted PKCS#8, PKCS#1 or SEC 1 private key.
func parseKey(data []byte) (crypto.Signer, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key is not PEM encoded")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("private key: more than one PEM block")
	}
	var (
		key any
		err error
	)
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("private key: unsupported PEM block %q (want an unencrypted PRIVATE KEY)", block.Type)
	}
	if err != nil {
		return nil, errors.New("private key does not parse")
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key type %T is not supported", key)
	}
	switch s.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
	default:
		return nil, fmt.Errorf("private key type %T is not supported by ACM", key)
	}
	return s, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}

// keyAlgorithm returns the ACM name for the certificate's key.
func keyAlgorithm(c *x509.Certificate) (types.KeyAlgorithm, error) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		switch k.N.BitLen() {
		case 2048:
			return types.KeyAlgorithmRsa2048, nil
		case 3072:
			return types.KeyAlgorithmRsa3072, nil
		case 4096:
			return types.KeyAlgorithmRsa4096, nil
		}
		return "", fmt.Errorf("RSA key size %d is not supported (want 2048, 3072 or 4096)", k.N.BitLen())
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return types.KeyAlgorithmEcPrime256v1, nil
		case elliptic.P384():
			return types.KeyAlgorithmEcSecp384r1, nil
		case elliptic.P521():
			return types.KeyAlgorithmEcSecp521r1, nil
		}
		return "", fmt.Errorf("ECDSA curve %s is not supported", k.Curve.Params().Name)
	}
	return "", fmt.Errorf("public key type %T is not supported by ACM", c.PublicKey)
}

// serialHex formats a serial number the way the connector does: lowercase
// hex without leading zeros or separators.
func serialHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	return fmt.Sprintf("%x", n)
}

// hexSerial normalizes a serial in the connector's form (hex, maybe with
// leading zeros or colons). It returns "" for anything else.
func hexSerial(s string) string {
	n, ok := new(big.Int).SetString(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), ":", ""), 16)
	if !ok || n.Sign() < 0 {
		return ""
	}
	return serialHex(n)
}

// acmSerial turns ACM's serial ("07:71:f4", one hex pair per byte) into
// lowercase hex without separators or leading zeros. It returns "" for
// anything else.
func acmSerial(s string) string { return hexSerial(s) }

// acmNames returns every name the ACM certificate covers now.
func acmNames(d *types.CertificateDetail) []string {
	var names []string
	add := func(n string) {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n != "" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	if d.DomainName != nil {
		add(*d.DomainName)
	}
	for _, n := range d.SubjectAlternativeNames {
		add(n)
	}
	return names
}

// covers reports whether the certificate serves name: an exact DNS name, a
// wildcard that matches one label, or the same wildcard.
func covers(c *x509.Certificate, name string) bool {
	certNames := c.DNSNames
	if len(certNames) == 0 && c.Subject.CommonName != "" {
		certNames = []string{c.Subject.CommonName}
	}
	for _, cn := range certNames {
		cn = strings.ToLower(strings.TrimSuffix(cn, "."))
		if cn == name {
			return true
		}
		if suffix, ok := strings.CutPrefix(cn, "*."); ok && !strings.HasPrefix(name, "*.") {
			if label, rest, found := strings.Cut(name, "."); found && label != "" && rest == suffix {
				return true
			}
		}
	}
	for _, ip := range c.IPAddresses {
		if ip.String() == name {
			return true
		}
	}
	return false
}

var keyUsageBits = map[types.KeyUsageName]x509.KeyUsage{
	types.KeyUsageNameDigitalSignature:   x509.KeyUsageDigitalSignature,
	types.KeyUsageNameNonRepudation:      x509.KeyUsageContentCommitment,
	types.KeyUsageNameKeyEncipherment:    x509.KeyUsageKeyEncipherment,
	types.KeyUsageNameDataEncipherment:   x509.KeyUsageDataEncipherment,
	types.KeyUsageNameKeyAgreement:       x509.KeyUsageKeyAgreement,
	types.KeyUsageNameCertificateSigning: x509.KeyUsageCertSign,
	types.KeyUsageNameCrlSigning:         x509.KeyUsageCRLSign,
	types.KeyUsageNameEnchiperOnly:       x509.KeyUsageEncipherOnly,
	types.KeyUsageNameDecipherOnly:       x509.KeyUsageDecipherOnly,
}

var extKeyUsages = map[types.ExtendedKeyUsageName]x509.ExtKeyUsage{
	types.ExtendedKeyUsageNameTlsWebServerAuthentication: x509.ExtKeyUsageServerAuth,
	types.ExtendedKeyUsageNameCodeSigning:                x509.ExtKeyUsageCodeSigning,
	types.ExtendedKeyUsageNameEmailProtection:            x509.ExtKeyUsageEmailProtection,
	types.ExtendedKeyUsageNameTimeStamping:               x509.ExtKeyUsageTimeStamping,
	types.ExtendedKeyUsageNameOcspSigning:                x509.ExtKeyUsageOCSPSigning,
	types.ExtendedKeyUsageNameIpsecEndSystem:             x509.ExtKeyUsageIPSECEndSystem,
	types.ExtendedKeyUsageNameIpsecTunnel:                x509.ExtKeyUsageIPSECTunnel,
	types.ExtendedKeyUsageNameIpsecUser:                  x509.ExtKeyUsageIPSECUser,
	// Client authentication is not checked: ACM's documentation says it
	// may be dropped on reimport (Let's Encrypt leaves no longer carry
	// it). This is not confirmed against ACM itself; if ACM refuses,
	// ImportCertificate fails and nothing changes.
}

// sameKeyAlgorithm compares ACM key algorithm names. DescribeCertificate
// reports EC keys with a hyphen ("EC-prime256v1") while the API enum uses
// an underscore ("EC_prime256v1"), so both spellings are accepted.
func sameKeyAlgorithm(a, b types.KeyAlgorithm) bool {
	norm := func(k types.KeyAlgorithm) string {
		return strings.ToUpper(strings.ReplaceAll(string(k), "-", "_"))
	}
	return norm(a) == norm(b)
}

// replaceProblem returns why ACM would refuse to re-import leaf over the
// certificate described by d, or why doing so would stop serving a name
// the certificate serves now. It returns "" when the replacement is fine.
func replaceProblem(d *types.CertificateDetail, leaf *x509.Certificate) string {
	if d.Type != types.CertificateTypeImported {
		return typeProblem(d)
	}
	alg, err := keyAlgorithm(leaf)
	if err != nil {
		return err.Error()
	}
	if d.KeyAlgorithm != "" && !sameKeyAlgorithm(d.KeyAlgorithm, alg) {
		return fmt.Sprintf("the ACM certificate has a %s key and this one %s; ACM cannot change the key type on reimport. Set key_store.key_type to match, or import a certificate with the new key type yourself first",
			d.KeyAlgorithm, alg)
	}
	var missing []string
	for _, n := range acmNames(d) {
		if !covers(leaf, n) {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return fmt.Sprintf("the new certificate does not cover %s, which the ACM certificate serves now; if dropping it is intended, re-import a certificate without it yourself first",
			strings.Join(missing, ", "))
	}
	return keyUsageProblem(d, leaf)
}

// keyUsageProblem returns why ACM would refuse leaf's key usages or extended
// key usages over the certificate described by d, or "".
func keyUsageProblem(d *types.CertificateDetail, leaf *x509.Certificate) string {
	_, isECDSA := leaf.PublicKey.(*ecdsa.PublicKey)
	for _, ku := range d.KeyUsages {
		// ACM records a certificate without a key usage extension as ANY and
		// then refuses any reimport that restricts key usage.
		if ku.Name == types.KeyUsageNameAny && leaf.KeyUsage != 0 {
			return "the ACM certificate has no key usage restriction (ACM shows ANY) and the new certificate restricts it; ACM refuses that on reimport. Import a placeholder with the same key usage as KrakenKey's certificates (keyUsage=critical,digitalSignature, extendedKeyUsage=serverAuth) and use its ARN"
		}
		bit, known := keyUsageBits[ku.Name]
		if !known || (isECDSA && ku.Name == types.KeyUsageNameKeyEncipherment) {
			continue
		}
		if leaf.KeyUsage&bit == 0 {
			return fmt.Sprintf("the new certificate lacks key usage %s, which the ACM certificate has; ACM refuses to remove key usages on reimport", ku.Name)
		}
	}
	for _, eku := range d.ExtendedKeyUsages {
		if eku.Name == types.ExtendedKeyUsageNameAny && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
			return "the ACM certificate allows any extended key usage (ACM shows ANY) and the new certificate restricts it; ACM refuses that on reimport. Import a placeholder with extendedKeyUsage=serverAuth and use its ARN"
		}
		want, known := extKeyUsages[eku.Name]
		if !known {
			continue
		}
		if !slices.Contains(leaf.ExtKeyUsage, want) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
			return fmt.Sprintf("the new certificate lacks extended key usage %s, which the ACM certificate has; ACM refuses to remove extended key usages on reimport", eku.Name)
		}
	}
	return ""
}

func typeProblem(d *types.CertificateDetail) string {
	switch d.Type {
	case types.CertificateTypeImported:
		return ""
	case types.CertificateTypeAmazonIssued:
		return "the certificate was issued by ACM (type AMAZON_ISSUED); ACM renews those itself and does not allow importing over them. Import a certificate and use its ARN"
	case types.CertificateTypePrivate:
		return "the certificate was issued by AWS Private CA (type PRIVATE); only imported certificates can be replaced. Import a certificate and use its ARN"
	}
	return fmt.Sprintf("the certificate has type %q; only imported certificates (type IMPORTED) can be replaced", d.Type)
}
