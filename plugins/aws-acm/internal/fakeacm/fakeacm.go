// Package fakeacm is an in-memory stand-in for the parts of the AWS
// Certificate Manager API the aws-acm target uses (DescribeCertificate and
// ImportCertificate), served over HTTP in the AWS JSON 1.1 protocol so the
// real SDK client can talk to it. It applies the ACM rules that matter for
// re-imports: the key must match, the key type cannot change, tags cannot
// be set on reimport, and only imported certificates can be replaced.
package fakeacm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// Cert is one certificate held by the fake.
type Cert struct {
	ARN        string
	Type       string // IMPORTED, AMAZON_ISSUED, PRIVATE
	Leaf       *x509.Certificate
	CertPEM    []byte
	ChainPEM   []byte
	KeyPEM     []byte
	Tags       map[string]string
	Imports    int
	Names      []string // for AMAZON_ISSUED certificates without a leaf
	KeyAlg     string
	ImportedAt time.Time
}

// Fault makes the next calls to an operation fail.
type Fault struct {
	Code    string // AWS error code, for example ThrottlingException
	Message string
	Status  int // HTTP status; default 400
	Times   int // how many calls fail; 0 means every call
	// Hang makes the server wait for the client to give up instead of
	// answering, like a lost connection.
	Hang bool
	// After applies the call before failing or hanging, so the caller sees
	// an error although the change was made.
	After bool
}

// Server is a fake ACM endpoint.
type Server struct {
	*httptest.Server
	Region  string
	Account string

	mu     sync.Mutex
	certs  map[string]*Cert
	faults map[string]*Fault
	calls  []string
	nextID int
}

// New starts a fake ACM endpoint. Close it when done.
func New() *Server {
	s := &Server{Region: "us-east-1", Account: "123456789012", certs: map[string]*Cert{}, faults: map[string]*Fault{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// ARN returns the ARN for certificate id.
func (s *Server) ARN(id string) string {
	return fmt.Sprintf("arn:aws:acm:%s:%s:certificate/%s", s.Region, s.Account, id)
}

// Fail installs a fault for an operation ("DescribeCertificate" or
// "ImportCertificate").
func (s *Server) Fail(op string, f Fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults[op] = &f
}

// Calls returns the operations called so far.
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// Cert returns a copy of the certificate under arn, or nil.
func (s *Server) Cert(arn string) *Cert {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.certs[arn]
	if !ok {
		return nil
	}
	cp := *c
	return &cp
}

// Import adds an imported certificate the way a person would before
// configuring the target, with tags.
func (s *Server) Import(certPEM, chainPEM string, keyPEM []byte, tags map[string]string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	arn := s.ARN(fmt.Sprintf("00000000-0000-0000-0000-%012d", s.nextID))
	c := &Cert{ARN: arn, Type: "IMPORTED", Tags: tags}
	if err := s.apply(c, []byte(certPEM), []byte(chainPEM), keyPEM); err != nil {
		return "", err
	}
	s.certs[arn] = c
	return arn, nil
}

// AddIssued adds a certificate of the given type (AMAZON_ISSUED or
// PRIVATE) for names.
func (s *Server) AddIssued(typ string, names []string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	arn := s.ARN(fmt.Sprintf("00000000-0000-0000-0000-%012d", s.nextID))
	s.certs[arn] = &Cert{ARN: arn, Type: typ, Names: names, KeyAlg: "RSA_2048"}
	return arn
}

type apiError struct {
	status  int
	code    string
	message string
}

func (e *apiError) Error() string { return e.code + ": " + e.message }

func validation(format string, args ...any) *apiError {
	return &apiError{http.StatusBadRequest, "ValidationException", fmt.Sprintf(format, args...)}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "CertificateManager.")
	body, _ := io.ReadAll(r.Body)
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		writeErr(w, &apiError{http.StatusBadRequest, "MissingAuthenticationToken", "request is not signed"})
		return
	}

	s.mu.Lock()
	s.calls = append(s.calls, op)
	f := s.faults[op]
	if f != nil {
		if f.Times > 0 {
			f.Times--
			if f.Times == 0 {
				delete(s.faults, op)
			}
		}
	}
	s.mu.Unlock()

	if f != nil && f.Hang && !f.After {
		<-r.Context().Done()
		return
	}
	if f != nil && !f.After {
		status := f.Status
		if status == 0 {
			status = http.StatusBadRequest
		}
		writeErr(w, &apiError{status, f.Code, f.Message})
		return
	}

	var (
		out any
		err *apiError
	)
	switch op {
	case "DescribeCertificate":
		out, err = s.describe(body)
	case "ImportCertificate":
		out, err = s.importCert(body)
	default:
		err = &apiError{http.StatusBadRequest, "UnknownOperationException", op}
	}
	if err == nil && f != nil && f.After && f.Hang {
		<-r.Context().Done()
		return
	}
	if err == nil && f != nil && f.After {
		status := f.Status
		if status == 0 {
			status = http.StatusBadRequest
		}
		err = &apiError{status, f.Code, f.Message}
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(out)
}

func writeErr(w http.ResponseWriter, e *apiError) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("X-Amzn-ErrorType", e.code)
	w.WriteHeader(e.status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": e.code, "message": e.message})
}

func (s *Server) describe(body []byte) (any, *apiError) {
	var in struct{ CertificateArn string }
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, validation("bad request: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.certs[in.CertificateArn]
	if !ok {
		return nil, &apiError{http.StatusBadRequest, "ResourceNotFoundException", "Could not find certificate " + in.CertificateArn + "."}
	}
	d := map[string]any{
		"CertificateArn": c.ARN,
		"Type":           c.Type,
		"Status":         "ISSUED",
		"KeyAlgorithm":   c.KeyAlg,
		"InUseBy":        []string{},
	}
	names := c.Names
	if c.Leaf != nil {
		names = c.Leaf.DNSNames
		d["Serial"] = colonHex(c.Leaf.SerialNumber.Bytes())
		d["NotBefore"] = float64(c.Leaf.NotBefore.Unix())
		d["NotAfter"] = float64(c.Leaf.NotAfter.Unix())
		d["ImportedAt"] = float64(c.ImportedAt.Unix())
		var kus []map[string]string
		for bit, name := range kuNames {
			if c.Leaf.KeyUsage&bit != 0 {
				kus = append(kus, map[string]string{"Name": name})
			}
		}
		d["KeyUsages"] = kus
		var ekus []map[string]string
		for _, u := range c.Leaf.ExtKeyUsage {
			if name, ok := ekuNames[u]; ok {
				ekus = append(ekus, map[string]string{"Name": name})
			}
		}
		d["ExtendedKeyUsages"] = ekus
	}
	if len(names) > 0 {
		d["DomainName"] = names[0]
		d["SubjectAlternativeNames"] = names
	}
	return map[string]any{"Certificate": d}, nil
}

func (s *Server) importCert(body []byte) (any, *apiError) {
	var in struct {
		CertificateArn   string
		Certificate      []byte
		CertificateChain []byte
		PrivateKey       []byte
		Tags             []struct{ Key, Value string }
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, validation("bad request: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.CertificateArn == "" {
		s.nextID++
		c := &Cert{ARN: s.ARN(fmt.Sprintf("00000000-0000-0000-0000-%012d", s.nextID)), Type: "IMPORTED", Tags: map[string]string{}}
		for _, t := range in.Tags {
			c.Tags[t.Key] = t.Value
		}
		if err := s.apply(c, in.Certificate, in.CertificateChain, in.PrivateKey); err != nil {
			return nil, err
		}
		s.certs[c.ARN] = c
		return map[string]string{"CertificateArn": c.ARN}, nil
	}
	c, ok := s.certs[in.CertificateArn]
	if !ok {
		return nil, &apiError{http.StatusBadRequest, "ResourceNotFoundException", "Could not find certificate " + in.CertificateArn + "."}
	}
	if len(in.Tags) > 0 {
		return nil, validation("Tags cannot be applied while reimporting a certificate.")
	}
	if c.Type != "IMPORTED" {
		return nil, validation("The certificate %s is not an imported certificate.", c.ARN)
	}
	next := *c
	if err := s.apply(&next, in.Certificate, in.CertificateChain, in.PrivateKey); err != nil {
		return nil, err
	}
	if c.KeyAlg != next.KeyAlg {
		return nil, validation("The algorithm of the reimported certificate's key (%s) does not match the original (%s).", next.KeyAlg, c.KeyAlg)
	}
	*c = next
	return map[string]string{"CertificateArn": c.ARN}, nil
}

// apply checks and stores certificate material on c.
func (s *Server) apply(c *Cert, certPEM, chainPEM, keyPEM []byte) *apiError {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return validation("Could not parse the certificate.")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return validation("Could not parse the certificate.")
	}
	if rest := chainPEM; len(rest) > 0 {
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if _, err := x509.ParseCertificate(b.Bytes); err != nil {
				return validation("Could not parse the certificate chain.")
			}
		}
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return validation("The certificate is not valid at this time.")
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return validation("Could not parse the private key.")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return validation("Could not parse the private key.")
	}
	signer, ok := k.(crypto.Signer)
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if !ok || !signer.Public().(equaler).Equal(leaf.PublicKey) {
		return validation("The private key does not match the certificate.")
	}
	c.Leaf, c.CertPEM, c.ChainPEM, c.KeyPEM = leaf, certPEM, chainPEM, keyPEM
	c.KeyAlg = keyAlg(leaf)
	c.Imports++
	c.ImportedAt = now
	return nil
}

func keyAlg(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA_%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		switch k.Curve.Params().Name {
		case "P-256":
			return "EC_prime256v1"
		case "P-384":
			return "EC_secp384r1"
		}
		return "EC_secp521r1"
	}
	return "UNKNOWN"
}

// colonHex formats a serial the way ACM does: two hex digits per byte,
// separated by colons.
func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}

var kuNames = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature: "DIGITAL_SIGNATURE",
	x509.KeyUsageKeyEncipherment:  "KEY_ENCIPHERMENT",
	x509.KeyUsageKeyAgreement:     "KEY_AGREEMENT",
}

var ekuNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageServerAuth: "TLS_WEB_SERVER_AUTHENTICATION",
	x509.ExtKeyUsageClientAuth: "TLS_WEB_CLIENT_AUTHENTICATION",
}
