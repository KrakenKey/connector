// Package fakevault is an in-memory stand-in for the parts of the Azure Key
// Vault certificates and secrets REST API the azure-keyvault plugin uses.
// It is for tests only: it speaks TLS with its own throwaway CA, answers
// unauthenticated requests with Key Vault's bearer challenge, and accepts
// one fixed token.
package fakevault

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Operation names, used for Deny, Fail and Calls.
const (
	OpCreate        = "create"
	OpGetPending    = "getPending"
	OpDeletePending = "deletePending"
	OpMerge         = "merge"
	OpGetPolicy     = "getPolicy"
	OpGetCert       = "getCert"
	OpGetSecret     = "getSecret"
)

// Token is the only bearer token the fake accepts.
const Token = "fake-key-vault-token"

// Server is a fake vault.
type Server struct {
	*httptest.Server
	// CAPEM is the CA that signed the server's TLS certificate.
	CAPEM []byte
	// Resource is the resource named in the authentication challenge.
	Resource string

	mu    sync.Mutex
	certs map[string]*certificate
	// Deny makes operations answer 403.
	deny map[string]bool
	// fail injects a status code for an operation, once per entry.
	fail map[string][]failure
	// csrDelay hides the CSR from this many pending reads after a create.
	csrDelay int
	// calls records "op name" for every authorized request.
	calls []string
	// omitCSROnCreate leaves the CSR out of the create response.
	omitCSROnCreate bool
	// ignoreReuse makes the fake create a new key even when reuse_key is set.
	ignoreReuse bool
	// base is the vault URL of the request being served.
	base string
}

type certificate struct {
	policy   *azcertificates.CertificatePolicy
	versions []*version
	pending  *pendingOp
}

type version struct {
	id          string
	key         crypto.Signer
	certs       [][]byte
	exportable  bool
	contentType string
}

type pendingOp struct {
	key       crypto.Signer
	csr       []byte
	policy    *azcertificates.CertificatePolicy
	requestID string
	status    string
	hideCSR   int
	issuer    string
}

// New starts a fake vault whose TLS certificate is valid for hosts (plus
// 127.0.0.1 and localhost). resource is the challenge resource; empty
// means the server's own URL.
func New(hosts []string, resource string) (*Server, error) {
	s := &Server{certs: map[string]*certificate{}, deny: map[string]bool{}, fail: map[string][]failure{}}
	tlsCfg, caPEM, err := serverTLS(append([]string{"127.0.0.1", "localhost"}, hosts...))
	if err != nil {
		return nil, err
	}
	s.CAPEM = caPEM
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.TLS = tlsCfg
	s.StartTLS()
	s.Resource = resource
	if s.Resource == "" {
		s.Resource = s.URL
	}
	return s, nil
}

// Transport returns an HTTP transport that trusts the fake's CA.
func (s *Server) Transport() *http.Transport {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(s.CAPEM)
	return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
}

// Deny makes op answer 403 until Allow.
func (s *Server) Deny(op string) { s.mu.Lock(); s.deny[op] = true; s.mu.Unlock() }

// Allow undoes Deny.
func (s *Server) Allow(op string) { s.mu.Lock(); delete(s.deny, op); s.mu.Unlock() }

// FailNext makes the next calls of op answer with the given statuses, one
// per call.
func (s *Server) FailNext(op string, statuses ...int) {
	s.mu.Lock()
	for _, st := range statuses {
		s.fail[op] = append(s.fail[op], failure{status: st, message: "injected failure"})
	}
	s.mu.Unlock()
}

// FailNextWith makes the next call of op answer with status and a Key
// Vault error message.
func (s *Server) FailNextWith(op string, status int, message string) {
	s.mu.Lock()
	s.fail[op] = append(s.fail[op], failure{status: status, message: message})
	s.mu.Unlock()
}

type failure struct {
	status  int
	message string
}

// HideCSR makes the next create leave the CSR out of its response and out
// of the next n pending reads.
func (s *Server) HideCSR(n int) {
	s.mu.Lock()
	s.omitCSROnCreate, s.csrDelay = true, n
	s.mu.Unlock()
}

// IgnoreReuseKey makes creates generate a new key even with reuse_key.
func (s *Server) IgnoreReuseKey() { s.mu.Lock(); s.ignoreReuse = true; s.mu.Unlock() }

// Calls returns the operations served so far, as "op name".
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// Versions returns the completed version ids of a certificate.
func (s *Server) Versions(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.certs[name]
	if c == nil {
		return nil
	}
	ids := make([]string, len(c.versions))
	for i, v := range c.versions {
		ids[i] = v.id
	}
	return ids
}

// HasPending reports whether a request is pending for a certificate.
func (s *Server) HasPending(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.certs[name]
	return c != nil && c.pending != nil
}

// SetPendingIssuer changes the issuer of the pending request, to simulate
// a request the connector did not start.
func (s *Server) SetPendingIssuer(name, issuer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.certs[name]; c != nil && c.pending != nil {
		c.pending.issuer = issuer
	}
}

// SetPolicyIssuer sets the issuer in a certificate's policy, creating the
// certificate's policy if needed.
func (s *Server) SetPolicyIssuer(name, issuer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.certs[name]
	if c == nil {
		c = &certificate{}
		s.certs[name] = c
	}
	if c.policy == nil {
		c.policy = &azcertificates.CertificatePolicy{}
	}
	c.policy.IssuerParameters = &azcertificates.IssuerParameters{Name: &issuer}
}

// Sign issues a certificate for the CSR from a throwaway CA, returning the
// leaf and the CA certificate as PEM. It stands in for KrakenKey.
func Sign(csrPEM string) (leafPEM, chainPEM string, err error) {
	b, _ := pem.Decode([]byte(csrPEM))
	if b == nil {
		return "", "", fmt.Errorf("no CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return "", "", err
	}
	return SignPublicKey(csr.PublicKey, csr.Subject.CommonName, csr.DNSNames)
}

// SignPublicKey issues a certificate for a public key.
func SignPublicKey(pub crypto.PublicKey, cn string, names []string) (leafPEM, chainPEM string, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Fake Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		return "", "", err
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, pub, caKey)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), nil
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+Token {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer authorization="https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000", resource="%s"`, s.Resource))
		kvError(w, http.StatusUnauthorized, "Unauthorized", "AKV10000: Request is missing a Bearer or PoP token.")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	op, name := route(r.Method, parts)
	if op == "" {
		kvError(w, http.StatusBadRequest, "BadParameter", "unknown route "+r.Method+" "+r.URL.Path)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Ids use the host the client asked for, as Key Vault does.
	s.base = "https://" + r.Host
	s.calls = append(s.calls, op+" "+name)
	if s.deny[op] {
		kvError(w, http.StatusForbidden, "Forbidden", "Caller is not authorized to perform action on resource.")
		return
	}
	if f := s.fail[op]; len(f) > 0 {
		s.fail[op] = f[1:]
		if f[0].status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "0")
		}
		kvError(w, f[0].status, strings.ReplaceAll(http.StatusText(f[0].status), " ", ""), f[0].message)
		return
	}

	body, _ := io.ReadAll(r.Body)
	c := s.certs[name]
	switch op {
	case OpCreate:
		s.create(w, name, c, body)
	case OpGetPending:
		if c == nil || c.pending == nil {
			kvError(w, http.StatusNotFound, "CertificateNotFound", "Pending certificate not found: "+name)
			return
		}
		show := c.pending.hideCSR == 0
		if !show {
			c.pending.hideCSR--
		}
		writeJSON(w, http.StatusOK, s.operation(name, c.pending, show))
	case OpDeletePending:
		if c == nil || c.pending == nil {
			kvError(w, http.StatusNotFound, "CertificateNotFound", "Pending certificate not found: "+name)
			return
		}
		p := c.pending
		c.pending = nil
		writeJSON(w, http.StatusOK, s.operation(name, p, true))
	case OpMerge:
		s.merge(w, name, c, body)
	case OpGetPolicy:
		if c == nil || c.policy == nil {
			kvError(w, http.StatusNotFound, "CertificateNotFound", "A certificate with (name/id) "+name+" was not found in this key vault.")
			return
		}
		writeJSON(w, http.StatusOK, c.policy)
	case OpGetCert:
		v := c.find(segment(parts, 2))
		if v == nil {
			kvError(w, http.StatusNotFound, "CertificateNotFound", "A certificate with (name/id) "+name+" was not found in this key vault.")
			return
		}
		writeJSON(w, http.StatusOK, s.certJSON(name, c, v))
	case OpGetSecret:
		v := c.find(segment(parts, 2))
		if v == nil {
			kvError(w, http.StatusNotFound, "SecretNotFound", "A secret with (name/id) "+name+" was not found in this key vault.")
			return
		}
		value, err := secretValue(v)
		if err != nil {
			kvError(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
		id := azsecrets.ID(s.base + "/secrets/" + name + "/" + v.id)
		writeJSON(w, http.StatusOK, azsecrets.Secret{ID: &id, ContentType: &v.contentType, Value: &value})
	}
}

func segment(p []string, i int) string {
	if i < len(p) {
		return p[i]
	}
	return ""
}

func route(method string, p []string) (op, name string) {
	if len(p) < 2 {
		return "", ""
	}
	name = p[1]
	switch {
	case p[0] == "certificates" && len(p) == 3 && p[2] == "create" && method == http.MethodPost:
		return OpCreate, name
	case p[0] == "certificates" && len(p) == 3 && p[2] == "pending" && method == http.MethodGet:
		return OpGetPending, name
	case p[0] == "certificates" && len(p) == 3 && p[2] == "pending" && method == http.MethodDelete:
		return OpDeletePending, name
	case p[0] == "certificates" && len(p) == 4 && p[2] == "pending" && p[3] == "merge" && method == http.MethodPost:
		return OpMerge, name
	case p[0] == "certificates" && len(p) == 3 && p[2] == "policy" && method == http.MethodGet:
		return OpGetPolicy, name
	case p[0] == "certificates" && method == http.MethodGet:
		return OpGetCert, name
	case p[0] == "secrets" && method == http.MethodGet:
		return OpGetSecret, name
	}
	return "", ""
}

// find returns version v, or the latest version for "" (or a missing
// segment).
func (c *certificate) find(v string) *version {
	if c == nil || len(c.versions) == 0 {
		return nil
	}
	if v == "" {
		return c.versions[len(c.versions)-1]
	}
	for _, ver := range c.versions {
		if ver.id == v {
			return ver
		}
	}
	return nil
}

func (s *Server) create(w http.ResponseWriter, name string, c *certificate, body []byte) {
	var params azcertificates.CreateCertificateParameters
	if err := json.Unmarshal(body, &params); err != nil || params.CertificatePolicy == nil {
		kvError(w, http.StatusBadRequest, "BadParameter", "invalid create request")
		return
	}
	if c == nil {
		c = &certificate{}
		s.certs[name] = c
	}
	if c.pending != nil {
		kvError(w, http.StatusConflict, "Conflict", "There is a pending operation on certificate "+name)
		return
	}
	pol := params.CertificatePolicy
	key, err := s.newKey(c, pol.KeyProperties)
	if err != nil {
		kvError(w, http.StatusBadRequest, "BadParameter", err.Error())
		return
	}
	tmpl := &x509.CertificateRequest{}
	if x := pol.X509CertificateProperties; x != nil {
		if x.Subject != nil {
			tmpl.Subject = pkix.Name{CommonName: strings.TrimPrefix(*x.Subject, "CN=")}
		}
		if x.SubjectAlternativeNames != nil {
			for _, n := range x.SubjectAlternativeNames.DNSNames {
				tmpl.DNSNames = append(tmpl.DNSNames, *n)
			}
		}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		kvError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	issuer := ""
	if pol.IssuerParameters != nil && pol.IssuerParameters.Name != nil {
		issuer = *pol.IssuerParameters.Name
	}
	c.policy = pol
	c.pending = &pendingOp{key: key, csr: csr, policy: pol, requestID: randomHex(16), status: "inProgress", issuer: issuer}
	show := true
	if s.omitCSROnCreate {
		show = false
		c.pending.hideCSR = s.csrDelay
		s.omitCSROnCreate, s.csrDelay = false, 0
	}
	writeJSON(w, http.StatusAccepted, s.operation(name, c.pending, show))
}

func (s *Server) newKey(c *certificate, kp *azcertificates.KeyProperties) (crypto.Signer, error) {
	if kp == nil || kp.KeyType == nil {
		return nil, fmt.Errorf("key_props.kty is required")
	}
	if kp.ReuseKey != nil && *kp.ReuseKey && !s.ignoreReuse && len(c.versions) > 0 {
		return c.versions[len(c.versions)-1].key, nil
	}
	switch *kp.KeyType {
	case azcertificates.KeyTypeRSA, azcertificates.KeyTypeRSAHSM:
		size := 2048
		if kp.KeySize != nil {
			size = int(*kp.KeySize)
		}
		if size != 2048 && size != 3072 && size != 4096 {
			return nil, fmt.Errorf("unsupported RSA key size %d", size)
		}
		return rsa.GenerateKey(rand.Reader, size)
	case azcertificates.KeyTypeEC, azcertificates.KeyTypeECHSM:
		crv := azcertificates.CurveNameP256
		if kp.Curve != nil {
			crv = *kp.Curve
		}
		switch crv {
		case azcertificates.CurveNameP256:
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case azcertificates.CurveNameP384:
			return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case azcertificates.CurveNameP521:
			return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		}
		return nil, fmt.Errorf("unsupported curve %s", crv)
	}
	return nil, fmt.Errorf("unsupported kty %s", *kp.KeyType)
}

func (s *Server) merge(w http.ResponseWriter, name string, c *certificate, body []byte) {
	if c == nil || c.pending == nil {
		kvError(w, http.StatusNotFound, "CertificateNotFound", "Pending certificate not found: "+name)
		return
	}
	var params azcertificates.MergeCertificateParameters
	if err := json.Unmarshal(body, &params); err != nil || len(params.X509Certificates) == 0 {
		kvError(w, http.StatusBadRequest, "BadParameter", "x5c is required")
		return
	}
	leaf, err := x509.ParseCertificate(params.X509Certificates[0])
	if err != nil {
		kvError(w, http.StatusBadRequest, "BadParameter", "x5c[0] is not a certificate")
		return
	}
	spki, _ := x509.MarshalPKIXPublicKey(c.pending.key.Public())
	if string(spki) != string(leaf.RawSubjectPublicKeyInfo) {
		kvError(w, http.StatusBadRequest, "BadParameter", "Public key from x509 certificate and key of this instance doesn't match")
		return
	}
	v := &version{id: randomHex(16), key: c.pending.key, certs: params.X509Certificates, exportable: true, contentType: "application/x-pkcs12"}
	if kp := c.pending.policy.KeyProperties; kp != nil && kp.Exportable != nil {
		v.exportable = *kp.Exportable
	}
	if sp := c.pending.policy.SecretProperties; sp != nil && sp.ContentType != nil {
		v.contentType = *sp.ContentType
	}
	c.versions = append(c.versions, v)
	c.pending = nil
	writeJSON(w, http.StatusCreated, s.certJSON(name, c, v))
}

func (s *Server) operation(name string, p *pendingOp, withCSR bool) azcertificates.CertificateOperation {
	id := azcertificates.ID(s.base + "/certificates/" + name + "/pending")
	issuer := p.issuer
	op := azcertificates.CertificateOperation{
		ID:               &id,
		IssuerParameters: &azcertificates.IssuerParameters{Name: &issuer},
		RequestID:        &p.requestID,
		Status:           &p.status,
	}
	if withCSR {
		op.CSR = p.csr
	}
	return op
}

func (s *Server) certJSON(name string, c *certificate, v *version) azcertificates.Certificate {
	id := azcertificates.ID(s.base + "/certificates/" + name + "/" + v.id)
	kid := azcertificates.ID(s.base + "/keys/" + name + "/" + v.id)
	sid := azcertificates.ID(s.base + "/secrets/" + name + "/" + v.id)
	enabled := true
	return azcertificates.Certificate{
		ID: &id, KID: &kid, SID: &sid,
		CER:        v.certs[0],
		Policy:     c.policy,
		Attributes: &azcertificates.CertificateAttributes{Enabled: &enabled},
	}
}

// secretValue renders a version's secret the way Key Vault does: base64
// PKCS#12 with an empty password, or PEM. Without export, only the
// certificates.
func secretValue(v *version) (string, error) {
	certs := make([]*x509.Certificate, len(v.certs))
	for i, der := range v.certs {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return "", err
		}
		certs[i] = c
	}
	if v.contentType == "application/x-pem-file" {
		var b strings.Builder
		if v.exportable {
			der, err := x509.MarshalPKCS8PrivateKey(v.key)
			if err != nil {
				return "", err
			}
			b.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		}
		for _, der := range v.certs {
			b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		}
		return b.String(), nil
	}
	var pfx []byte
	var err error
	if v.exportable {
		pfx, err = pkcs12.LegacyDES.Encode(v.key, certs[0], certs[1:], "")
	} else {
		pfx, err = pkcs12.LegacyDES.EncodeTrustStore(certs, "")
	}
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pfx), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func kvError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	return n
}

// serverTLS makes a throwaway CA and a server certificate for hosts.
func serverTLS(hosts []string) (*tls.Config, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "fakevault test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "fakevault"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
	return cfg, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
}
