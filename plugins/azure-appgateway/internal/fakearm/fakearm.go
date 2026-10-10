// Package fakearm is a small fake of the Azure Resource Manager API for
// Application Gateways, for tests. It serves GET and PUT on gateways with
// ETag and If-Match handling, Azure-AsyncOperation long-running operations,
// and fault injection. It never talks to Azure.
package fakearm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// Request is a request the fake received.
type Request struct {
	Method  string
	Path    string
	IfMatch string
	Body    map[string]any
}

// Fault makes the fake answer matching requests with an error.
type Fault struct {
	// Method and PathContains select requests; empty matches any.
	Method       string
	PathContains string
	Status       int
	Code         string
	Message      string
	// Times is how many requests the fault applies to; 0 means once.
	Times int
}

// OpFailure makes the next long-running operation end in Failed.
type OpFailure struct {
	Code    string
	Message string
	// Keep leaves the PUT body in the gateway model (with provisioning
	// state Failed), as Azure does when the update fails part way.
	// Otherwise the model goes back to what it was before the PUT.
	Keep bool
}

type operation struct {
	key     string
	pending int
	fail    *OpFailure
	hang    bool
	before  map[string]any
	done    bool
	status  string
}

// Server is the fake ARM endpoint.
type Server struct {
	*httptest.Server

	mu       sync.Mutex
	gateways map[string]map[string]any
	etags    map[string]int
	ops      map[string]*operation
	opSeq    int
	faults   []*Fault
	requests []Request

	// Certs maps a lowercase versioned Key Vault secret ID to the DER
	// certificates the gateway would load from it (leaf first).
	Certs map[string][][]byte
	// OpPolls is how many status polls answer InProgress before an
	// operation finishes. Default 1.
	OpPolls int
	// NextOpFailure, if set, makes the next operation fail.
	NextOpFailure *OpFailure
	// HangOps makes operations never finish.
	HangOps bool
	// ConcurrentWrites bumps the ETag before the next N PUTs, as if
	// someone else changed the gateway between our read and write.
	ConcurrentWrites int
	// OnConcurrentWrite, if set, is that other writer's change to the
	// stored gateway body.
	OnConcurrentWrite func(g map[string]any)
}

// New starts a fake ARM server. Close it when done.
func New() *Server {
	s := &Server{
		gateways: map[string]map[string]any{},
		etags:    map[string]int{},
		ops:      map[string]*operation{},
		Certs:    map[string][][]byte{},
		OpPolls:  1,
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// GatewayPath is the ARM path of a gateway.
func GatewayPath(sub, rg, name string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/applicationGateways/%s", sub, rg, name)
}

// V2Gateway returns a minimal v2 gateway body with a user-assigned
// identity, one HTTPS listener using sslCert, and that sslCertificates
// entry pointing at secretID (omitted when secretID is empty).
func V2Gateway(sub, rg, name, sslCert, secretID string) map[string]any {
	gwID := GatewayPath(sub, rg, name)
	certs := []any{}
	if secretID != "" {
		certs = append(certs, map[string]any{
			"name":       sslCert,
			"id":         gwID + "/sslCertificates/" + sslCert,
			"properties": map[string]any{"keyVaultSecretId": secretID},
		})
	}
	return map[string]any{
		"id":       gwID,
		"name":     name,
		"location": "eastus",
		"identity": map[string]any{
			"type": "UserAssigned",
			"userAssignedIdentities": map[string]any{
				"/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/agw-id": map[string]any{
					"principalId": "00000000-0000-0000-0000-00000000000a", "clientId": "00000000-0000-0000-0000-00000000000b",
				},
			},
		},
		"properties": map[string]any{
			"sku":             map[string]any{"name": "Standard_v2", "tier": "Standard_v2"},
			"sslCertificates": certs,
			"httpListeners": []any{map[string]any{
				"name": "https",
				"id":   gwID + "/httpListeners/https",
				"properties": map[string]any{
					"protocol":       "Https",
					"sslCertificate": map[string]any{"id": gwID + "/sslCertificates/" + sslCert},
				},
			}},
			"provisioningState": "Succeeded",
		},
	}
}

// PutGateway stores a gateway body as if it existed in Azure.
func (s *Server) PutGateway(sub, rg, name string, body map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(GatewayPath(sub, rg, name))
	s.etags[key]++
	s.gateways[key] = s.decorate(clone(body), key)
}

// Gateway returns a copy of a stored gateway body, or nil.
func (s *Server) Gateway(sub, rg, name string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.gateways[strings.ToLower(GatewayPath(sub, rg, name))]
	if g == nil {
		return nil
	}
	return clone(g)
}

// SetSecretID points a stored gateway's sslCertificates entry at id, as
// an operator would.
func (s *Server) SetSecretID(sub, rg, name, sslCert, id string) {
	g := s.Gateway(sub, rg, name)
	SetEntrySecretID(g, sslCert, id)
	s.PutGateway(sub, rg, name, g)
}

// SetEntrySecretID changes a gateway body's sslCertificates entry in place.
func SetEntrySecretID(g map[string]any, sslCert, id string) {
	if c := findCert(g, sslCert); c != nil {
		c["properties"] = map[string]any{"keyVaultSecretId": id}
	}
}

// SecretID returns the keyVaultSecretId of a gateway's sslCertificates
// entry, and whether the entry exists.
func (s *Server) SecretID(sub, rg, name, sslCert string) (string, bool) {
	g := s.Gateway(sub, rg, name)
	if g == nil {
		return "", false
	}
	c := findCert(g, sslCert)
	if c == nil {
		return "", false
	}
	props, _ := c["properties"].(map[string]any)
	id, _ := props["keyVaultSecretId"].(string)
	return id, true
}

// AddFault queues a fault.
func (s *Server) AddFault(f Fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.Times <= 0 {
		f.Times = 1
	}
	s.faults = append(s.faults, &f)
}

// Requests returns the requests received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Count returns how many requests had the method.
func (s *Server) Count(method string) int {
	n := 0
	for _, r := range s.Requests() {
		if r.Method == method && !strings.Contains(r.Path, "/operations/") {
			n++
		}
	}
	return n
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req := Request{Method: r.Method, Path: r.URL.Path, IfMatch: r.Header.Get("If-Match")}
	if r.Method == http.MethodPut {
		_ = json.NewDecoder(r.Body).Decode(&req.Body)
	}
	s.requests = append(s.requests, req)

	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		writeError(w, http.StatusUnauthorized, "AuthenticationFailed", "no bearer token")
		return
	}
	if r.URL.Query().Get("api-version") == "" {
		writeError(w, http.StatusBadRequest, "MissingApiVersionParameter", "api-version is required")
		return
	}
	for i, f := range s.faults {
		if (f.Method == "" || f.Method == r.Method) && strings.Contains(r.URL.Path, f.PathContains) {
			f.Times--
			if f.Times <= 0 {
				s.faults = append(s.faults[:i], s.faults[i+1:]...)
			}
			if f.Status == http.StatusTooManyRequests {
				w.Header().Set("Retry-After", "0")
			}
			writeError(w, f.Status, f.Code, f.Message)
			return
		}
	}

	if strings.Contains(r.URL.Path, "/operations/") {
		s.serveOperation(w, r)
		return
	}
	key := strings.ToLower(r.URL.Path)
	switch r.Method {
	case http.MethodGet:
		g, ok := s.gateways[key]
		if !ok {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The Resource 'Microsoft.Network/applicationGateways' was not found.")
			return
		}
		writeJSON(w, http.StatusOK, g)
	case http.MethodPut:
		s.servePut(w, r, key, req.Body)
	default:
		writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", r.Method)
	}
}

func (s *Server) servePut(w http.ResponseWriter, r *http.Request, key string, body map[string]any) {
	old, ok := s.gateways[key]
	if !ok {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "gateway not found")
		return
	}
	if s.ConcurrentWrites > 0 {
		s.ConcurrentWrites--
		s.etags[key]++
		if s.OnConcurrentWrite != nil {
			s.OnConcurrentWrite(old)
			old = s.decorate(old, key)
			s.gateways[key] = old
		}
		old["etag"] = s.etag(key)
	}
	if im := r.Header.Get("If-Match"); im != "" && im != "*" && im != s.etag(key) {
		writeError(w, http.StatusPreconditionFailed, "PreconditionFailed",
			"The specified If-Match header doesn't match the resource's current ETag.")
		return
	}
	if p, _ := old["properties"].(map[string]any); p != nil && p["provisioningState"] == "Updating" {
		writeError(w, http.StatusConflict, "AnotherOperationInProgress", "Another operation on this or dependent resource is in progress.")
		return
	}
	if body == nil {
		writeError(w, http.StatusBadRequest, "InvalidRequestFormat", "no body")
		return
	}
	s.etags[key]++
	g := s.decorate(body, key)
	g["properties"].(map[string]any)["provisioningState"] = "Updating"
	s.gateways[key] = g

	s.opSeq++
	id := fmt.Sprintf("op-%d", s.opSeq)
	op := &operation{key: key, pending: s.OpPolls, fail: s.NextOpFailure, hang: s.HangOps, before: old, status: "InProgress"}
	s.NextOpFailure = nil
	s.ops[id] = op
	sub := strings.Split(strings.TrimPrefix(r.URL.Path, "/subscriptions/"), "/")[0]
	w.Header().Set("Azure-AsyncOperation",
		fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Network/locations/eastus/operations/%s?api-version=%s",
			s.URL, sub, id, r.URL.Query().Get("api-version")))
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) serveOperation(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	op, ok := s.ops[id]
	if !ok {
		writeError(w, http.StatusNotFound, "OperationNotFound", id)
		return
	}
	if !op.done && !op.hang {
		if op.pending > 0 {
			op.pending--
		} else {
			op.done = true
			s.finish(op)
		}
	}
	resp := map[string]any{"status": op.status}
	if op.status == "Failed" {
		resp["error"] = map[string]any{"code": op.fail.Code, "message": op.fail.Message}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) finish(op *operation) {
	g := s.gateways[op.key]
	if op.fail == nil {
		op.status = "Succeeded"
		g["properties"].(map[string]any)["provisioningState"] = "Succeeded"
		return
	}
	op.status = "Failed"
	s.etags[op.key]++
	if op.fail.Keep {
		g["properties"].(map[string]any)["provisioningState"] = "Failed"
		g["etag"] = s.etag(op.key)
		return
	}
	restored := clone(op.before)
	restored["etag"] = s.etag(op.key)
	s.gateways[op.key] = restored
}

// decorate sets the read-only fields ARM fills in: etag, and for each SSL
// certificate the publicCertData of what the gateway would load. Write-only
// fields (PFX data and password) are dropped.
func (s *Server) decorate(g map[string]any, key string) map[string]any {
	g["etag"] = s.etag(key)
	props, _ := g["properties"].(map[string]any)
	if props == nil {
		props = map[string]any{}
		g["properties"] = props
	}
	certs, _ := props["sslCertificates"].([]any)
	for _, c := range certs {
		cm, _ := c.(map[string]any)
		cp, _ := cm["properties"].(map[string]any)
		if cp == nil {
			continue
		}
		if id, _ := cp["keyVaultSecretId"].(string); id != "" {
			if ders, ok := s.Certs[strings.ToLower(id)]; ok {
				cp["publicCertData"] = base64.StdEncoding.EncodeToString(PKCS7(ders...))
			} else {
				delete(cp, "publicCertData")
			}
		}
		delete(cp, "data")
		delete(cp, "password")
		cp["provisioningState"] = "Succeeded"
	}
	return g
}

func (s *Server) etag(key string) string {
	return fmt.Sprintf(`W/"%08d-0000-0000-0000-000000000000"`, s.etags[key])
}

func findCert(g map[string]any, name string) map[string]any {
	props, _ := g["properties"].(map[string]any)
	certs, _ := props["sslCertificates"].([]any)
	for _, c := range certs {
		cm, _ := c.(map[string]any)
		if n, _ := cm["name"].(string); strings.EqualFold(n, name) {
			return cm
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("x-ms-error-code", code)
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": msg}})
}

func clone(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// PKCS7 wraps DER certificates in a degenerate PKCS#7 signedData bundle,
// the form ARM uses for publicCertData.
func PKCS7(ders ...[]byte) []byte {
	var certs []byte
	for _, d := range ders {
		certs = append(certs, d...)
	}
	mustMarshal := func(v any, params string) []byte {
		b, err := asn1.MarshalWithParams(v, params)
		if err != nil {
			panic(err)
		}
		return b
	}
	version := mustMarshal(1, "")
	digestAlgs := mustMarshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true}, "")
	dataCI := mustMarshal(struct{ OID asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}}, "")
	certSet := mustMarshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certs}, "")
	signerInfos := digestAlgs
	sdBody := append(append(append(append(version, digestAlgs...), dataCI...), certSet...), signerInfos...)
	sd := mustMarshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: sdBody}, "")
	return mustMarshal(struct {
		OID     asn1.ObjectIdentifier
		Content asn1.RawValue
	}{
		asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sd},
	}, "")
}

// TestCert returns a self-signed DER certificate with the given serial.
func TestCert(serial int64) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "app.example.com"},
		DNSNames:     []string{"app.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		panic(err)
	}
	return der
}
