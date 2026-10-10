// Package fakekk is an in-memory KrakenKey for tests: the connector
// enrolment, token, and rotation routes, checked strictly against the API
// contract. Other routes go to Fallback.
package fakekk

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// Connector is a connector KrakenKey knows.
type Connector struct {
	ID        string
	Name      string
	PublicKey ed25519.PublicKey
	Revoked   bool
	Version   string
	OS        string
	Arch      string
}

// Server is the fake.
type Server struct {
	t   *testing.T
	srv *httptest.Server
	URL string

	// Fallback serves every route not handled here. Requests to it carry
	// the bearer token; Authorized says which connector it belongs to.
	Fallback http.Handler
	// Now is KrakenKey's clock. Defaults to time.Now.
	Now func() time.Time
	// TokenTTL is the lifetime of issued keys. Default one hour.
	TokenTTL time.Duration
	// RotateStatus, if set, is returned by /connectors/rotate instead of
	// rotating.
	RotateStatus int

	mu          sync.Mutex
	tokens      map[string]string // enrolment token -> connector name
	connectors  map[string]*Connector
	nonces      map[string]bool
	issued      map[string]string // api key -> connector id
	requests    []string
	tokenCalls  int
	rotateCalls int
}

// New starts a fake.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{t: t, tokens: map[string]string{}, connectors: map[string]*Connector{},
		nonces: map[string]bool{}, issued: map[string]string{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	s.URL = s.srv.URL
	t.Cleanup(s.srv.Close)
	return s
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// AddEnrolmentToken makes token valid once, for a connector named name.
func (s *Server) AddEnrolmentToken(token, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = name
}

// Connector returns a copy of a connector, or nil.
func (s *Server) Connector(id string) *Connector {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.connectors[id]; ok {
		cp := *c
		return &cp
	}
	return nil
}

// Revoke revokes a connector and every key issued to it.
func (s *Server) Revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connectors[id].Revoked = true
	for k, cid := range s.issued {
		if cid == id {
			delete(s.issued, k)
		}
	}
}

// Requests returns "METHOD /path" for every request so far.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// TokenCalls returns the number of POST /connectors/token requests.
func (s *Server) TokenCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenCalls
}

// RotateCalls returns the number of POST /connectors/rotate requests.
func (s *Server) RotateCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rotateCalls
}

// Authorized returns the connector id that r's bearer token was issued
// to, or "" if it is not a connector-issued key.
func (s *Server) Authorized(r *http.Request) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issued[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
}

var (
	timestampRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
	nonceRe     = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func unauthorized(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusUnauthorized, map[string]any{"statusCode": 401, "message": msg, "error": "Unauthorized"})
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, r.Method+" "+r.URL.Path)
	s.mu.Unlock()

	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/connectors/") {
		switch r.URL.Path {
		case "/connectors/enrol":
			s.enrol(w, r)
			return
		case "/connectors/token":
			s.token(w, r)
			return
		case "/connectors/rotate":
			s.rotate(w, r)
			return
		}
	}
	if s.Fallback != nil {
		s.Fallback.ServeHTTP(w, r)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func (s *Server) noBearer(r *http.Request) {
	if r.Header.Get("Authorization") != "" {
		s.t.Errorf("%s sent an Authorization header", r.URL.Path)
	}
}

func (s *Server) enrol(w http.ResponseWriter, r *http.Request) {
	s.noBearer(r)
	var body struct {
		Token, PublicKey, Version, OS, Arch string
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.t.Errorf("enrol: bad body: %v", err)
	}
	pub, err := base64.StdEncoding.DecodeString(body.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		s.t.Errorf("enrol: publicKey %q is not standard base64 of 32 bytes", body.PublicKey)
	}
	if body.Version == "" || body.OS == "" || body.Arch == "" {
		s.t.Errorf("enrol: version/os/arch missing: %+v", body)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name, ok := s.tokens[body.Token]
	if !ok {
		unauthorized(w, "Invalid enrolment token")
		return
	}
	delete(s.tokens, body.Token)
	id := newUUID()
	s.connectors[id] = &Connector{ID: id, Name: name, PublicKey: pub, Version: body.Version, OS: body.OS, Arch: body.Arch}
	writeJSON(w, http.StatusOK, map[string]string{"connectorId": id, "name": name})
}

// checkAssertion verifies the parts every signed request shares and
// returns the connector, or nil with a 401 written.
func (s *Server) checkAssertion(w http.ResponseWriter, connectorID, timestamp, nonce, signature string, msg []byte) *Connector {
	if !timestampRe.MatchString(timestamp) {
		s.t.Errorf("timestamp %q is not RFC 3339 UTC with second precision", timestamp)
	}
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || !nonceRe.MatchString(nonce) || len(raw) < 16 || len(nonce) > 64 {
		s.t.Errorf("nonce %q is not unpadded base64url of 16+ bytes, at most 64 characters", nonce)
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		s.t.Errorf("signature is not standard base64 of 64 bytes")
	}

	c, ok := s.connectors[connectorID]
	if !ok || c.Revoked {
		unauthorized(w, "Invalid connector credentials")
		return nil
	}
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil || ts.Sub(s.now()).Abs() > 300*time.Second {
		unauthorized(w, "Invalid connector credentials")
		return nil
	}
	if !ed25519.Verify(c.PublicKey, msg, sig) {
		unauthorized(w, "Invalid connector credentials")
		return nil
	}
	if s.nonces[connectorID+"/"+nonce] {
		unauthorized(w, "Invalid connector credentials")
		return nil
	}
	s.nonces[connectorID+"/"+nonce] = true
	return c
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	s.noBearer(r)
	var body struct{ ConnectorID, Timestamp, Nonce, Signature string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.t.Errorf("token: bad body: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenCalls++
	// The canonical message, written out here rather than shared with the
	// connector's code, so a change on either side shows up.
	msg := "KRAKENKEY-CONNECTOR-TOKEN-V1\n" + body.ConnectorID + "\n" + body.Timestamp + "\n" + body.Nonce
	if s.checkAssertion(w, body.ConnectorID, body.Timestamp, body.Nonce, body.Signature, []byte(msg)) == nil {
		return
	}
	ttl := s.TokenTTL
	if ttl == 0 {
		ttl = time.Hour
	}
	key := "kk_" + randHex(24)
	s.issued[key] = body.ConnectorID
	writeJSON(w, http.StatusOK, map[string]string{
		"apiKey":    key,
		"expiresAt": s.now().Add(ttl).UTC().Format("2006-01-02T15:04:05.000Z"),
	})
}

func (s *Server) rotate(w http.ResponseWriter, r *http.Request) {
	s.noBearer(r)
	var body struct{ ConnectorID, NewPublicKey, Timestamp, Nonce, Signature string }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.t.Errorf("rotate: bad body: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotateCalls++
	if s.RotateStatus != 0 {
		writeJSON(w, s.RotateStatus, map[string]any{"statusCode": s.RotateStatus, "message": "rotation refused"})
		return
	}
	newPub, err := base64.StdEncoding.DecodeString(body.NewPublicKey)
	if err != nil || len(newPub) != ed25519.PublicKeySize {
		s.t.Errorf("rotate: newPublicKey %q is not standard base64 of 32 bytes", body.NewPublicKey)
	}
	msg := "KRAKENKEY-CONNECTOR-ROTATE-V1\n" + body.ConnectorID + "\n" + body.NewPublicKey + "\n" + body.Timestamp + "\n" + body.Nonce
	c := s.checkAssertion(w, body.ConnectorID, body.Timestamp, body.Nonce, body.Signature, []byte(msg))
	if c == nil {
		return
	}
	c.PublicKey = newPub
	w.WriteHeader(http.StatusNoContent)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newUUID() string {
	h := randHex(16)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
