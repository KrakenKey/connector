// Package fakekk is an in-memory KrakenKey for tests: the connector
// enrollment, token, and rotation routes, checked strictly against the API
// contract. Other routes go to Fallback.
package fakekk

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
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
	// ReportStatus, if set, is returned by /connectors/report instead of
	// storing the report.
	ReportStatus int
	// RejectCertificateIDs are certificates the connector may not manage:
	// /connectors/report skips them and lists them in its answer.
	RejectCertificateIDs map[int]bool
	// ReportNoContent makes /connectors/report answer 204 with no body,
	// as an earlier version of the contract had it.
	ReportNoContent bool
	// ConfigStatus, if set, is returned by PUT and DELETE /connectors/config
	// instead of storing or clearing the summary.
	ConfigStatus int

	mu          sync.Mutex
	tokens      map[string]string // enrollment token -> connector name
	connectors  map[string]*Connector
	nonces      map[string]bool
	issued      map[string]string // api key -> connector id
	requests    []string
	tokenCalls  int
	rotateCalls int
	reports     []json.RawMessage
	configs     []json.RawMessage
	configCalls []string
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

// AddEnrollmentToken makes token valid once, for a connector named name.
func (s *Server) AddEnrollmentToken(token, name string) {
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
		case "/connectors/enroll":
			s.enroll(w, r)
			return
		case "/connectors/token":
			s.token(w, r)
			return
		case "/connectors/rotate":
			s.rotate(w, r)
			return
		case "/connectors/report":
			s.report(w, r)
			return
		}
	}
	if r.URL.Path == "/connectors/config" && (r.Method == http.MethodPut || r.Method == http.MethodDelete) {
		s.config(w, r)
		return
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

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	s.noBearer(r)
	var body struct {
		Token, PublicKey, Version, OS, Arch string
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.t.Errorf("enroll: bad body: %v", err)
	}
	pub, err := base64.StdEncoding.DecodeString(body.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		s.t.Errorf("enroll: publicKey %q is not standard base64 of 32 bytes", body.PublicKey)
	}
	if body.Version == "" || body.OS == "" || body.Arch == "" {
		s.t.Errorf("enroll: version/os/arch missing: %+v", body)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name, ok := s.tokens[body.Token]
	if !ok {
		unauthorized(w, "Invalid enrollment token")
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

// Reports returns the raw bodies of the reports accepted so far.
func (s *Server) Reports() []json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]json.RawMessage(nil), s.reports...)
}

var (
	labelRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	serialRe = regexp.MustCompile(`^[0-9a-fA-F]{1,64}$`)
	states   = map[string]bool{"pending": true, "staged": true, "activated": true, "verified": true,
		"activated_unverifiable": true, "failed": true, "rolled_back": true}
)

// report checks a status report against the contract, field by field, and
// stores it.
func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	if s.Authorized(r) == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{"statusCode": 403, "message": "Reports need a connector key"})
		return
	}
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		s.t.Errorf("report: bad body: %v", err)
	}
	var body map[string]json.RawMessage
	_ = json.Unmarshal(raw, &body)
	allowed(s.t, "report", body, "version", "os", "arch", "certificates")
	for _, k := range []string{"version", "os", "arch"} {
		var v string
		if json.Unmarshal(body[k], &v) != nil || v == "" {
			s.t.Errorf("report: %s missing", k)
		}
	}
	var certs []map[string]json.RawMessage
	if err := json.Unmarshal(body["certificates"], &certs); err != nil || len(certs) > 500 {
		s.t.Errorf("report: certificates: %v (%d)", err, len(certs))
	}
	accepted, rejected := 0, []int{}
	for _, c := range certs {
		allowed(s.t, "report certificate", c, "certificateId", "targets")
		var id int
		if json.Unmarshal(c["certificateId"], &id) != nil || id <= 0 {
			s.t.Errorf("report: certificateId %s", c["certificateId"])
		}
		if s.RejectCertificateIDs[id] {
			rejected = append(rejected, id)
		} else {
			accepted++
		}
		var targets []map[string]json.RawMessage
		if err := json.Unmarshal(c["targets"], &targets); err != nil || targets == nil || len(targets) > 50 {
			s.t.Errorf("report: targets of %d: %v (%d)", id, err, len(targets))
		}
		for _, t := range targets {
			allowed(s.t, "report target", t, "label", "state", "serial", "error", "updatedAt")
			var label, state, serial, errText, updated string
			_ = json.Unmarshal(t["label"], &label)
			_ = json.Unmarshal(t["state"], &state)
			_ = json.Unmarshal(t["updatedAt"], &updated)
			if !labelRe.MatchString(label) || !states[state] {
				s.t.Errorf("report: target %q state %q", label, state)
			}
			if _, err := time.Parse(time.RFC3339, updated); err != nil || !strings.HasSuffix(updated, "Z") {
				s.t.Errorf("report: updatedAt %q", updated)
			}
			if v, ok := t["serial"]; ok {
				if json.Unmarshal(v, &serial) != nil || !serialRe.MatchString(serial) {
					s.t.Errorf("report: serial %s", v)
				}
			}
			if v, ok := t["error"]; ok {
				if json.Unmarshal(v, &errText) != nil || errText == "" || len(utf16.Encode([]rune(errText))) > 200 {
					s.t.Errorf("report: error %s", v)
				}
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ReportStatus != 0 {
		writeJSON(w, s.ReportStatus, map[string]any{"statusCode": s.ReportStatus, "message": "report refused"})
		return
	}
	s.reports = append(s.reports, raw)
	if s.ReportNoContent {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": accepted, "rejectedCertificateIds": rejected})
}

func allowed(t *testing.T, what string, m map[string]json.RawMessage, keys ...string) {
	for k := range m {
		ok := false
		for _, a := range keys {
			ok = ok || k == a
		}
		if !ok {
			t.Errorf("%s: unexpected field %q", what, k)
		}
	}
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

// ConfigSummaries returns the raw bodies of the config summaries stored so
// far, oldest first.
func (s *Server) ConfigSummaries() []json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]json.RawMessage(nil), s.configs...)
}

// ConfigCalls returns the method of every /connectors/config request with
// a connector key, answered or not.
func (s *Server) ConfigCalls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.configCalls...)
}

var (
	hashRe        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	pluginNameRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	settingKeyRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	pluginSources = map[string]bool{"bundled": true, "data_dir": true, "path": true, "builtin": true}
)

// config checks PUT /connectors/config against the contract, field by
// field, and stores the summary; DELETE clears it.
func (s *Server) config(w http.ResponseWriter, r *http.Request) {
	if s.Authorized(r) == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{"statusCode": 403, "message": "Config summaries need a connector key"})
		return
	}
	s.mu.Lock()
	s.configCalls = append(s.configCalls, r.Method)
	status := s.ConfigStatus
	s.mu.Unlock()
	if r.Method == http.MethodDelete {
		if status != 0 {
			writeJSON(w, status, map[string]any{"statusCode": status, "message": "refused"})
			return
		}
		s.mu.Lock()
		s.configs = nil
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		s.t.Errorf("config: bad body: %v", err)
	}
	s.checkConfig(raw)
	if status != 0 {
		writeJSON(w, status, map[string]any{"statusCode": status, "message": "refused"})
		return
	}
	s.mu.Lock()
	s.configs = append(s.configs, raw)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) checkConfig(raw json.RawMessage) {
	t := s.t
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Errorf("config: %v", err)
		return
	}
	allowed(t, "config", body, "hash", "version", "checkIntervalSeconds", "plugins", "certificates", "truncated")
	var hash string
	if json.Unmarshal(body["hash"], &hash) != nil || !hashRe.MatchString(hash) {
		t.Errorf("config: hash %s", body["hash"])
	}
	// The hash covers the body without it: the connector sends the hash
	// first, then the summary as it hashed it.
	prefix := []byte(`{"hash":"` + hash + `",`)
	if !bytes.HasPrefix(raw, prefix) {
		t.Errorf("config: body does not start with the hash: %.80s", raw)
	} else if sum := sha256.Sum256(append([]byte("{"), raw[len(prefix):]...)); hex.EncodeToString(sum[:]) != hash {
		t.Errorf("config: hash %s does not match the body", hash)
	}
	var version string
	if json.Unmarshal(body["version"], &version) != nil || !printable(version, 64) || version == "" {
		t.Errorf("config: version %s", body["version"])
	}
	if v, ok := body["checkIntervalSeconds"]; ok && string(v) != "null" {
		var n int
		if json.Unmarshal(v, &n) != nil || n < 1 || n > 604800 {
			t.Errorf("config: checkIntervalSeconds %s", v)
		}
	}
	var truncated bool
	if json.Unmarshal(body["truncated"], &truncated) != nil {
		t.Errorf("config: truncated %s", body["truncated"])
	}

	var plugins []map[string]json.RawMessage
	if err := json.Unmarshal(body["plugins"], &plugins); err != nil || plugins == nil || len(plugins) > 50 {
		t.Errorf("config: plugins: %v (%d)", err, len(plugins))
	}
	for _, p := range plugins {
		allowed(t, "config plugin", p, "name", "version", "source")
		var name, source string
		_ = json.Unmarshal(p["name"], &name)
		_ = json.Unmarshal(p["source"], &source)
		if !pluginNameRe.MatchString(name) || !pluginSources[source] {
			t.Errorf("config: plugin %q source %q", name, source)
		}
		s.nullOrString(p["version"], 64, "plugin version")
	}

	var certs []map[string]json.RawMessage
	if err := json.Unmarshal(body["certificates"], &certs); err != nil || certs == nil || len(certs) > 500 {
		t.Errorf("config: certificates: %v (%d)", err, len(certs))
	}
	for _, c := range certs {
		allowed(t, "config certificate", c, "certificateId", "names", "keyStore", "targets")
		var id int
		if json.Unmarshal(c["certificateId"], &id) != nil || id < 1 {
			t.Errorf("config: certificateId %s", c["certificateId"])
		}
		var names []string
		if err := json.Unmarshal(c["names"], &names); err != nil || names == nil || len(names) > 100 {
			t.Errorf("config: names of %d: %v (%d)", id, err, len(names))
		}
		for _, n := range names {
			if !printable(n, 253) {
				t.Errorf("config: name %q", n)
			}
		}
		var ks map[string]json.RawMessage
		if err := json.Unmarshal(c["keyStore"], &ks); err != nil {
			t.Errorf("config: keyStore of %d: %v", id, err)
		}
		allowed(t, "config key store", ks, "plugin", "keyType", "settings")
		var ksPlugin string
		if json.Unmarshal(ks["plugin"], &ksPlugin) != nil || !pluginNameRe.MatchString(ksPlugin) {
			t.Errorf("config: keyStore.plugin %s", ks["plugin"])
		}
		s.nullOrString(ks["keyType"], 32, "keyType")
		s.checkSettings(ks["settings"])

		var targets []map[string]json.RawMessage
		if err := json.Unmarshal(c["targets"], &targets); err != nil || targets == nil || len(targets) > 50 {
			t.Errorf("config: targets of %d: %v (%d)", id, err, len(targets))
		}
		for _, tg := range targets {
			allowed(t, "config target", tg, "label", "plugin", "implicit", "runsCommand", "verify", "settings")
			var label, plugin string
			var implicit, runs bool
			_ = json.Unmarshal(tg["label"], &label)
			_ = json.Unmarshal(tg["plugin"], &plugin)
			if !labelRe.MatchString(label) || !pluginNameRe.MatchString(plugin) ||
				json.Unmarshal(tg["implicit"], &implicit) != nil || json.Unmarshal(tg["runsCommand"], &runs) != nil {
				t.Errorf("config: target %s", mustJSON(tg))
			}
			if v := tg["verify"]; string(v) != "null" {
				var vf map[string]json.RawMessage
				if err := json.Unmarshal(v, &vf); err != nil {
					t.Errorf("config: verify %s", v)
				}
				allowed(t, "config verify", vf, "host", "port", "skipChainValidation")
				s.nullOrString(vf["host"], 253, "verify.host")
				if p := vf["port"]; string(p) != "null" {
					var n int
					if json.Unmarshal(p, &n) != nil || n < 1 || n > 65535 {
						t.Errorf("config: verify.port %s", p)
					}
				}
				var skip bool
				if json.Unmarshal(vf["skipChainValidation"], &skip) != nil {
					t.Errorf("config: verify.skipChainValidation %s", vf["skipChainValidation"])
				}
			}
			s.checkSettings(tg["settings"])
		}
	}
}

func (s *Server) nullOrString(v json.RawMessage, max int, what string) {
	if string(v) == "null" {
		return
	}
	var str string
	if json.Unmarshal(v, &str) != nil || !printable(str, max) {
		s.t.Errorf("config: %s %s", what, v)
	}
}

func (s *Server) checkSettings(v json.RawMessage) {
	var m map[string]any
	if err := json.Unmarshal(v, &m); err != nil || m == nil || len(m) > 10 {
		s.t.Errorf("config: settings %s", v)
	}
	for k, val := range m {
		if !settingKeyRe.MatchString(k) {
			s.t.Errorf("config: setting key %q", k)
		}
		switch x := val.(type) {
		case string:
			if len(utf16.Encode([]rune(x))) > 256 || strings.ContainsFunc(x, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
				s.t.Errorf("config: setting %s = %q", k, x)
			}
		case bool:
		case float64:
			if math.IsInf(x, 0) || math.IsNaN(x) {
				s.t.Errorf("config: setting %s = %v", k, x)
			}
		default:
			s.t.Errorf("config: setting %s has type %T", k, val)
		}
	}
}

func printable(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
