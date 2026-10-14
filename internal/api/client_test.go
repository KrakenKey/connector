package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testKey = "kk_secret_test_key"

type recorder struct {
	mu     sync.Mutex
	sleeps []time.Duration
}

func (r *recorder) sleep(_ context.Context, d time.Duration) error {
	r.mu.Lock()
	r.sleeps = append(r.sleeps, d)
	r.mu.Unlock()
	return nil
}

func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *recorder) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL, testKey, "krakenkey-connector/test")
	rec := &recorder{}
	c.sleep = rec.sleep
	return c, rec
}

func TestGetCertWithRenewAfter(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/certs/tls/1043" {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+testKey {
			t.Error("missing bearer token")
		}
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "krakenkey-connector/") {
			t.Errorf("user agent %q", r.Header.Get("User-Agent"))
		}
		_, _ = w.Write([]byte(`{"id":1043,"status":"issued","crtPem":"x","expiresAt":"2026-12-31T00:00:00.000Z",
			"renewAfter":"2026-12-01T12:00:00.000Z","managedBy":"connector"}`))
	})
	cert, err := c.GetCert(context.Background(), 1043)
	if err != nil {
		t.Fatal(err)
	}
	at, source, ok := cert.RenewAt()
	if !ok || source != RenewSourceAPI || !at.Equal(time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("RenewAt = %v %v %v", at, source, ok)
	}
	if cert.ManagedBy == nil || *cert.ManagedBy != "connector" {
		t.Errorf("managedBy = %v", cert.ManagedBy)
	}
}

func TestRenewAfterFallback(t *testing.T) {
	for _, body := range []string{
		`{"id":1,"status":"issued","expiresAt":"2026-12-31T00:00:00Z"}`,                   // older API: field missing
		`{"id":1,"status":"issued","expiresAt":"2026-12-31T00:00:00Z","renewAfter":null}`, // explicit null
	} {
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
		cert, err := c.GetCert(context.Background(), 1)
		if err != nil {
			t.Fatal(err)
		}
		at, source, ok := cert.RenewAt()
		if !ok || source != RenewSourceExpiry || !at.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("%s: RenewAt = %v %v %v, want 30 days before expiry", body, at, source, ok)
		}
	}
	var none Cert
	if _, _, ok := none.RenewAt(); ok {
		t.Error("RenewAt with no dates reported ok")
	}
}

func TestRenewAtTwoThirdsOfLifetime(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: nb, NotAfter: nb.Add(6 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	pemData := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	expires := nb.Add(6 * 24 * time.Hour)
	c := Cert{CrtPem: pemData, ExpiresAt: &expires}
	at, source, ok := c.RenewAt()
	// A six-day certificate renews after four days, not 30 days before
	// expiry (which would be before it was issued).
	if !ok || source != RenewSourceLifetime || !at.Equal(nb.Add(4*24*time.Hour)) {
		t.Errorf("RenewAt = %v %q %v", at, source, ok)
	}
}

func TestRedirectsAreRefused(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
	}))
	defer other.Close()
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	})
	_, err := c.GetCert(context.Background(), 1)
	if err == nil || !strings.Contains(err.Error(), "unexpected redirect") {
		t.Fatalf("err = %v", err)
	}
	if leaked.Load() {
		t.Error("API key sent to the redirect target")
	}
}

func TestWaitForIssuanceStopsOnClientErrors(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusBadRequest} {
		var calls atomic.Int32
		c, rec := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"statusCode":` + strconv.Itoa(code) + `,"message":"no"}`))
		})
		if _, err := c.WaitForIssuance(context.Background(), 1, "", time.Time{}); err == nil || !IsClientError(err) {
			t.Errorf("%d: err = %v", code, err)
		}
		if calls.Load() != 1 || len(rec.sleeps) != 0 {
			t.Errorf("%d: polled %d times", code, calls.Load())
		}
	}
	// A rate limit the client will not wait out ends the wait too.
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "86400")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, err := c.WaitForIssuance(context.Background(), 1, "", time.Time{})
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Errorf("429: err = %v", err)
	}
}

func TestRenewSendsCSR(t *testing.T) {
	const csr = "-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----\n"
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/certs/tls/9/renew" {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type %q", r.Header.Get("Content-Type"))
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if len(body) != 1 || body["csrPem"] != csr {
			t.Errorf("body = %v", body)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":9,"status":"renewing"}`))
	})
	resp, err := c.RenewCert(context.Background(), 9, csr)
	if err != nil || resp.Status != StatusRenewing {
		t.Fatalf("RenewCert = %+v, %v", resp, err)
	}
}

func TestUnauthorizedStopsAllCalls(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"statusCode":401,"message":"Invalid API key","error":"Unauthorized"}`))
	})
	_, err := c.GetCert(context.Background(), 1)
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("err = %v, want AuthError", err)
	}
	if strings.Contains(err.Error(), testKey) {
		t.Error("error message contains the API key")
	}
	_, err = c.RenewCert(context.Background(), 1, "csr")
	if !errors.As(err, &authErr) {
		t.Fatalf("second call err = %v", err)
	}
	_, err = c.WaitForIssuance(context.Background(), 1, "", time.Time{})
	if !errors.As(err, &authErr) {
		t.Fatalf("wait err = %v", err)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("server saw %d requests after a 401, want 1", n)
	}
}

func TestRateLimitHonoursRetryAfter(t *testing.T) {
	var calls atomic.Int32
	c, rec := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"statusCode":429,"message":"ThrottlerException: Too Many Requests"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":1,"status":"renewing"}`))
	})
	if _, err := c.RenewCert(context.Background(), 1, "csr"); err != nil {
		t.Fatalf("RenewCert: %v", err)
	}
	if len(rec.sleeps) != 1 || rec.sleeps[0] != 7*time.Second {
		t.Errorf("sleeps = %v, want [7s]", rec.sleeps)
	}
}

func TestRateLimitTooLongIsReturned(t *testing.T) {
	var calls atomic.Int32
	c, rec := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, err := c.GetCert(context.Background(), 1)
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.RetryAfter != time.Hour {
		t.Fatalf("err = %v, want RateLimitError with 1h", err)
	}
	if calls.Load() != 1 || len(rec.sleeps) != 0 {
		t.Errorf("calls = %d, sleeps = %v; a long Retry-After must not be waited out", calls.Load(), rec.sleeps)
	}
}

func TestRateLimitRetriesAreBounded(t *testing.T) {
	var calls atomic.Int32
	c, rec := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests) // no Retry-After
	})
	_, err := c.GetCert(context.Background(), 1)
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != int32(c.MaxRateLimitRetries+1) {
		t.Errorf("calls = %d", calls.Load())
	}
	for _, s := range rec.sleeps {
		if s != defaultRetryAfter {
			t.Errorf("sleep %s, want the default %s when Retry-After is missing", s, defaultRetryAfter)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	cases := map[string]time.Duration{
		"":                              defaultRetryAfter,
		"garbage":                       defaultRetryAfter,
		"0":                             time.Second,
		"-5":                            time.Second,
		"99999999999999999999":          defaultRetryAfter, // not an int64
		"9223372036":                    maxRetryAfter,     // would overflow as a Duration
		"Sat, 10 Oct 2099 12:00:00 GMT": maxRetryAfter,
		"30":                            30 * time.Second,
		"Sat, 10 Oct 2026 12:02:00 GMT": 2 * time.Minute,
	}
	for in, want := range cases {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("parseRetryAfter(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestErrorShapes(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/certs/tls/1":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"statusCode":404,"message":"Certificate not found"}`))
		case "/certs/tls/2/renew":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"statusCode":400,"message":["csrPem must be a string","names differ"]}`))
		default:
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`<html>bad gateway</html>`))
		}
	})
	_, err := c.GetCert(context.Background(), 1)
	var nf *NotFoundError
	if !errors.As(err, &nf) {
		t.Errorf("404 err = %v", err)
	}
	_, err = c.RenewCert(context.Background(), 2, "x")
	if err == nil || !strings.Contains(err.Error(), "csrPem must be a string; names differ") {
		t.Errorf("400 err = %v", err)
	}
	_, err = c.GetCertChain(context.Background(), 3)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 502 || !strings.Contains(err.Error(), "bad gateway") {
		t.Errorf("502 err = %v", err)
	}
}

func TestWaitForIssuance(t *testing.T) {
	var calls atomic.Int32
	c, rec := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		switch calls.Add(1) {
		case 1:
			// The record may still show the old certificate as issued.
			_, _ = w.Write([]byte(`{"id":1,"status":"issued","crtPem":"OLD"}`))
		case 2:
			_, _ = w.Write([]byte(`{"id":1,"status":"renewing","crtPem":"OLD"}`))
		case 3:
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			_, _ = w.Write([]byte(`{"id":1,"status":"issued","crtPem":"NEW","chainPem":"CHAIN"}`))
		}
	})
	c.PollInterval = 3 * time.Second
	cert, err := c.WaitForIssuance(context.Background(), 1, "OLD", time.Time{})
	if err != nil {
		t.Fatalf("WaitForIssuance: %v", err)
	}
	if cert.CrtPem != "NEW" || cert.ChainPem != "CHAIN" {
		t.Errorf("cert = %+v", cert)
	}
	if len(rec.sleeps) != 3 {
		t.Errorf("sleeps = %v, want one poll interval per unfinished check", rec.sleeps)
	}
	for _, s := range rec.sleeps {
		if s != 3*time.Second {
			t.Errorf("sleep %s, want the poll interval", s)
		}
	}
}

func TestWaitForIssuanceFailed(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":1,"status":"failed","failureReason":"CNAME for _acme-challenge.example.com missing"}`))
	})
	_, err := c.WaitForIssuance(context.Background(), 1, "OLD", time.Time{})
	var f *IssuanceFailedError
	if !errors.As(err, &f) || !strings.Contains(err.Error(), "CNAME") {
		t.Fatalf("err = %v", err)
	}
}

func TestWaitForIssuanceRenewalFailed(t *testing.T) {
	requested := time.Date(2026, 10, 14, 6, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	c, rec := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"id":1,"status":"renewing","crtPem":"OLD"}`))
			return
		}
		// KrakenKey kept the current certificate after the renewal failed.
		_, _ = w.Write([]byte(`{"id":1,"status":"issued","crtPem":"OLD","expiresAt":"2026-11-20T10:00:00.000Z",
			"failureReason":"CAA record for example.com prevents issuance","renewalFailedAt":"2026-10-14T06:00:03.000Z"}`))
	})
	_, err := c.WaitForIssuance(context.Background(), 1, "OLD", requested)
	var rf *RenewalFailedError
	if !errors.As(err, &rf) {
		t.Fatalf("err = %v, want a RenewalFailedError", err)
	}
	if rf.Reason != "CAA record for example.com prevents issuance" || !rf.FailedAt.Equal(requested.Add(3*time.Second)) {
		t.Errorf("error = %+v", rf)
	}
	want := "renewal failed in KrakenKey: CAA record for example.com prevents issuance; KrakenKey kept the current certificate (expires 2026-11-20T10:00:00Z)"
	if err.Error() != want {
		t.Errorf("message = %q, want %q", err.Error(), want)
	}
	if IsClientError(err) {
		t.Error("a failed renewal is not a client error")
	}
	if len(rec.sleeps) != 1 {
		t.Errorf("sleeps = %v, want to stop at the first check that shows the failure", rec.sleeps)
	}
}

// A renewalFailedAt from before the request (less the allowed skew)
// belongs to an earlier renewal, and the wait goes on as before.
func TestWaitForIssuanceIgnoresEarlierRenewalFailure(t *testing.T) {
	requested := time.Date(2026, 10, 14, 6, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"id":1,"status":"issued","crtPem":"OLD","failureReason":"x","renewalFailedAt":"2026-10-13T06:00:00.000Z"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":1,"status":"issued","crtPem":"NEW"}`))
	})
	cert, err := c.WaitForIssuance(context.Background(), 1, "OLD", requested)
	if err != nil || cert.CrtPem != "NEW" {
		t.Fatalf("cert = %+v, err = %v, want the new certificate", cert, err)
	}
}

// A failure recorded slightly before the request time, as a clock that is
// a little ahead would show it, still counts.
func TestWaitForIssuanceRenewalFailedWithinSkew(t *testing.T) {
	requested := time.Date(2026, 10, 14, 6, 0, 0, 0, time.UTC)
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":1,"status":"issued","crtPem":"OLD","renewalFailedAt":"2026-10-14T05:59:30.000Z"}`))
	})
	_, err := c.WaitForIssuance(context.Background(), 1, "OLD", requested)
	var rf *RenewalFailedError
	if !errors.As(err, &rf) {
		t.Fatalf("err = %v, want a RenewalFailedError", err)
	}
}

func TestRenewCertServerTime(t *testing.T) {
	date := time.Date(2026, 10, 14, 6, 0, 0, 0, time.UTC)
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Date", date.Format(http.TimeFormat))
		_, _ = w.Write([]byte(`{"id":1,"status":"renewing"}`))
	})
	r, err := c.RenewCert(context.Background(), 1, "CSR")
	if err != nil {
		t.Fatal(err)
	}
	if !r.ServerTime.Equal(date) {
		t.Errorf("ServerTime = %v, want %v", r.ServerTime, date)
	}
}

func TestWaitForIssuanceTimeout(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":1,"status":"renewing"}`))
	})
	c.sleep = sleepCtx
	c.PollInterval = 10 * time.Millisecond
	c.IssuanceTimeout = 50 * time.Millisecond
	_, err := c.WaitForIssuance(context.Background(), 1, "", time.Time{})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v", err)
	}
}

func TestGetCertChain(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/certs/tls/4/chain" {
			t.Errorf("path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"leafCert":{},"intermediates":[],"fullChainPem":"LEAF\nINTER"}`))
	})
	ch, err := c.GetCertChain(context.Background(), 4)
	if err != nil || ch.FullChainPem != "LEAF\nINTER" {
		t.Fatalf("chain = %+v, %v", ch, err)
	}
}

func TestConnectorRoutesSendNoBearerAndDoNotLatch401(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if strings.HasPrefix(r.URL.Path, "/connectors/") && r.Header.Get("Authorization") != "" {
			t.Errorf("%s sent a bearer token", r.URL.Path)
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"statusCode":401,"message":"Invalid connector credentials"}`))
	})
	ctx := context.Background()
	_, err := c.Enroll(ctx, EnrollRequest{Token: "kkce_x"})
	var tokErr *EnrollmentTokenError
	if !errors.As(err, &tokErr) {
		t.Errorf("enroll 401: %v", err)
	}
	_, err = c.ConnectorToken(ctx, ConnectorTokenRequest{ConnectorID: "c"})
	var connErr *ConnectorAuthError
	if !errors.As(err, &connErr) || !IsClientError(err) {
		t.Errorf("token 401: %v", err)
	}
	if err := c.RotateIdentity(ctx, RotateRequest{}); !errors.As(err, &connErr) {
		t.Errorf("rotate 401: %v", err)
	}
	// None of these is the API key failing, so authenticated calls still go out.
	_, _ = c.GetCert(ctx, 1)
	if calls.Load() != 4 {
		t.Errorf("%d requests, want 4: a 401 on a connector route blocked later calls", calls.Load())
	}
}

func TestKeySourceIsAskedPerRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":1,"status":"issued","auth":"` + r.Header.Get("Authorization") + `"}`))
	}))
	defer srv.Close()
	var n atomic.Int32
	keys := KeySourceFunc(func(context.Context) (string, error) {
		if n.Add(1) == 3 {
			return "", &ConnectorAuthError{Message: "revoked"}
		}
		return "kk_short_" + strconv.Itoa(int(n.Load())), nil
	})
	c := NewClientWithKeys(srv.URL, keys, "test")
	for range 2 {
		if _, err := c.GetCert(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
	}
	_, err := c.GetCert(context.Background(), 1)
	if !errors.As(err, new(*ConnectorAuthError)) {
		t.Errorf("key source error not returned: %v", err)
	}
}
