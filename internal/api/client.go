package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// KeySource supplies the API key for each request: a fixed key, or a
// short-lived key the connector gets by proving its identity.
type KeySource interface {
	APIKey(ctx context.Context) (string, error)
}

// StaticKey is a KeySource for a fixed API key.
type StaticKey string

// APIKey returns the key.
func (k StaticKey) APIKey(context.Context) (string, error) { return string(k), nil }

// KeySourceFunc adapts a function to KeySource.
type KeySourceFunc func(ctx context.Context) (string, error)

// APIKey calls f.
func (f KeySourceFunc) APIKey(ctx context.Context) (string, error) { return f(ctx) }

// Client calls the KrakenKey API with an API key. It is safe for
// concurrent use.
type Client struct {
	baseURL    string
	keys       KeySource
	userAgent  string
	httpClient *http.Client

	// MaxRateLimitWait is the longest Retry-After the client waits out
	// before returning a RateLimitError.
	MaxRateLimitWait time.Duration
	// MaxRateLimitRetries is how many 429s in a row one call waits out.
	MaxRateLimitRetries int
	// PollInterval is the time between status checks in WaitForIssuance.
	PollInterval time.Duration
	// IssuanceTimeout bounds WaitForIssuance.
	IssuanceTimeout time.Duration

	authFailed atomic.Pointer[AuthError]
	sleep      func(context.Context, time.Duration) error
}

// NewClient returns a client for baseURL. The key is sent as a bearer
// token and never logged or included in errors.
func NewClient(baseURL, apiKey, userAgent string) *Client {
	return NewClientWithKeys(baseURL, StaticKey(apiKey), userAgent)
}

// NewClientWithKeys returns a client that asks keys for the bearer token
// before each request.
func NewClientWithKeys(baseURL string, keys KeySource, userAgent string) *Client {
	return &Client{
		baseURL:   strings.TrimRight(baseURL, "/"),
		keys:      keys,
		userAgent: userAgent,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			// Never follow redirects: the bearer token must only go to the
			// configured API URL.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		MaxRateLimitWait:    5 * time.Minute,
		MaxRateLimitRetries: 3,
		PollInterval:        10 * time.Second,
		IssuanceTimeout:     15 * time.Minute,
		sleep:               sleepCtx,
	}
}

// defaultRetryAfter is used when a 429 has no usable Retry-After header.
const defaultRetryAfter = 60 * time.Second

// do sends an authenticated request.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	return c.send(ctx, method, path, body, out, true)
}

// send sends a request, with the bearer token when auth is true. A 401 on
// an authenticated request is remembered and ends every later call; on an
// unauthenticated one (the connector enrollment and token routes) it is
// returned as an *APIError and not remembered.
func (c *Client) send(ctx context.Context, method, path string, body, out any, auth bool) error {
	_, err := c.sendDated(ctx, method, path, body, out, auth)
	return err
}

// sendDated is send that also returns the Date header of a 2xx response:
// the API's clock when it answered (zero when absent or unreadable).
func (c *Client) sendDated(ctx context.Context, method, path string, body, out any, auth bool) (time.Time, error) {
	if prev := c.authFailed.Load(); prev != nil && auth {
		return time.Time{}, prev
	}
	var data []byte
	if body != nil {
		var err error
		if data, err = json.Marshal(body); err != nil {
			return time.Time{}, fmt.Errorf("encode request: %w", err)
		}
	}

	for attempt := 0; ; attempt++ {
		var reader io.Reader
		if data != nil {
			reader = bytes.NewReader(data)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
		if err != nil {
			return time.Time{}, fmt.Errorf("build request: %w", err)
		}
		if auth {
			key, err := c.keys.APIKey(ctx)
			if err != nil {
				return time.Time{}, err
			}
			req.Header.Set("Authorization", "Bearer "+key)
		}
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("Accept", "application/json")
		if data != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return time.Time{}, fmt.Errorf("%s %s: %w", method, path, err)
		}
		respData, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if err != nil {
			return time.Time{}, fmt.Errorf("%s %s: read response: %w", method, path, err)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			date, _ := http.ParseTime(resp.Header.Get("Date"))
			if out != nil && len(respData) > 0 {
				if err := json.Unmarshal(respData, out); err != nil {
					return date, fmt.Errorf("%s %s: decode response: %w", method, path, err)
				}
			}
			return date, nil
		}

		apiErr := &APIError{}
		if json.Unmarshal(respData, apiErr) != nil || len(apiErr.RawMessage) == 0 {
			msg, _ := json.Marshal(strings.TrimSpace(string(respData)))
			apiErr.RawMessage = msg
		}
		apiErr.StatusCode = resp.StatusCode

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			msg, _ := json.Marshal(fmt.Sprintf("unexpected redirect to %q; check krakenkey.api_url", resp.Header.Get("Location")))
			apiErr.RawMessage = msg
			return time.Time{}, apiErr
		}

		switch {
		case resp.StatusCode == http.StatusUnauthorized && !auth:
			return time.Time{}, apiErr
		case resp.StatusCode == http.StatusUnauthorized:
			authErr := &AuthError{Message: apiErr.Message()}
			c.authFailed.Store(authErr)
			return time.Time{}, authErr
		case resp.StatusCode == http.StatusNotFound:
			return time.Time{}, &NotFoundError{Message: apiErr.Message()}
		case resp.StatusCode == http.StatusTooManyRequests:
			wait := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
			if attempt >= c.MaxRateLimitRetries || wait > c.MaxRateLimitWait {
				return time.Time{}, &RateLimitError{Message: apiErr.Message(), RetryAfter: wait}
			}
			if err := c.sleep(ctx, wait); err != nil {
				return time.Time{}, err
			}
			continue
		}
		return time.Time{}, apiErr
	}
}

// maxRetryAfter caps what a Retry-After header can ask for.
const maxRetryAfter = 7 * 24 * time.Hour

// parseRetryAfter reads a Retry-After header in seconds or HTTP date form.
// A missing or unreadable value means defaultRetryAfter. The result is at
// least one second, so callers cannot spin, and at most maxRetryAfter.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	d := defaultRetryAfter
	if v != "" {
		if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
			if secs > int64(maxRetryAfter/time.Second) {
				secs = int64(maxRetryAfter / time.Second)
			}
			d = time.Duration(secs) * time.Second
		} else if t, err := http.ParseTime(v); err == nil {
			d = t.Sub(now)
		}
	}
	return min(max(d, time.Second), maxRetryAfter)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// GetCert fetches a certificate record.
func (c *Client) GetCert(ctx context.Context, id int) (*Cert, error) {
	var cert Cert
	if err := c.do(ctx, http.MethodGet, "/certs/tls/"+strconv.Itoa(id), nil, &cert); err != nil {
		return nil, err
	}
	return &cert, nil
}

// RenewCert asks KrakenKey to renew a certificate with a new CSR. The CSR
// must cover the same names as the certificate; its key may be new.
// CertResponse.ServerTime is the API's time of the answer, for
// WaitForIssuance.
func (c *Client) RenewCert(ctx context.Context, id int, csrPEM string) (*CertResponse, error) {
	body := map[string]string{"csrPem": csrPEM}
	var r CertResponse
	date, err := c.sendDated(ctx, http.MethodPost, "/certs/tls/"+strconv.Itoa(id)+"/renew", body, &r, true)
	if err != nil {
		return nil, err
	}
	r.ServerTime = date
	return &r, nil
}

// GetCertChain fetches the chain for an issued certificate.
func (c *Client) GetCertChain(ctx context.Context, id int) (*Chain, error) {
	var ch Chain
	if err := c.do(ctx, http.MethodGet, "/certs/tls/"+strconv.Itoa(id)+"/chain", nil, &ch); err != nil {
		return nil, err
	}
	return &ch, nil
}

// renewalFailureSkew is how far renewalFailedAt may lie before the time a
// renewal was requested and still count as that renewal's failure. It
// covers the Date header's one-second resolution and clock differences
// between the API servers, the proxy in front of them and this host.
const renewalFailureSkew = 2 * time.Minute

// WaitForIssuance polls a certificate until it is issued with a leaf other
// than previousCrt, or fails, or IssuanceTimeout passes. Transient errors
// (network, 5xx) are retried at PollInterval. Client errors (401, 403, 404
// and other 4xx) and rate limits the client did not wait out stop at once.
//
// requestedAt is when the renewal was requested, by the API's clock when
// known (CertResponse.ServerTime). A certificate that is issued with
// previousCrt and a renewalFailedAt from then on means the renewal failed
// and KrakenKey kept the current certificate; that returns a
// *RenewalFailedError at once. A renewalFailedAt from before requestedAt
// belongs to an earlier renewal and is ignored. APIs that don't send
// renewalFailedAt end a failed renewal as failed instead.
func (c *Client) WaitForIssuance(ctx context.Context, id int, previousCrt string, requestedAt time.Time) (*Cert, error) {
	ctx, cancel := context.WithTimeout(ctx, c.IssuanceTimeout)
	defer cancel()

	var lastErr error
	for {
		cert, err := c.GetCert(ctx, id)
		var rl *RateLimitError
		switch {
		case IsClientError(err), errors.As(err, &rl):
			return nil, err
		case err != nil:
			if ctx.Err() != nil {
				return nil, waitErr(id, ctx.Err(), err)
			}
			lastErr = err
		case cert.Status == StatusFailed:
			return nil, &IssuanceFailedError{Reason: cert.FailureReason}
		case cert.Status == StatusIssued && cert.CrtPem != "" && cert.CrtPem != previousCrt:
			return cert, nil
		case cert.Status == StatusIssued && cert.RenewalFailedAt != nil &&
			(requestedAt.IsZero() || !cert.RenewalFailedAt.Before(requestedAt.Add(-renewalFailureSkew))):
			return nil, &RenewalFailedError{Reason: cert.FailureReason, FailedAt: *cert.RenewalFailedAt, ExpiresAt: cert.ExpiresAt}
		case cert.Status == StatusRevoked || cert.Status == StatusRevoking:
			return nil, fmt.Errorf("certificate %d is %s", id, cert.Status)
		}
		if err := c.sleep(ctx, c.PollInterval); err != nil {
			return nil, waitErr(id, err, lastErr)
		}
	}
}

func waitErr(id int, err, last error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		err = errors.New("timed out")
	}
	if last != nil {
		return fmt.Errorf("waiting for certificate %d: %w (last error: %v)", id, err, last)
	}
	return fmt.Errorf("waiting for certificate %d: %w", id, err)
}
