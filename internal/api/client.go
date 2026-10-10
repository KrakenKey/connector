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

// Client calls the KrakenKey API with an API key. It is safe for
// concurrent use.
type Client struct {
	baseURL    string
	apiKey     string
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
	return &Client{
		baseURL:   strings.TrimRight(baseURL, "/"),
		apiKey:    apiKey,
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

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	if prev := c.authFailed.Load(); prev != nil {
		return prev
	}
	var data []byte
	if body != nil {
		var err error
		if data, err = json.Marshal(body); err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
	}

	for attempt := 0; ; attempt++ {
		var reader io.Reader
		if data != nil {
			reader = bytes.NewReader(data)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("User-Agent", c.userAgent)
		req.Header.Set("Accept", "application/json")
		if data != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("%s %s: %w", method, path, err)
		}
		respData, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if err != nil {
			return fmt.Errorf("%s %s: read response: %w", method, path, err)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out != nil && len(respData) > 0 {
				if err := json.Unmarshal(respData, out); err != nil {
					return fmt.Errorf("%s %s: decode response: %w", method, path, err)
				}
			}
			return nil
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
			return apiErr
		}

		switch resp.StatusCode {
		case http.StatusUnauthorized:
			authErr := &AuthError{Message: apiErr.Message()}
			c.authFailed.Store(authErr)
			return authErr
		case http.StatusNotFound:
			return &NotFoundError{Message: apiErr.Message()}
		case http.StatusTooManyRequests:
			wait := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
			if attempt >= c.MaxRateLimitRetries || wait > c.MaxRateLimitWait {
				return &RateLimitError{Message: apiErr.Message(), RetryAfter: wait}
			}
			if err := c.sleep(ctx, wait); err != nil {
				return err
			}
			continue
		}
		return apiErr
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
func (c *Client) RenewCert(ctx context.Context, id int, csrPEM string) (*CertResponse, error) {
	body := map[string]string{"csrPem": csrPEM}
	var r CertResponse
	if err := c.do(ctx, http.MethodPost, "/certs/tls/"+strconv.Itoa(id)+"/renew", body, &r); err != nil {
		return nil, err
	}
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

// WaitForIssuance polls a certificate until it is issued with a leaf other
// than previousCrt, or fails, or IssuanceTimeout passes. Transient errors
// (network, 5xx) are retried at PollInterval. Client errors (401, 403, 404
// and other 4xx) and rate limits the client did not wait out stop at once.
func (c *Client) WaitForIssuance(ctx context.Context, id int, previousCrt string) (*Cert, error) {
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
