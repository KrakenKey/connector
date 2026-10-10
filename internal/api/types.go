// Package api is the connector's client for the KrakenKey REST API.
package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Certificate status values.
const (
	StatusPending  = "pending"
	StatusIssuing  = "issuing"
	StatusIssued   = "issued"
	StatusFailed   = "failed"
	StatusRenewing = "renewing"
	StatusRevoking = "revoking"
	StatusRevoked  = "revoked"
)

// FallbackRenewBefore is used to work out when to renew when the API does
// not send renewAfter (older API versions).
const FallbackRenewBefore = 30 * 24 * time.Hour

// Cert is a TLS certificate record from GET /certs/tls/:id.
type Cert struct {
	ID            int        `json:"id"`
	Status        string     `json:"status"`
	CrtPem        string     `json:"crtPem"`
	ChainPem      string     `json:"chainPem"`
	ExpiresAt     *time.Time `json:"expiresAt"`
	RenewAfter    *time.Time `json:"renewAfter"`
	ManagedBy     *string    `json:"managedBy"`
	AutoRenew     bool       `json:"autoRenew"`
	FailureReason string     `json:"failureReason,omitempty"`
}

// RenewAt returns when the certificate should be renewed: renewAfter when
// the API sends it, otherwise 30 days before expiry. ok is false when
// neither is known.
func (c *Cert) RenewAt() (t time.Time, fromAPI bool, ok bool) {
	if c.RenewAfter != nil {
		return *c.RenewAfter, true, true
	}
	if c.ExpiresAt != nil {
		return c.ExpiresAt.Add(-FallbackRenewBefore), false, true
	}
	return time.Time{}, false, false
}

// CertResponse is returned by POST /certs/tls/:id/renew.
type CertResponse struct {
	ID     int    `json:"id"`
	Status string `json:"status"`
}

// Chain is returned by GET /certs/tls/:id/chain.
type Chain struct {
	FullChainPem string `json:"fullChainPem"`
}

// APIError is a non-2xx response that has no more specific type.
type APIError struct {
	StatusCode int             `json:"statusCode"`
	RawMessage json.RawMessage `json:"message"`
	ErrorText  string          `json:"error"`
}

// Message returns the API's message. Validation errors send a list of
// strings; they are joined.
func (e *APIError) Message() string {
	var s string
	if json.Unmarshal(e.RawMessage, &s) == nil {
		return s
	}
	var list []string
	if json.Unmarshal(e.RawMessage, &list) == nil {
		return strings.Join(list, "; ")
	}
	return strings.TrimSpace(string(e.RawMessage))
}

func (e *APIError) Error() string {
	if m := e.Message(); m != "" {
		return fmt.Sprintf("KrakenKey API: %d: %s", e.StatusCode, m)
	}
	return fmt.Sprintf("KrakenKey API: status %d", e.StatusCode)
}

// AuthError is a 401. The connector stops calling the API after one: a
// bad or revoked key would only lock the client out.
type AuthError struct{ Message string }

func (e *AuthError) Error() string {
	return "KrakenKey API rejected the API key (401): " + e.Message + "; check KK_API_KEY"
}

// NotFoundError is a 404.
type NotFoundError struct{ Message string }

func (e *NotFoundError) Error() string { return "KrakenKey API: not found: " + e.Message }

// RateLimitError is a 429 the client did not wait out.
type RateLimitError struct {
	Message    string
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("KrakenKey API rate limit: %s (retry after %s)", e.Message, e.RetryAfter)
}

// IssuanceFailedError means the certificate went to status failed.
type IssuanceFailedError struct{ Reason string }

func (e *IssuanceFailedError) Error() string {
	if e.Reason == "" {
		return "certificate issuance failed"
	}
	return "certificate issuance failed: " + e.Reason
}
