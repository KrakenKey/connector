// Package api is the connector's client for the KrakenKey REST API.
package api

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	// StatusAwaitingCSR is a certificate created in KrakenKey with names
	// only, waiting for a connector to send the first CSR through renew.
	StatusAwaitingCSR = "awaiting_csr"
)

// FallbackRenewBefore is used to work out when to renew when the API does
// not send renewAfter and the leaf cannot be parsed.
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
	// RequestedNames are the names of an awaiting_csr certificate; the
	// first CSR must cover exactly these.
	RequestedNames []string `json:"requestedNames"`
}

// Renewal time sources reported by RenewAt.
const (
	RenewSourceAPI      = "renewAfter from the API"
	RenewSourceLifetime = "two thirds of the certificate lifetime (the API sent no renewAfter)"
	RenewSourceExpiry   = "30 days before expiry (the API sent no renewAfter)"
)

// RenewAt returns when the certificate should be renewed and where that
// time came from: renewAfter when the API sends it; otherwise two thirds of
// the way from the leaf's notBefore to its notAfter; otherwise 30 days
// before expiresAt. ok is false when none of these is known.
func (c *Cert) RenewAt() (t time.Time, source string, ok bool) {
	if c.RenewAfter != nil {
		return *c.RenewAfter, RenewSourceAPI, true
	}
	if leaf, err := parseLeaf(c.CrtPem); err == nil && leaf.NotAfter.After(leaf.NotBefore) {
		life := leaf.NotAfter.Sub(leaf.NotBefore)
		return leaf.NotBefore.Add(life * 2 / 3), RenewSourceLifetime, true
	}
	if c.ExpiresAt != nil {
		return c.ExpiresAt.Add(-FallbackRenewBefore), RenewSourceExpiry, true
	}
	return time.Time{}, "", false
}

func parseLeaf(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no certificate")
	}
	return x509.ParseCertificate(block.Bytes)
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
	return "KrakenKey API rejected the API key (401): " + e.Message
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

// IsClientError reports whether err is a 4xx answer other than 429: the
// request will not succeed by repeating it.
func IsClientError(err error) bool {
	var nf *NotFoundError
	var auth *AuthError
	var connAuth *ConnectorAuthError
	var apiErr *APIError
	switch {
	case errors.As(err, &nf), errors.As(err, &auth), errors.As(err, &connAuth):
		return true
	case errors.As(err, &apiErr):
		return apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 && apiErr.StatusCode != 429
	}
	return false
}

// IssuanceFailedError means the certificate went to status failed.
type IssuanceFailedError struct{ Reason string }

func (e *IssuanceFailedError) Error() string {
	if e.Reason == "" {
		return "certificate issuance failed"
	}
	return "certificate issuance failed: " + e.Reason
}
