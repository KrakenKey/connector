package api

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// EnrollRequest is the body of POST /connectors/enroll.
type EnrollRequest struct {
	Token     string `json:"token"`
	PublicKey string `json:"publicKey"`
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// EnrollResponse is returned by POST /connectors/enroll.
type EnrollResponse struct {
	ConnectorID string `json:"connectorId"`
	Name        string `json:"name"`
}

// ConnectorTokenRequest is the body of POST /connectors/token.
type ConnectorTokenRequest struct {
	ConnectorID string `json:"connectorId"`
	Timestamp   string `json:"timestamp"`
	Nonce       string `json:"nonce"`
	Signature   string `json:"signature"`
}

// ConnectorToken is returned by POST /connectors/token: a short-lived API
// key for the connector.
type ConnectorToken struct {
	APIKey    string    `json:"apiKey"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// RotateRequest is the body of POST /connectors/rotate.
type RotateRequest struct {
	ConnectorID  string `json:"connectorId"`
	NewPublicKey string `json:"newPublicKey"`
	Timestamp    string `json:"timestamp"`
	Nonce        string `json:"nonce"`
	Signature    string `json:"signature"`
}

// EnrollmentTokenError means KrakenKey refused the enrollment token: it is
// wrong, expired, already used, or its connector was revoked.
type EnrollmentTokenError struct{ Message string }

func (e *EnrollmentTokenError) Error() string {
	return "KrakenKey refused the enrollment token (401): " + e.Message +
		"; tokens work once and expire after 24 hours, so issue a new one in the dashboard"
}

// ConnectorAuthError means KrakenKey refused the connector's signed
// request: the connector was revoked, its identity is not the one
// KrakenKey knows, or the clocks differ by more than five minutes.
type ConnectorAuthError struct{ Message string }

func (e *ConnectorAuthError) Error() string {
	return "KrakenKey refused the connector's identity (401): " + e.Message +
		"; the connector may have been revoked (enroll it again with a new token), or this machine's clock is off"
}

// Enroll registers the connector's public key with a one-time enrollment
// token. It sends no API key.
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error) {
	var r EnrollResponse
	err := c.send(ctx, http.MethodPost, "/connectors/enroll", req, &r, false)
	if e, ok := unauthorized(err); ok {
		return nil, &EnrollmentTokenError{Message: e.Message()}
	}
	if err != nil {
		return nil, err
	}
	if r.ConnectorID == "" {
		return nil, errors.New("POST /connectors/enroll: response has no connectorId")
	}
	return &r, nil
}

// ConnectorToken exchanges a signed assertion for a short-lived API key. It
// sends no API key.
func (c *Client) ConnectorToken(ctx context.Context, req ConnectorTokenRequest) (*ConnectorToken, error) {
	var r ConnectorToken
	err := c.send(ctx, http.MethodPost, "/connectors/token", req, &r, false)
	if e, ok := unauthorized(err); ok {
		return nil, &ConnectorAuthError{Message: e.Message()}
	}
	if err != nil {
		return nil, err
	}
	if r.APIKey == "" || r.ExpiresAt.IsZero() {
		return nil, errors.New("POST /connectors/token: response has no apiKey or expiresAt")
	}
	return &r, nil
}

// RotateIdentity replaces the connector's public key. The request is
// signed with the current key. It sends no API key.
func (c *Client) RotateIdentity(ctx context.Context, req RotateRequest) error {
	err := c.send(ctx, http.MethodPost, "/connectors/rotate", req, nil, false)
	if e, ok := unauthorized(err); ok {
		return &ConnectorAuthError{Message: e.Message()}
	}
	return err
}

func unauthorized(err error) (*APIError, bool) {
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized {
		return apiErr, true
	}
	return nil, false
}
