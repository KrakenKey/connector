package api

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// EnrolRequest is the body of POST /connectors/enrol.
type EnrolRequest struct {
	Token     string `json:"token"`
	PublicKey string `json:"publicKey"`
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// EnrolResponse is returned by POST /connectors/enrol.
type EnrolResponse struct {
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

// EnrolmentTokenError means KrakenKey refused the enrolment token: it is
// wrong, expired, already used, or its connector was revoked.
type EnrolmentTokenError struct{ Message string }

func (e *EnrolmentTokenError) Error() string {
	return "KrakenKey refused the enrolment token (401): " + e.Message +
		"; tokens work once and expire after 24 hours, so issue a new one in the dashboard"
}

// ConnectorAuthError means KrakenKey refused the connector's signed
// request: the connector was revoked, its identity is not the one
// KrakenKey knows, or the clocks differ by more than five minutes.
type ConnectorAuthError struct{ Message string }

func (e *ConnectorAuthError) Error() string {
	return "KrakenKey refused the connector's identity (401): " + e.Message +
		"; the connector may have been revoked (enrol it again with a new token), or this machine's clock is off"
}

// Enrol registers the connector's public key with a one-time enrolment
// token. It sends no API key.
func (c *Client) Enrol(ctx context.Context, req EnrolRequest) (*EnrolResponse, error) {
	var r EnrolResponse
	err := c.send(ctx, http.MethodPost, "/connectors/enrol", req, &r, false)
	if e, ok := unauthorized(err); ok {
		return nil, &EnrolmentTokenError{Message: e.Message()}
	}
	if err != nil {
		return nil, err
	}
	if r.ConnectorID == "" {
		return nil, errors.New("POST /connectors/enrol: response has no connectorId")
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

// Deployment states for POST /connectors/report.
const (
	DeployPending               = "pending"
	DeployStaged                = "staged"
	DeployActivated             = "activated"
	DeployVerified              = "verified"
	DeployActivatedUnverifiable = "activated_unverifiable"
	DeployFailed                = "failed"
	DeployRolledBack            = "rolled_back"
)

// Report limits from the API contract.
const (
	MaxReportCertificates = 500
	MaxReportTargets      = 50
	MaxReportError        = 200
	MaxReportSerial       = 64
)

// Report is the body of POST /connectors/report.
type Report struct {
	Version      string              `json:"version"`
	OS           string              `json:"os"`
	Arch         string              `json:"arch"`
	Certificates []ReportCertificate `json:"certificates"`
}

// ReportCertificate is one certificate in a Report. Targets of the
// certificate that a report leaves out are deleted on KrakenKey's side.
type ReportCertificate struct {
	CertificateID int            `json:"certificateId"`
	Targets       []ReportTarget `json:"targets"`
}

// ReportTarget is the state of one target.
type ReportTarget struct {
	Label  string `json:"label"`
	State  string `json:"state"`
	Serial string `json:"serial,omitempty"`
	Error  string `json:"error,omitempty"`
	// UpdatedAt is an ISO 8601 UTC time.
	UpdatedAt string `json:"updatedAt"`
}

// ReportTime formats t for ReportTarget.UpdatedAt.
func ReportTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// Report sends the connector's deployment status. KrakenKey accepts it
// only with a key issued to a connector.
func (c *Client) Report(ctx context.Context, r Report) error {
	return c.do(ctx, http.MethodPost, "/connectors/report", r, nil)
}
