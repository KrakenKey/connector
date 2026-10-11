package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// ReportResult is KrakenKey's answer to a report. Certificates the
// connector may not manage are skipped and listed in
// RejectedCertificateIDs; the rest are stored.
type ReportResult struct {
	Accepted               int   `json:"accepted"`
	RejectedCertificateIDs []int `json:"rejectedCertificateIds"`
}

// Report sends the connector's deployment status. KrakenKey accepts it
// only with a key issued to a connector. Any 2xx is success; an empty
// answer (204) gives an empty result.
func (c *Client) Report(ctx context.Context, r Report) (*ReportResult, error) {
	var res ReportResult
	if err := c.do(ctx, http.MethodPost, "/connectors/report", r, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Config summary limits from the API contract. Certificates and targets
// per certificate share the report's limits.
const (
	MaxConfigPlugins       = 50
	MaxConfigNames         = 100
	MaxConfigSettings      = 10
	MaxConfigSettingValue  = 256
	MaxConfigVersion       = 64
	MaxConfigKeyType       = 32
	MaxConfigCheckInterval = 7 * 24 * 60 * 60 // seconds
)

// Plugin sources in a config summary.
const (
	PluginSourceBundled = "bundled"
	PluginSourceDataDir = "data_dir"
	PluginSourcePath    = "path"
	PluginSourceBuiltin = "builtin"
)

// ConfigSummary is a read-only summary of the connector's config for the
// dashboard. It holds only allowlisted settings: no commands, file
// owners, tags, cloud account ids or secrets. Its JSON encoding, with
// settings keys sorted as encoding/json does, is what ConfigSummaryHash
// hashes, so the field order is part of the contract.
type ConfigSummary struct {
	Version              string              `json:"version"`
	CheckIntervalSeconds *int                `json:"checkIntervalSeconds"`
	Plugins              []ConfigPlugin      `json:"plugins"`
	Certificates         []ConfigCertificate `json:"certificates"`
	Truncated            bool                `json:"truncated"`
}

// ConfigPlugin is one plugin in a ConfigSummary.
type ConfigPlugin struct {
	Name string `json:"name"`
	// Version is null for plugins run from a path setting.
	Version *string `json:"version"`
	// Source is one of the PluginSource constants.
	Source string `json:"source"`
}

// ConfigCertificate is one certificate in a ConfigSummary.
type ConfigCertificate struct {
	CertificateID int            `json:"certificateId"`
	Names         []string       `json:"names"`
	KeyStore      ConfigKeyStore `json:"keyStore"`
	Targets       []ConfigTarget `json:"targets"`
}

// ConfigKeyStore is a certificate's key store in a ConfigSummary.
type ConfigKeyStore struct {
	Plugin   string         `json:"plugin"`
	KeyType  *string        `json:"keyType"`
	Settings map[string]any `json:"settings"`
}

// ConfigTarget is one target in a ConfigSummary.
type ConfigTarget struct {
	Label  string `json:"label"`
	Plugin string `json:"plugin"`
	// Implicit is true for the target the key store added by itself.
	Implicit bool `json:"implicit"`
	// RunsCommand is true for exec targets and targets with then.
	RunsCommand bool           `json:"runsCommand"`
	Verify      *ConfigVerify  `json:"verify"`
	Settings    map[string]any `json:"settings"`
}

// ConfigVerify is a target's verify block in a ConfigSummary, without
// address and ca_file.
type ConfigVerify struct {
	Host                *string `json:"host"`
	Port                *int    `json:"port"`
	SkipChainValidation bool    `json:"skipChainValidation"`
}

// ConfigSummaryHash returns the lowercase hex sha256 of the summary's
// canonical JSON encoding.
func ConfigSummaryHash(s ConfigSummary) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("encode config summary: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// configSummaryBody is the body of PUT /connectors/config: the hash, then
// the summary's fields.
type configSummaryBody struct {
	Hash string `json:"hash"`
	ConfigSummary
}

// PutConfigSummary stores the connector's config summary with KrakenKey.
// hash is ConfigSummaryHash(s). KrakenKey accepts it only with a key
// issued to a connector; KrakenKey versions without the route answer 404
// or 405 (see IsMissingRoute).
func (c *Client) PutConfigSummary(ctx context.Context, hash string, s ConfigSummary) error {
	return c.do(ctx, http.MethodPut, "/connectors/config", configSummaryBody{Hash: hash, ConfigSummary: s}, nil)
}

// DeleteConfigSummary clears the config summary KrakenKey stored for the
// connector, if any.
func (c *Client) DeleteConfigSummary(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "/connectors/config", nil, nil)
}

// IsMissingRoute reports whether err is a 404 or 405: the KrakenKey
// version does not have the route.
func IsMissingRoute(err error) bool {
	var nf *NotFoundError
	var apiErr *APIError
	switch {
	case errors.As(err, &nf):
		return true
	case errors.As(err, &apiErr):
		return apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusMethodNotAllowed
	}
	return false
}
