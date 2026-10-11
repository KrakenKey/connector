package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// KeyType is a private key algorithm and size, written the same way as in
// the connector config file.
type KeyType string

// Key types known to the protocol. Each key store and target says which of
// these it supports in its capabilities.
const (
	KeyTypeECDSAP256 KeyType = "ecdsa-p256"
	KeyTypeECDSAP384 KeyType = "ecdsa-p384"
	KeyTypeRSA2048   KeyType = "rsa-2048"
	KeyTypeRSA3072   KeyType = "rsa-3072"
	KeyTypeRSA4096   KeyType = "rsa-4096"
)

// AllKeyTypes lists every key type the protocol knows, in a stable order.
var AllKeyTypes = []KeyType{
	KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096,
}

// ParseKeyType validates s and returns it as a KeyType.
func ParseKeyType(s string) (KeyType, error) {
	k := KeyType(strings.ToLower(strings.TrimSpace(s)))
	for _, known := range AllKeyTypes {
		if k == known {
			return k, nil
		}
	}
	return "", fmt.Errorf("unknown key type %q (want one of %s)", s, joinKeyTypes(AllKeyTypes))
}

// IsRSA reports whether k is an RSA key type.
func (k KeyType) IsRSA() bool { return strings.HasPrefix(string(k), "rsa-") }

// IsECDSA reports whether k is an ECDSA key type.
func (k KeyType) IsECDSA() bool { return strings.HasPrefix(string(k), "ecdsa-") }

// KeyFormat is how key material moves from a key store to a target.
type KeyFormat string

// Key formats known to the protocol.
const (
	// KeyFormatVaultRef is a reference to a key that stays in a vault or HSM.
	KeyFormatVaultRef KeyFormat = "vault_ref"
	// KeyFormatPEM is a PKCS#8 private key in PEM encoding.
	KeyFormatPEM KeyFormat = "pem"
	// KeyFormatPFX is a PKCS#12 bundle with the key and certificate chain.
	KeyFormatPFX KeyFormat = "pfx"
)

// formatPreference is the order in which the core picks a format when a key
// store and a target share more than one. A vault reference keeps the key
// inside the vault, so it comes first.
var formatPreference = []KeyFormat{KeyFormatVaultRef, KeyFormatPEM, KeyFormatPFX}

// KeyStoreCapabilities is what a key store reports from Describe.
type KeyStoreCapabilities struct {
	// Provides lists the formats the key store can hand to a target.
	Provides []KeyFormat
	// Exportable is true when Export can return private key bytes.
	Exportable bool
	// KeyTypes lists the key types CreateCSR accepts.
	KeyTypes []KeyType
	// ImplicitTarget, when set, is the deployment the key store makes by
	// itself in Complete (see ImplicitTarget). It depends on the settings,
	// so the connector reads it only from ValidateCapabilities and ignores
	// it in Describe.
	ImplicitTarget *ImplicitTarget
}

// ImplicitTarget describes a key store whose certificate is itself a
// deployment: Complete puts the issued certificate where services already
// read it (for example a Key Vault certificate that services reference
// without a version). The connector adds a target of the key store's own
// plugin with these settings to every certificate that uses the key store,
// labeled with the plugin's name from the config, unless a configured
// target of that plugin reports the same DeploymentID from Validate; that
// target then takes its place.
//
// The key store's own deployment is matched with MatchKeyStoreDeployment
// instead of Match: it does not need an exportable key, since the
// certificate is already there.
type ImplicitTarget struct {
	// Config is the target's settings, sent as Config in Target calls.
	Config json.RawMessage
	// DeploymentID says where the key store deploys, in the form the
	// plugin's target returns in TargetValidation.DeploymentID. Required.
	DeploymentID string
}

// TargetCapabilities is what a target reports from Describe.
type TargetCapabilities struct {
	// Accepts lists the key formats the target can install.
	Accepts []KeyFormat
	// NeedsExportableKey is true when the target needs a key store that
	// allows export, even if it is handed a vault reference.
	NeedsExportableKey bool
	// SupportsRollback is true when Rollback can restore the previous
	// certificate.
	SupportsRollback bool
	// KeyTypes lists the key types the target can serve. Empty means any.
	KeyTypes []KeyType
	// DefaultVerifyWindow is how long the core keeps checking the endpoint
	// after Activate when the config does not say. Zero means the core
	// default.
	DefaultVerifyWindow time.Duration
	// PropagatesAsync is true for targets that pick up changes on their own
	// schedule. The core reports verification failures for them but does not
	// roll them back.
	PropagatesAsync bool
	// RollbackNeedsMaterial is true when Rollback needs the previous
	// certificate and its private key handed back, because the target
	// cannot keep them itself (for example a cloud service that never
	// returns an imported key). The core then fills the Previous* fields of
	// RollbackRequest when it still holds that material.
	RollbackNeedsMaterial bool
}

// KeyMaterial is a private key, or a reference to one, in a given format.
// Its String, GoString, LogValue and MarshalJSON methods never include Data
// or Password, so passing it to a logger or encoder by mistake does not leak
// the key. Never log the protobuf messages that carry it either.
type KeyMaterial struct {
	Format   KeyFormat
	Data     []byte // PEM or PFX bytes; empty for KeyFormatVaultRef
	Ref      string // vault reference for KeyFormatVaultRef
	Password string // PFX password, if any
}

// String describes the key material without its secret parts.
func (k KeyMaterial) String() string {
	return fmt.Sprintf("KeyMaterial{Format: %s, Ref: %q, Data: %d bytes redacted}", k.Format, k.Ref, len(k.Data))
}

// GoString is the same as String, so %#v does not print the key either.
func (k KeyMaterial) GoString() string { return k.String() }

// LogValue implements slog.LogValuer.
func (k KeyMaterial) LogValue() slog.Value {
	return slog.GroupValue(slog.String("format", string(k.Format)), slog.String("ref", k.Ref))
}

// MarshalJSON writes only the format and reference.
func (k KeyMaterial) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Format KeyFormat `json:"format"`
		Ref    string    `json:"ref,omitempty"`
	}{k.Format, k.Ref})
}

// KeyStoreValidateRequest asks a key store to check its settings.
type KeyStoreValidateRequest struct {
	// Config is the key store's settings from the connector config, as JSON.
	Config        json.RawMessage
	CertificateID string
}

// KeyStoreValidation is a key store's answer to ValidateCapabilities.
type KeyStoreValidation struct {
	// Problems are human readable; empty means the settings are usable.
	Problems []string
	// Capabilities, when set, replace what Describe reports for these
	// settings (for example keys that are exportable or not depending on
	// a setting). Nil means use Describe's.
	Capabilities *KeyStoreCapabilities
}

// KeyStoreCapabilityValidator is implemented by key stores whose
// capabilities depend on their settings. The SDK calls ValidateCapabilities
// instead of Validate when it is implemented, so the connector matches
// targets against the capabilities for each certificate's settings.
type KeyStoreCapabilityValidator interface {
	ValidateCapabilities(ctx context.Context, req KeyStoreValidateRequest) (KeyStoreValidation, error)
}

// ValidateKeyStore validates ks's settings, with per-settings capabilities
// when ks implements KeyStoreCapabilityValidator.
func ValidateKeyStore(ctx context.Context, ks KeyStore, req KeyStoreValidateRequest) (KeyStoreValidation, error) {
	if v, ok := ks.(KeyStoreCapabilityValidator); ok {
		return v.ValidateCapabilities(ctx, req)
	}
	problems, err := ks.Validate(ctx, req)
	return KeyStoreValidation{Problems: problems}, err
}

// CSRRequest asks a key store for a new key and CSR.
type CSRRequest struct {
	Config json.RawMessage
	// CertificateID is the KrakenKey certificate id, for naming keys.
	CertificateID string
	// Names are the DNS names for the CSR. The first is the common name.
	Names   []string
	KeyType KeyType
}

// CSR is a key store's answer to CreateCSR.
type CSR struct {
	// PEM is the PKCS#10 certificate request.
	PEM string
	// KeyRef is an opaque reference to the new key.
	KeyRef string
}

// PublicKeyRequest asks for the public half of a key.
type PublicKeyRequest struct {
	Config json.RawMessage
	KeyRef string
}

// CompleteRequest hands the issued certificate back to the key store.
type CompleteRequest struct {
	Config   json.RawMessage
	KeyRef   string
	CertPEM  string // leaf
	ChainPEM string // intermediates
}

// ExportRequest asks a key store for key material.
type ExportRequest struct {
	Config json.RawMessage
	KeyRef string
	Format KeyFormat
}

// ReleaseRequest tells a key store that a key is no longer in use.
type ReleaseRequest struct {
	Config json.RawMessage
	KeyRef string
}

// KeyStore owns private keys. Implementations must be safe for concurrent
// use. Embed UnimplementedKeyStore to get "not supported" answers for calls
// you do not implement. Return errors wrapping the sentinels in errors.go
// (ErrPermanent, ErrNotFound, ...) so the core can tell what to do next.
type KeyStore interface {
	// Describe reports the key store's capabilities.
	Describe(ctx context.Context) (KeyStoreCapabilities, error)
	// Validate checks the settings without changing anything and returns
	// the problems found. Optional.
	Validate(ctx context.Context, req KeyStoreValidateRequest) ([]string, error)
	// CreateCSR creates a new key and a CSR signed by it.
	CreateCSR(ctx context.Context, req CSRRequest) (CSR, error)
	// PublicKey returns the key's DER encoded SubjectPublicKeyInfo, or an
	// error wrapping ErrNotFound if the key is gone. Optional.
	PublicKey(ctx context.Context, req PublicKeyRequest) ([]byte, error)
	// Complete attaches the issued certificate to the key and returns the
	// key reference to use from now on (often unchanged).
	Complete(ctx context.Context, req CompleteRequest) (string, error)
	// Export returns key material in the requested format. PEM and PFX need
	// an exportable key store; otherwise return an error wrapping
	// ErrPermanent.
	Export(ctx context.Context, req ExportRequest) (KeyMaterial, error)
	// Release tells the key store no target uses the key any more.
	// Releasing an unknown key is not an error.
	Release(ctx context.Context, req ReleaseRequest) error
}

// TargetValidateRequest asks a target to check its settings.
type TargetValidateRequest struct {
	Config        json.RawMessage
	CertificateID string
	Label         string
	// KeyStoreDeploymentID is the DeploymentID of the ImplicitTarget that
	// the certificate's key store reports, set only when the key store is
	// served by the same plugin as this target. A target whose settings
	// have this DeploymentID is the key store's own deployment, and may
	// skip checks the key store already makes.
	KeyStoreDeploymentID string
}

// TargetValidation is a target's answer to ValidateDeployment.
type TargetValidation struct {
	// Problems are human readable; empty means the settings are usable.
	Problems []string
	// DeploymentID is an opaque, stable id of the place the settings
	// deploy to (for example a normalized vault URL and certificate name),
	// or "" when the target does not say. Set it even when there are
	// problems, if the settings say where that is. The connector reports
	// two targets of one certificate with the same plugin and DeploymentID
	// as a problem, and a target with the DeploymentID of the key store's
	// ImplicitTarget replaces that implicit target.
	DeploymentID string
}

// TargetDeploymentValidator is implemented by targets that say where their
// settings deploy to. The SDK calls ValidateDeployment instead of Validate
// when it is implemented.
type TargetDeploymentValidator interface {
	ValidateDeployment(ctx context.Context, req TargetValidateRequest) (TargetValidation, error)
}

// ValidateTarget validates t's settings, with the deployment id when t
// implements TargetDeploymentValidator.
func ValidateTarget(ctx context.Context, t Target, req TargetValidateRequest) (TargetValidation, error) {
	if v, ok := t.(TargetDeploymentValidator); ok {
		return v.ValidateDeployment(ctx, req)
	}
	problems, err := t.Validate(ctx, req)
	return TargetValidation{Problems: problems}, err
}

// CurrentRequest asks a target what it serves now.
type CurrentRequest struct {
	Config        json.RawMessage
	CertificateID string
	Label         string
}

// StageRequest carries an issued certificate to a target.
type StageRequest struct {
	Config        json.RawMessage
	CertificateID string
	// Label is the target's label from the connector config.
	Label        string
	CertPEM      string // leaf
	ChainPEM     string // intermediates
	FullChainPEM string // leaf followed by intermediates
	Key          KeyMaterial
	// Serial is the leaf serial number in lowercase hex.
	Serial string
}

// LogValue implements slog.LogValuer without the certificate or key.
func (r StageRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("certificate_id", r.CertificateID),
		slog.String("label", r.Label),
		slog.String("serial", r.Serial),
		slog.String("key_format", string(r.Key.Format)),
	)
}

// ActivateRequest makes a staged certificate live.
type ActivateRequest struct {
	Config        json.RawMessage
	StagedRef     string
	CertificateID string
	Label         string
}

// RollbackRequest restores what was live before an Activate.
//
// The Previous* fields are set only for targets with
// RollbackNeedsMaterial, and only when the core still holds the
// certificate it last deployed to the target successfully and can export
// its key. A target that needs them and gets none returns an error
// wrapping ErrPermanent. Its String, LogValue and MarshalJSON methods leave
// out the key and the certificates.
type RollbackRequest struct {
	Config        json.RawMessage
	PreviousRef   string
	CertificateID string
	Label         string
	// PreviousCertPEM is the leaf that was live before, PreviousChainPEM
	// its intermediates and PreviousFullChainPEM both.
	PreviousCertPEM      string
	PreviousChainPEM     string
	PreviousFullChainPEM string
	// PreviousKey is the previous leaf's private key, in the same format
	// as StageRequest.Key.
	PreviousKey KeyMaterial
	// PreviousSerial is the previous leaf's serial number in lowercase hex.
	PreviousSerial string
}

// HasPreviousMaterial reports whether the core handed back the previous
// certificate and key.
func (r RollbackRequest) HasPreviousMaterial() bool {
	return r.PreviousCertPEM != "" && (len(r.PreviousKey.Data) > 0 || r.PreviousKey.Ref != "")
}

// rollbackSummary is what String, LogValue and MarshalJSON show.
type rollbackSummary struct {
	PreviousRef       string    `json:"previous_ref"`
	CertificateID     string    `json:"certificate_id"`
	Label             string    `json:"label"`
	PreviousSerial    string    `json:"previous_serial,omitempty"`
	PreviousKeyFormat KeyFormat `json:"previous_key_format,omitempty"`
}

func (r RollbackRequest) summary() rollbackSummary {
	return rollbackSummary{r.PreviousRef, r.CertificateID, r.Label, r.PreviousSerial, r.PreviousKey.Format}
}

// String describes the request without the key or certificates.
func (r RollbackRequest) String() string {
	s := r.summary()
	return fmt.Sprintf("RollbackRequest{PreviousRef: %q, CertificateID: %q, Label: %q, PreviousSerial: %q, PreviousKey: %d bytes redacted}",
		s.PreviousRef, s.CertificateID, s.Label, s.PreviousSerial, len(r.PreviousKey.Data))
}

// GoString is the same as String.
func (r RollbackRequest) GoString() string { return r.String() }

// LogValue implements slog.LogValuer without the key or certificates.
func (r RollbackRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("certificate_id", r.CertificateID),
		slog.String("label", r.Label),
		slog.String("previous_ref", r.PreviousRef),
		slog.String("previous_serial", r.PreviousSerial),
		slog.String("previous_key_format", string(r.PreviousKey.Format)),
	)
}

// MarshalJSON writes the same fields as LogValue.
func (r RollbackRequest) MarshalJSON() ([]byte, error) { return json.Marshal(r.summary()) }

// DiscardRequest drops staged material that will not be activated.
type DiscardRequest struct {
	Config        json.RawMessage
	StagedRef     string
	CertificateID string
	Label         string
}

// Target installs certificates. Implementations must be safe for concurrent
// use. Embed UnimplementedTarget to get "not supported" answers for calls
// you do not implement. The proto file documents each call's contract.
type Target interface {
	// Describe reports the target's capabilities.
	Describe(ctx context.Context) (TargetCapabilities, error)
	// Validate checks config without changing anything and returns the
	// problems found. A nil or empty slice means the config is usable.
	Validate(ctx context.Context, req TargetValidateRequest) ([]string, error)
	// Current returns the serial (lowercase hex) of the certificate the
	// target is set up to serve now, as the target records it, or "" when
	// it cannot tell. Optional.
	Current(ctx context.Context, req CurrentRequest) (string, error)
	// Stage prepares a certificate without making it live and returns an
	// opaque reference for Activate or Discard.
	Stage(ctx context.Context, req StageRequest) (string, error)
	// Activate makes a staged certificate live and returns an opaque
	// reference to what was live before, for Rollback. On error it must
	// leave the previous state in place.
	Activate(ctx context.Context, req ActivateRequest) (string, error)
	// Rollback restores exactly what was live before the Activate that
	// returned the previous ref, removing what it installed if nothing was
	// there before. If it cannot, return an error wrapping ErrPermanent.
	Rollback(ctx context.Context, req RollbackRequest) error
	// Discard deletes staged material. It must be idempotent. Optional.
	Discard(ctx context.Context, req DiscardRequest) error
}

func joinKeyTypes(ks []KeyType) string {
	s := make([]string, len(ks))
	for i, k := range ks {
		s[i] = string(k)
	}
	return strings.Join(s, ", ")
}

func joinFormats(fs []KeyFormat) string {
	if len(fs) == 0 {
		return "none"
	}
	s := make([]string, len(fs))
	for i, f := range fs {
		s[i] = string(f)
	}
	return strings.Join(s, ", ")
}
