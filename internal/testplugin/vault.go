package testplugin

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/krakenkey/connector/pkg/plugin"
)

// Vault is an in-memory key store whose certificates are themselves
// deployments, like a cloud vault that services read without naming a
// version: Complete adds a version, and the latest version is what those
// services use. It reports an implicit target (plugin.ImplicitTarget), and
// VaultTarget serves that target over the same versions. Settings for both
// are {"vault": "<name>"}; the key store and target share one Vault per
// name.
type Vault struct {
	*KeyStore

	// Exportable is reported in the capabilities for every setting.
	Exportable bool

	mu       sync.Mutex
	versions map[string][]VaultVersion // by vault name
	staged   map[string]stagedVersion
}

// VaultVersion is one certificate version in a vault.
type VaultVersion struct {
	Serial  string
	CertPEM string
	// FullChainPEM is the leaf followed by its intermediates.
	FullChainPEM string
	Key          crypto.Signer
}

type stagedVersion struct {
	vault   string
	serial  string
	inPlace bool
	version VaultVersion
}

type vaultSettings struct {
	Vault string `json:"vault"`
}

// NewVault returns an empty vault with exportable keys.
func NewVault() *Vault {
	return &Vault{KeyStore: NewKeyStore(), Exportable: true, versions: map[string][]VaultVersion{}, staged: map[string]stagedVersion{}}
}

func parseVaultSettings(raw json.RawMessage) (vaultSettings, error) {
	var s vaultSettings
	if err := json.Unmarshal(raw, &s); err != nil || s.Vault == "" {
		return s, fmt.Errorf("%w: settings need a vault name", plugin.ErrPermanent)
	}
	s.Vault = strings.ToLower(s.Vault)
	return s, nil
}

// VaultDeploymentID is the deployment id for a vault name.
func VaultDeploymentID(name string) string { return "vault:" + strings.ToLower(name) }

// Describe reports vault references and PEM export.
func (v *Vault) Describe(context.Context) (plugin.KeyStoreCapabilities, error) {
	return plugin.KeyStoreCapabilities{
		Provides:   []plugin.KeyFormat{plugin.KeyFormatVaultRef, plugin.KeyFormatPEM},
		Exportable: v.Exportable,
		KeyTypes:   []plugin.KeyType{plugin.KeyTypeECDSAP256},
	}, nil
}

// Validate checks the settings.
func (v *Vault) Validate(ctx context.Context, req plugin.KeyStoreValidateRequest) ([]string, error) {
	r, err := v.ValidateCapabilities(ctx, req)
	return r.Problems, err
}

// ValidateCapabilities reports the implicit target for the vault.
func (v *Vault) ValidateCapabilities(ctx context.Context, req plugin.KeyStoreValidateRequest) (plugin.KeyStoreValidation, error) {
	s, err := parseVaultSettings(req.Config)
	if err != nil {
		return plugin.KeyStoreValidation{Problems: []string{err.Error()}}, nil
	}
	caps, _ := v.Describe(ctx)
	cfg, _ := json.Marshal(vaultSettings{Vault: s.Vault})
	caps.ImplicitTarget = &plugin.ImplicitTarget{Config: cfg, DeploymentID: VaultDeploymentID(s.Vault)}
	return plugin.KeyStoreValidation{Capabilities: &caps}, nil
}

// Complete adds the certificate as the vault's latest version.
func (v *Vault) Complete(ctx context.Context, req plugin.CompleteRequest) (string, error) {
	s, err := parseVaultSettings(req.Config)
	if err != nil {
		return "", err
	}
	ref, err := v.KeyStore.Complete(ctx, req)
	if err != nil {
		return "", err
	}
	v.KeyStore.mu.Lock()
	key := v.keys[ref]
	v.KeyStore.mu.Unlock()
	leaf, err := parseLeaf(req.CertPEM)
	if err != nil {
		return "", err
	}
	v.add(s.Vault, VaultVersion{Serial: leaf, CertPEM: req.CertPEM, FullChainPEM: strings.TrimSpace(req.CertPEM) + "\n" + req.ChainPEM, Key: key})
	return ref, nil
}

// Export returns a vault reference, or the key as PEM when exportable.
func (v *Vault) Export(ctx context.Context, req plugin.ExportRequest) (plugin.KeyMaterial, error) {
	switch req.Format {
	case plugin.KeyFormatVaultRef:
		return plugin.KeyMaterial{Format: plugin.KeyFormatVaultRef, Ref: "vault-key:" + req.KeyRef}, nil
	case plugin.KeyFormatPEM:
		if !v.Exportable {
			return plugin.KeyMaterial{}, fmt.Errorf("%w: key not exportable", plugin.ErrPermanent)
		}
		return v.KeyStore.Export(ctx, req)
	}
	return plugin.KeyMaterial{}, fmt.Errorf("%w: unsupported format %q", plugin.ErrPermanent, req.Format)
}

func (v *Vault) add(name string, ver VaultVersion) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.versions[name] = append(v.versions[name], ver)
}

// Versions returns the versions of a vault, oldest first.
func (v *Vault) Versions(name string) []VaultVersion {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]VaultVersion(nil), v.versions[name]...)
}

// Latest returns the serial of a vault's latest version, or "".
func (v *Vault) Latest(name string) string {
	vs := v.Versions(name)
	if len(vs) == 0 {
		return ""
	}
	return vs[len(vs)-1].Serial
}

// GetCertificate serves the latest version of a vault over TLS, like a
// service that reads the vault without naming a version.
func (v *Vault) GetCertificate(name string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		vs := v.Versions(name)
		if len(vs) == 0 {
			return nil, errors.New("vault is empty")
		}
		latest := vs[len(vs)-1]
		var c tls.Certificate
		rest := []byte(latest.FullChainPEM)
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			c.Certificate = append(c.Certificate, b.Bytes)
		}
		c.PrivateKey = latest.Key
		return &c, nil
	}
}

// Target returns the target side of the vault.
func (v *Vault) Target() *VaultTarget { return &VaultTarget{v: v} }

// VaultTarget deploys certificates as new versions of a Vault. It accepts
// vault references to the Vault's own keys and PEM keys, needs the
// previous material to roll back, and reports where it deploys.
type VaultTarget struct {
	v *Vault
	// ValidateRequests records every validate request.
	ValidateRequests []plugin.TargetValidateRequest
	mu               sync.Mutex
}

var (
	_ plugin.Target                    = (*VaultTarget)(nil)
	_ plugin.TargetDeploymentValidator = (*VaultTarget)(nil)
)

// Describe reports the capabilities.
func (t *VaultTarget) Describe(context.Context) (plugin.TargetCapabilities, error) {
	return plugin.TargetCapabilities{
		Accepts:               []plugin.KeyFormat{plugin.KeyFormatVaultRef, plugin.KeyFormatPEM},
		NeedsExportableKey:    true,
		SupportsRollback:      true,
		RollbackNeedsMaterial: true,
	}, nil
}

// Validate checks the settings.
func (t *VaultTarget) Validate(ctx context.Context, req plugin.TargetValidateRequest) ([]string, error) {
	v, err := t.ValidateDeployment(ctx, req)
	return v.Problems, err
}

// ValidateDeployment checks the settings and reports the deployment id.
func (t *VaultTarget) ValidateDeployment(_ context.Context, req plugin.TargetValidateRequest) (plugin.TargetValidation, error) {
	t.mu.Lock()
	t.ValidateRequests = append(t.ValidateRequests, req)
	t.mu.Unlock()
	s, err := parseVaultSettings(req.Config)
	if err != nil {
		return plugin.TargetValidation{Problems: []string{err.Error()}}, nil
	}
	return plugin.TargetValidation{DeploymentID: VaultDeploymentID(s.Vault)}, nil
}

// Current returns the latest version's serial.
func (t *VaultTarget) Current(_ context.Context, req plugin.CurrentRequest) (string, error) {
	s, err := parseVaultSettings(req.Config)
	if err != nil {
		return "", err
	}
	return t.v.Latest(s.Vault), nil
}

// Stage finds the certificate in place, or prepares a new version from
// the key material.
func (t *VaultTarget) Stage(_ context.Context, req plugin.StageRequest) (string, error) {
	s, err := parseVaultSettings(req.Config)
	if err != nil {
		return "", err
	}
	sv := stagedVersion{vault: s.Vault, serial: req.Serial}
	if t.v.Latest(s.Vault) == req.Serial {
		sv.inPlace = true
	} else {
		key, err := t.key(req.Key)
		if err != nil {
			return "", err
		}
		sv.version = VaultVersion{Serial: req.Serial, CertPEM: req.CertPEM, FullChainPEM: req.FullChainPEM, Key: key}
	}
	ref := randomID()
	t.v.mu.Lock()
	t.v.staged[ref] = sv
	t.v.mu.Unlock()
	return ref, nil
}

// key resolves key material: a reference to a key of the Vault, or PEM.
func (t *VaultTarget) key(k plugin.KeyMaterial) (crypto.Signer, error) {
	switch k.Format {
	case plugin.KeyFormatVaultRef:
		if !t.v.Exportable {
			return nil, fmt.Errorf("%w: the vault's key is not exportable", plugin.ErrPermanent)
		}
		t.v.KeyStore.mu.Lock()
		key, ok := t.v.keys[strings.TrimPrefix(k.Ref, "vault-key:")]
		t.v.KeyStore.mu.Unlock()
		if !ok {
			return nil, fmt.Errorf("%w: unknown key %q", plugin.ErrNotFound, k.Ref)
		}
		return key, nil
	case plugin.KeyFormatPEM:
		b, _ := pem.Decode(k.Data)
		if b == nil {
			return nil, fmt.Errorf("%w: no PEM key", plugin.ErrInvalid)
		}
		key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", plugin.ErrInvalid, err)
		}
		return key.(crypto.Signer), nil
	}
	return nil, fmt.Errorf("%w: the key is needed to add a version (got %q)", plugin.ErrPermanent, k.Format)
}

// Activate adds the staged version, or, for a certificate already in
// place, records the version before it as the previous state.
func (t *VaultTarget) Activate(_ context.Context, req plugin.ActivateRequest) (string, error) {
	t.v.mu.Lock()
	sv, ok := t.v.staged[req.StagedRef]
	delete(t.v.staged, req.StagedRef)
	t.v.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("%w: staged ref %q", plugin.ErrNotFound, req.StagedRef)
	}
	vs := t.v.Versions(sv.vault)
	if sv.inPlace {
		for i := len(vs) - 1; i > 0; i-- {
			if vs[i].Serial == sv.serial {
				return "serial:" + vs[i-1].Serial, nil
			}
		}
		return "", nil
	}
	prev := ""
	if len(vs) > 0 {
		prev = "serial:" + vs[len(vs)-1].Serial
	}
	t.v.add(sv.vault, sv.version)
	return prev, nil
}

// Rollback adds the previous certificate again as the latest version.
func (t *VaultTarget) Rollback(_ context.Context, req plugin.RollbackRequest) error {
	s, err := parseVaultSettings(req.Config)
	if err != nil {
		return err
	}
	prev, ok := strings.CutPrefix(req.PreviousRef, "serial:")
	if !ok || prev == "" {
		return fmt.Errorf("%w: no previous version", plugin.ErrPermanent)
	}
	if t.v.Latest(s.Vault) == prev {
		return nil
	}
	if !req.HasPreviousMaterial() {
		return fmt.Errorf("%w: no previous certificate and key", plugin.ErrPermanent)
	}
	if req.PreviousSerial != prev {
		return fmt.Errorf("%w: material for %s, but %s was live", plugin.ErrPermanent, req.PreviousSerial, prev)
	}
	key, err := t.key(req.PreviousKey)
	if err != nil {
		return err
	}
	t.v.add(s.Vault, VaultVersion{Serial: prev, CertPEM: req.PreviousCertPEM, FullChainPEM: req.PreviousFullChainPEM, Key: key})
	return nil
}

// Discard drops a staged version.
func (t *VaultTarget) Discard(_ context.Context, req plugin.DiscardRequest) error {
	t.v.mu.Lock()
	delete(t.v.staged, req.StagedRef)
	t.v.mu.Unlock()
	return nil
}

func parseLeaf(certPEM string) (string, error) {
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil {
		return "", fmt.Errorf("%w: no certificate", plugin.ErrInvalid)
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return "", fmt.Errorf("%w: %v", plugin.ErrInvalid, err)
	}
	return fmt.Sprintf("%x", c.SerialNumber), nil
}
