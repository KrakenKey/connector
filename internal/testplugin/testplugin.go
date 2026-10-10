// Package testplugin holds small in-memory key store and target
// implementations used to exercise the plugin protocol in tests. They keep
// everything in memory and are not meant for real deployments.
package testplugin

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"

	"github.com/krakenkey/connector/pkg/plugin"
)

// KeyStore is an in-memory key store that creates ECDSA P-256 keys.
type KeyStore struct {
	mu   sync.Mutex
	keys map[string]crypto.Signer
	// Completed records the certificate PEM passed to Complete per key ref.
	Completed map[string]string
	// Released records key refs passed to Release.
	Released []string
}

var _ plugin.KeyStore = (*KeyStore)(nil)

// NewKeyStore returns an empty in-memory key store.
func NewKeyStore() *KeyStore {
	return &KeyStore{keys: map[string]crypto.Signer{}, Completed: map[string]string{}}
}

// Describe reports PEM export of ECDSA P-256 keys.
func (k *KeyStore) Describe(context.Context) (plugin.KeyStoreCapabilities, error) {
	return plugin.KeyStoreCapabilities{
		Provides:   []plugin.KeyFormat{plugin.KeyFormatPEM},
		Exportable: true,
		KeyTypes:   []plugin.KeyType{plugin.KeyTypeECDSAP256},
	}, nil
}

// Validate accepts an empty settings object only.
func (k *KeyStore) Validate(_ context.Context, req plugin.KeyStoreValidateRequest) ([]string, error) {
	if len(req.Config) > 0 && string(req.Config) != "{}" {
		return []string{"the in-memory key store has no settings"}, nil
	}
	return nil, nil
}

// PublicKey returns the key's SubjectPublicKeyInfo.
func (k *KeyStore) PublicKey(_ context.Context, req plugin.PublicKeyRequest) ([]byte, error) {
	k.mu.Lock()
	key, ok := k.keys[req.KeyRef]
	k.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: key %q", plugin.ErrNotFound, req.KeyRef)
	}
	return x509.MarshalPKIXPublicKey(key.Public())
}

// CreateCSR generates a key and CSR.
func (k *KeyStore) CreateCSR(_ context.Context, req plugin.CSRRequest) (plugin.CSR, error) {
	if req.KeyType != plugin.KeyTypeECDSAP256 {
		return plugin.CSR{}, fmt.Errorf("%w: unsupported key type %q", plugin.ErrPermanent, req.KeyType)
	}
	if len(req.Names) == 0 {
		return plugin.CSR{}, fmt.Errorf("%w: no names", plugin.ErrInvalid)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return plugin.CSR{}, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: req.Names[0]},
		DNSNames: req.Names,
	}, key)
	if err != nil {
		return plugin.CSR{}, err
	}
	ref := req.CertificateID + "/" + randomID()
	k.mu.Lock()
	k.keys[ref] = key
	k.mu.Unlock()
	return plugin.CSR{
		PEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})),
		KeyRef: ref,
	}, nil
}

// Complete records the certificate and returns the same ref.
func (k *KeyStore) Complete(_ context.Context, req plugin.CompleteRequest) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.keys[req.KeyRef]; !ok {
		return "", fmt.Errorf("%w: key %q", plugin.ErrNotFound, req.KeyRef)
	}
	k.Completed[req.KeyRef] = req.CertPEM
	return req.KeyRef, nil
}

// Export returns the key as PKCS#8 PEM.
func (k *KeyStore) Export(_ context.Context, req plugin.ExportRequest) (plugin.KeyMaterial, error) {
	if req.Format != plugin.KeyFormatPEM {
		return plugin.KeyMaterial{}, fmt.Errorf("%w: unsupported format %q", plugin.ErrPermanent, req.Format)
	}
	k.mu.Lock()
	key, ok := k.keys[req.KeyRef]
	k.mu.Unlock()
	if !ok {
		return plugin.KeyMaterial{}, fmt.Errorf("%w: key %q", plugin.ErrNotFound, req.KeyRef)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return plugin.KeyMaterial{}, err
	}
	return plugin.KeyMaterial{
		Format: plugin.KeyFormatPEM,
		Data:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
	}, nil
}

// KeyRefs lists the keys held for a certificate.
func (k *KeyStore) KeyRefs(certificateID string) ([]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var refs []string
	for ref := range k.keys {
		if strings.HasPrefix(ref, certificateID+"/") {
			refs = append(refs, ref)
		}
	}
	return refs, nil
}

// Release forgets the key.
func (k *KeyStore) Release(_ context.Context, req plugin.ReleaseRequest) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.keys, req.KeyRef)
	k.Released = append(k.Released, req.KeyRef)
	return nil
}

// TargetConfig is the config the in-memory target accepts.
type TargetConfig struct {
	Name string `json:"name"`
}

// Target is an in-memory target that holds one live certificate.
type Target struct {
	mu     sync.Mutex
	staged map[string]plugin.StageRequest
	live   *plugin.StageRequest
	prev   map[string]*plugin.StageRequest
}

var _ plugin.Target = (*Target)(nil)

// NewTarget returns an empty in-memory target.
func NewTarget() *Target {
	return &Target{staged: map[string]plugin.StageRequest{}, prev: map[string]*plugin.StageRequest{}}
}

// Describe reports a PEM target with rollback.
func (t *Target) Describe(context.Context) (plugin.TargetCapabilities, error) {
	return plugin.TargetCapabilities{
		Accepts:            []plugin.KeyFormat{plugin.KeyFormatPEM},
		NeedsExportableKey: true,
		SupportsRollback:   true,
		KeyTypes:           []plugin.KeyType{plugin.KeyTypeECDSAP256, plugin.KeyTypeRSA2048},
	}, nil
}

// Validate requires a non-empty name.
func (t *Target) Validate(_ context.Context, req plugin.TargetValidateRequest) ([]string, error) {
	var c TargetConfig
	if err := json.Unmarshal(req.Config, &c); err != nil {
		return []string{"config is not a JSON object: " + err.Error()}, nil
	}
	if c.Name == "" {
		return []string{"name is required"}, nil
	}
	return nil, nil
}

// Current returns the live serial.
func (t *Target) Current(context.Context, plugin.CurrentRequest) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.live == nil {
		return "", nil
	}
	return t.live.Serial, nil
}

// Stage keeps the request in memory.
func (t *Target) Stage(_ context.Context, req plugin.StageRequest) (string, error) {
	if req.Key.Format != plugin.KeyFormatPEM || len(req.Key.Data) == 0 {
		return "", fmt.Errorf("%w: PEM key material required", plugin.ErrPermanent)
	}
	ref := randomID()
	t.mu.Lock()
	t.staged[ref] = req
	t.mu.Unlock()
	return ref, nil
}

// Activate makes a staged request live.
func (t *Target) Activate(_ context.Context, r plugin.ActivateRequest) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	req, ok := t.staged[r.StagedRef]
	if !ok {
		return "", fmt.Errorf("%w: staged ref %q", plugin.ErrNotFound, r.StagedRef)
	}
	delete(t.staged, r.StagedRef)
	prevRef := randomID()
	t.prev[prevRef] = t.live
	t.live = &req
	return prevRef, nil
}

// Rollback restores the request live before Activate.
func (t *Target) Rollback(_ context.Context, r plugin.RollbackRequest) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	prev, ok := t.prev[r.PreviousRef]
	if !ok {
		return fmt.Errorf("%w: previous ref %q", plugin.ErrNotFound, r.PreviousRef)
	}
	t.live = prev
	return nil
}

// Discard drops a staged request. Unknown refs are ignored.
func (t *Target) Discard(_ context.Context, r plugin.DiscardRequest) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.staged, r.StagedRef)
	return nil
}

// Staged reports how many staged requests are waiting.
func (t *Target) Staged() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.staged)
}

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
