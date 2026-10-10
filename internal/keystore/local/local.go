// Package local is the built-in key store. It generates keys in process
// and keeps them as PEM files under the connector's data directory.
//
// Layout:
//
//	<data_dir>/                      0700
//	<data_dir>/keys/                 0700
//	<data_dir>/keys/<cert id>/       0700
//	<data_dir>/keys/<cert id>/<key id>.key   0600  PKCS#8 private key
//	<data_dir>/keys/<cert id>/<key id>.crt   0600  issued leaf + chain
//
// Keys stay on disk until the core releases them, which it does only after
// the certificate for a newer key is live and verified on every target.
package local

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/krakenkey/connector/internal/certutil"
	"github.com/krakenkey/connector/pkg/plugin"
)

// ErrInsecurePermissions means a directory or key file is accessible to
// users other than the owner.
var ErrInsecurePermissions = errors.New("insecure permissions")

// SupportedKeyTypes are the key types this key store creates.
var SupportedKeyTypes = []plugin.KeyType{
	plugin.KeyTypeECDSAP256, plugin.KeyTypeECDSAP384, plugin.KeyTypeRSA2048, plugin.KeyTypeRSA3072,
}

var (
	certIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	keyIDRe  = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`)
)

// Store is the local key store.
type Store struct {
	dir string // <data_dir>/keys
	now func() time.Time
}

var _ plugin.KeyStore = (*Store)(nil)

// Open prepares the key directory under dataDir, creating it with mode
// 0700 when missing, and refuses to continue if dataDir, any directory
// below keys/, or any key file is readable or writable by group or others.
func Open(dataDir string) (*Store, error) {
	if err := ensureDir(dataDir); err != nil {
		return nil, err
	}
	dir := filepath.Join(dataDir, "keys")
	if err := ensureDir(dir); err != nil {
		return nil, err
	}
	if err := checkTree(dir); err != nil {
		return nil, err
	}
	return &Store{dir: dir, now: time.Now}, nil
}

func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	return checkPerm(dir)
}

func checkPerm(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", ErrInsecurePermissions, path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		want := "600"
		if info.IsDir() {
			want = "700"
		}
		return fmt.Errorf("%w: %s has mode %04o; run: chmod %s %s", ErrInsecurePermissions, path, perm, want, path)
	}
	return nil
}

func checkTree(root string) error {
	return filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return checkPerm(path)
	})
}

// Describe reports PEM keys that can be exported.
func (s *Store) Describe(context.Context) (plugin.KeyStoreCapabilities, error) {
	return plugin.KeyStoreCapabilities{
		Provides:   []plugin.KeyFormat{plugin.KeyFormatPEM},
		Exportable: true,
		KeyTypes:   SupportedKeyTypes,
	}, nil
}

// CreateCSR generates a key, stores it, and returns a CSR for names.
func (s *Store) CreateCSR(_ context.Context, req plugin.CSRRequest) (plugin.CSR, error) {
	if err := noSettings(req.Config); err != nil {
		return plugin.CSR{}, err
	}
	if !certIDRe.MatchString(req.CertificateID) {
		return plugin.CSR{}, fmt.Errorf("invalid certificate id %q", req.CertificateID)
	}
	if len(req.Names) == 0 {
		return plugin.CSR{}, errors.New("no names for the CSR")
	}
	key, err := generate(req.KeyType)
	if err != nil {
		return plugin.CSR{}, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: req.Names[0]},
		DNSNames: req.Names,
	}, key)
	if err != nil {
		return plugin.CSR{}, fmt.Errorf("create CSR: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return plugin.CSR{}, fmt.Errorf("encode key: %w", err)
	}

	certDir := filepath.Join(s.dir, req.CertificateID)
	if err := ensureDir(certDir); err != nil {
		return plugin.CSR{}, err
	}
	keyID := s.now().UTC().Format("20060102T150405Z") + "-" + randomHex(4)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeFile(filepath.Join(certDir, keyID+".key"), keyPEM); err != nil {
		return plugin.CSR{}, err
	}
	return plugin.CSR{
		PEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		KeyRef: req.CertificateID + "/" + keyID,
	}, nil
}

// Complete stores the issued certificate next to its key, after checking
// that the certificate is for that key.
func (s *Store) Complete(_ context.Context, req plugin.CompleteRequest) (string, error) {
	keyPath, err := s.path(req.KeyRef, ".key")
	if err != nil {
		return "", err
	}
	key, err := readKey(keyPath)
	if err != nil {
		return "", err
	}
	leaf, err := certutil.ParseLeaf(req.CertPEM)
	if err != nil {
		return "", err
	}
	if !certutil.SamePublicKey(key.Public(), leaf.PublicKey) {
		return "", errors.New("certificate does not match the stored key")
	}
	crtPath := strings.TrimSuffix(keyPath, ".key") + ".crt"
	if err := writeFile(crtPath, []byte(strings.TrimSpace(req.CertPEM)+"\n"+strings.TrimSpace(req.ChainPEM)+"\n")); err != nil {
		return "", err
	}
	return req.KeyRef, nil
}

// Export returns the key as PKCS#8 PEM. PFX is not supported.
func (s *Store) Export(_ context.Context, req plugin.ExportRequest) (plugin.KeyMaterial, error) {
	if req.Format != plugin.KeyFormatPEM {
		return plugin.KeyMaterial{}, fmt.Errorf("local key store exports only pem, not %q", req.Format)
	}
	keyPath, err := s.path(req.KeyRef, ".key")
	if err != nil {
		return plugin.KeyMaterial{}, err
	}
	if err := checkPerm(keyPath); err != nil {
		return plugin.KeyMaterial{}, err
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return plugin.KeyMaterial{}, fmt.Errorf("read key %s: %w", req.KeyRef, err)
	}
	return plugin.KeyMaterial{Format: plugin.KeyFormatPEM, Data: data}, nil
}

// Release deletes the key and its certificate.
func (s *Store) Release(_ context.Context, req plugin.ReleaseRequest) error {
	keyPath, err := s.path(req.KeyRef, ".key")
	if err != nil {
		return err
	}
	for _, p := range []string{keyPath, strings.TrimSuffix(keyPath, ".key") + ".crt"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("release key %s: %w", req.KeyRef, err)
		}
	}
	return nil
}

// path maps a key ref to a file, rejecting anything that is not a ref this
// store created.
func (s *Store) path(ref, ext string) (string, error) {
	certID, keyID, ok := strings.Cut(ref, "/")
	if !ok || !certIDRe.MatchString(certID) || !keyIDRe.MatchString(keyID) {
		return "", fmt.Errorf("invalid key ref %q", ref)
	}
	return filepath.Join(s.dir, certID, keyID+ext), nil
}

func noSettings(cfg json.RawMessage) error {
	if len(cfg) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(cfg, &m); err != nil {
		return fmt.Errorf("key store settings: %w", err)
	}
	for k := range m {
		return fmt.Errorf("local key store has no setting %q", k)
	}
	return nil
}

func generate(kt plugin.KeyType) (crypto.Signer, error) {
	switch kt {
	case plugin.KeyTypeECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case plugin.KeyTypeECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case plugin.KeyTypeRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case plugin.KeyTypeRSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	}
	return nil, fmt.Errorf("local key store cannot create %q keys", kt)
}

func readKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("key file %s is not PEM", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key %s: %w", path, err)
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key %s cannot sign", path)
	}
	return signer, nil
}

// writeFile writes data to path with mode 0600 through a temp file and
// rename, so a crash never leaves a half-written key.
func writeFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
