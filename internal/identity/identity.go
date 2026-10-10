// Package identity holds the connector's enrolled identity: an Ed25519 key
// pair whose public half KrakenKey stores at enrolment, and the connector
// id it was given. The connector proves it holds the private key to get
// short-lived API keys, so no long-lived API key has to live on the
// machine.
//
// Files, under <data_dir>/identity (mode 0700):
//
//	identity.key       the private key, PKCS#8 PEM, mode 0600
//	connector.json     the connector id and name, mode 0600
//	identity.key.next  a new key during a rotation, until KrakenKey accepts it
//
// Private keys are never logged.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/krakenkey/connector/internal/securefs"
)

// File and directory names.
const (
	DirName     = "identity"
	KeyFile     = "identity.key"
	NextKeyFile = "identity.key.next"
	MetaFile    = "connector.json"
	// newKeyFile holds the key of an enrolment in progress.
	newKeyFile = "identity.key.new"
)

// Signed message prefixes.
const (
	TokenMessageV1  = "KRAKENKEY-CONNECTOR-TOKEN-V1"
	RotateMessageV1 = "KRAKENKEY-CONNECTOR-ROTATE-V1"
)

// ErrAlreadyEnrolled means an identity exists and enrol was not forced.
var ErrAlreadyEnrolled = errors.New("this connector is already enrolled")

// Meta is what connector.json holds.
type Meta struct {
	ConnectorID string    `json:"connector_id"`
	Name        string    `json:"name"`
	APIURL      string    `json:"api_url"`
	EnrolledAt  time.Time `json:"enrolled_at"`
}

// Identity is a loaded identity. Its private keys are unexported and its
// String, GoString and LogValue methods print only the connector id, so it
// can be logged or printed safely.
type Identity struct {
	Meta
	key ed25519.PrivateKey
	// next is the key of a rotation that may or may not have reached
	// KrakenKey, or nil.
	next ed25519.PrivateKey
}

func (i *Identity) String() string { return "connector " + i.ConnectorID }

// GoString keeps %#v from printing the keys.
func (i *Identity) GoString() string { return i.String() }

// LogValue keeps slog from printing the keys.
func (i *Identity) LogValue() slog.Value { return slog.StringValue(i.String()) }

// PublicKey returns the current public key in the API's encoding.
func (i *Identity) PublicKey() string { return EncodePublicKey(i.key.Public().(ed25519.PublicKey)) }

// RotationPending reports whether an earlier rotation did not finish.
func (i *Identity) RotationPending() bool { return i.next != nil }

// EncodePublicKey encodes an Ed25519 public key as standard, padded base64
// of the raw 32 bytes.
func EncodePublicKey(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }

// Timestamp formats t as RFC 3339 UTC with second precision.
func Timestamp(t time.Time) string { return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z") }

// nonceBytes is the number of random bytes in a nonce: 43 characters
// once encoded, within the API's 16 bytes to 64 characters.
const nonceBytes = 32

// NewNonce returns base64url (unpadded) of 32 random bytes.
func NewNonce() (string, error) {
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// TokenMessage is the message signed for POST /connectors/token.
func TokenMessage(connectorID, timestamp, nonce string) []byte {
	return []byte(strings.Join([]string{TokenMessageV1, connectorID, timestamp, nonce}, "\n"))
}

// RotateMessage is the message signed for POST /connectors/rotate.
func RotateMessage(connectorID, newPublicKey, timestamp, nonce string) []byte {
	return []byte(strings.Join([]string{RotateMessageV1, connectorID, newPublicKey, timestamp, nonce}, "\n"))
}

// sign returns standard base64 of the Ed25519 signature of msg.
func sign(key ed25519.PrivateKey, msg []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, msg))
}

// Store reads and writes the identity files.
type Store struct {
	dir string
}

// NewStore returns the store for dataDir. It touches nothing on disk.
func NewStore(dataDir string) *Store { return &Store{dir: filepath.Join(dataDir, DirName)} }

// Dir returns the identity directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) path(name string) string { return filepath.Join(s.dir, name) }

// Load returns the identity, or nil if the connector is not enrolled. The
// directory and files must be private (see securefs.CheckPrivate).
func (s *Store) Load() (*Identity, error) {
	if err := securefs.CheckPrivate(s.dir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	keyExists, err := s.exists(KeyFile)
	if err != nil {
		return nil, err
	}
	metaExists, err := s.exists(MetaFile)
	if err != nil {
		return nil, err
	}
	switch {
	case !keyExists && !metaExists:
		return nil, nil
	case keyExists != metaExists:
		return nil, fmt.Errorf("identity in %s is incomplete (an interrupted enrolment?); enrol again with a new token and --force", s.dir)
	}

	id := &Identity{}
	data, err := s.readPrivate(MetaFile)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &id.Meta); err != nil {
		return nil, fmt.Errorf("identity: parse %s: %w", s.path(MetaFile), err)
	}
	if id.ConnectorID == "" {
		return nil, fmt.Errorf("identity: %s has no connector id", s.path(MetaFile))
	}
	if id.key, err = s.readKey(KeyFile); err != nil {
		return nil, err
	}
	nextExists, err := s.exists(NextKeyFile)
	if err != nil {
		return nil, err
	}
	if nextExists {
		if id.next, err = s.readKey(NextKeyFile); err != nil {
			return nil, err
		}
	}
	return id, nil
}

func (s *Store) exists(name string) (bool, error) {
	_, err := os.Lstat(s.path(name))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	return false, fmt.Errorf("identity: %w", err)
}

func (s *Store) readPrivate(name string) ([]byte, error) {
	p := s.path(name)
	if err := securefs.CheckPrivate(p); err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	return data, nil
}

func (s *Store) readKey(name string) (ed25519.PrivateKey, error) {
	data, err := s.readPrivate(name)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("identity: %s is not a PEM private key", s.path(name))
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("identity: %s: parse key failed", s.path(name))
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("identity: %s is not an Ed25519 key", s.path(name))
	}
	return key, nil
}

func (s *Store) writeKey(name string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := securefs.WriteFile(s.path(name), data); err != nil {
		return fmt.Errorf("identity: write %s: %w", name, err)
	}
	return nil
}

func (s *Store) writeMeta(m Meta) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := securefs.WriteFile(s.path(MetaFile), data); err != nil {
		return fmt.Errorf("identity: write %s: %w", MetaFile, err)
	}
	return nil
}

// generateKey creates a new Ed25519 key.
func generateKey() (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	return key, err
}

// removeIfExists removes a file in the identity directory and syncs it.
func (s *Store) removeIfExists(name string) error {
	if err := os.Remove(s.path(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("identity: %w", err)
	}
	return securefs.SyncDir(s.dir)
}

// promoteNext makes the rotation key the current key, in one rename.
func (s *Store) promoteNext() error {
	if err := os.Rename(s.path(NextKeyFile), s.path(KeyFile)); err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	return securefs.SyncDir(s.dir)
}
