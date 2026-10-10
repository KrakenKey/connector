package deploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// State is what the connector remembers about one certificate between
// runs. It holds references to keys, never key material.
type State struct {
	CertificateID int    `json:"certificate_id"`
	KeyStore      string `json:"key_store"`
	// KeyRef is the key store's reference to the key of the current
	// certificate.
	KeyRef       string `json:"key_ref"`
	Serial       string `json:"serial"`
	CertPEM      string `json:"cert_pem"`
	ChainPEM     string `json:"chain_pem"`
	FullChainPEM string `json:"fullchain_pem"`
	// Targets maps target labels to what is deployed there.
	Targets map[string]TargetState `json:"targets"`
	// RetiredKeys are earlier keys that some target may still use. They
	// are released once every target serves the current certificate.
	RetiredKeys []string  `json:"retired_keys,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TargetState is what the connector knows about one target.
type TargetState struct {
	// Serial is the certificate last deployed to the target successfully.
	Serial string `json:"serial,omitempty"`
	// PreviousRef is the target's reference from the last Activate.
	PreviousRef string    `json:"previous_ref,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// StateStore keeps State files under <data_dir>/state, mode 0600.
type StateStore struct {
	dir string
}

// OpenStateStore creates <dataDir>/state (0700) if needed.
func OpenStateStore(dataDir string) (*StateStore, error) {
	dir := filepath.Join(dataDir, "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	return &StateStore{dir: dir}, nil
}

func (s *StateStore) path(id int) string {
	return filepath.Join(s.dir, strconv.Itoa(id)+".json")
}

// Load returns the state for a certificate, or nil if there is none.
func (s *StateStore) Load(id int) (*State, error) {
	data, err := os.ReadFile(s.path(id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", s.path(id), err)
	}
	if st.Targets == nil {
		st.Targets = map[string]TargetState{}
	}
	return &st, nil
}

// Save writes the state atomically.
func (s *StateStore) Save(st *State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".state-*")
	if err != nil {
		return fmt.Errorf("save state: %w", err)
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
	if err := os.Rename(tmp.Name(), s.path(st.CertificateID)); err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	return nil
}
