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

	"github.com/krakenkey/connector/internal/securefs"
)

// State is what the connector remembers about one certificate between
// runs. It holds references to keys, never key material.
type State struct {
	CertificateID int    `json:"certificate_id"`
	KeyStore      string `json:"key_store"`
	// KeyRef is the key store's reference to the key of the current
	// certificate, and KeySPKI the SHA-256 of that key's
	// SubjectPublicKeyInfo (hex).
	KeyRef       string    `json:"key_ref"`
	KeySPKI      string    `json:"key_spki_sha256"`
	Serial       string    `json:"serial"`
	NotAfter     time.Time `json:"not_after"`
	CertPEM      string    `json:"cert_pem"`
	ChainPEM     string    `json:"chain_pem"`
	FullChainPEM string    `json:"fullchain_pem"`
	// Pending is a key whose CSR was sent to KrakenKey but whose
	// certificate the connector has not seen yet. It is recorded before
	// the renewal request, so a renewal that completes after the connector
	// stopped waiting is picked up instead of renewed again.
	Pending *PendingKey `json:"pending,omitempty"`
	// Targets maps target labels to what is deployed there.
	Targets map[string]TargetState `json:"targets"`
	// RetiredKeys are earlier keys that some target may still use. They
	// are released once every target serves the current certificate.
	RetiredKeys []string  `json:"retired_keys,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PendingKey is a key with a renewal in flight.
type PendingKey struct {
	KeyRef    string    `json:"key_ref"`
	SPKI      string    `json:"spki_sha256"`
	CreatedAt time.Time `json:"created_at"`
}

// Deployment phases recorded while a target is being changed, so a later
// run can finish or undo a deployment that was interrupted.
const (
	PhaseStaged     = "staged"     // Stage returned StagedRef
	PhaseActivating = "activating" // Activate called, result unknown
	PhaseActivated  = "activated"  // Activate returned PreviousRef; not verified yet
)

// Outcomes of the last finished deployment to a target, as reported to
// KrakenKey.
const (
	OutcomeVerified     = "verified"               // verified with a TLS handshake
	OutcomeUnverifiable = "activated_unverifiable" // activated, not verified (no verify block, or the target propagates on its own schedule and verification failed)
	OutcomeFailed       = "failed"                 // failed, not rolled back (nothing changed, or the new certificate stayed)
	OutcomeRolledBack   = "rolled_back"            // failed and rolled back to the previous certificate
)

// TargetState is what the connector knows about one target.
type TargetState struct {
	// Serial is the certificate last deployed to the target successfully,
	// and NotAfter its expiry.
	Serial   string    `json:"serial,omitempty"`
	NotAfter time.Time `json:"not_after,omitzero"`
	// Phase, DeployingSerial, StagedRef and PreviousRef describe a
	// deployment in progress.
	Phase           string `json:"phase,omitempty"`
	DeployingSerial string `json:"deploying_serial,omitempty"`
	StagedRef       string `json:"staged_ref,omitempty"`
	PreviousRef     string `json:"previous_ref,omitempty"`
	// Failures counts failed deployments in a row; NextAttempt is the
	// earliest time the next one is tried.
	Failures    int       `json:"failures,omitempty"`
	NextAttempt time.Time `json:"next_attempt,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	// Outcome is how the last finished deployment ended (Outcome*). Empty
	// for state written before it was recorded.
	Outcome   string    `json:"outcome,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// StateStore keeps State files under <data_dir>/state, mode 0600.
type StateStore struct {
	dir string
}

// OpenStateStore creates <dataDir>/state (0700) if needed and checks it.
func OpenStateStore(dataDir string) (*StateStore, error) {
	dir := filepath.Join(dataDir, "state")
	if err := securefs.EnsurePrivateDir(dir); err != nil {
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

// Save writes the state atomically and syncs the directory.
func (s *StateStore) Save(st *State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := securefs.WriteFile(s.path(st.CertificateID), data); err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	return nil
}
