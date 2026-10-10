// Package audit writes the connector's audit log: one JSON object per line
// for every step that changes something.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/krakenkey/connector/internal/redact"
	"github.com/krakenkey/connector/internal/securefs"
)

// Steps.
const (
	StepCheck     = "check"
	StepCreateCSR = "create_csr"
	StepRenew     = "renew"
	StepIssued    = "issued"
	StepComplete  = "complete"
	StepExport    = "export_key"
	StepStage     = "stage"
	StepDiscard   = "discard"
	StepRecover   = "recover"
	StepActivate  = "activate"
	StepThen      = "then"
	StepVerify    = "verify"
	StepRollback  = "rollback"
	StepRelease   = "release_key"
)

// Results.
const (
	ResultOK       = "ok"
	ResultFailed   = "failed"
	ResultSkipped  = "skipped"
	ResultRejected = "rejected"
	ResultReported = "reported" // failure reported, not rolled back
)

// Entry is one line of the audit log. It never holds key material.
type Entry struct {
	Time          time.Time `json:"time"`
	RunID         string    `json:"run_id"`
	CertificateID int       `json:"certificate_id"`
	Target        string    `json:"target,omitempty"`
	Step          string    `json:"step"`
	Result        string    `json:"result"`
	OldSerial     string    `json:"old_serial,omitempty"`
	NewSerial     string    `json:"new_serial,omitempty"`
	// PreviousRef is the target's reference to what was live before
	// Activate. It is what Rollback needs.
	PreviousRef string `json:"previous_ref,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Error       string `json:"error,omitempty"`
}

// Writer records entries.
type Writer interface {
	Write(Entry) error
}

// Log appends entries to a file and syncs after each one, so an entry is
// on disk before the caller moves on.
type Log struct {
	mu  sync.Mutex
	f   *os.File
	now func() time.Time
}

// Open opens (or creates) the audit log at path with mode 0600, creating
// its directory with mode 0700 when missing. An existing log must be a
// regular file owned by the connector's user with no group or other
// access.
func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		if err := securefs.CheckPrivate(path); err != nil {
			return nil, fmt.Errorf("audit log: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscallNoFollow, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	return &Log{f: f, now: time.Now}, nil
}

// maxField caps the error and detail text kept per entry.
const maxField = 1024

// Scrub removes private keys and KrakenKey API keys from s and caps its
// length. Command output and plugin errors pass through it before they
// reach the audit log.
func Scrub(s string) string { return redact.Limit(redact.String(s), maxField) }

// Write appends e. A zero Time is set to now.
func (l *Log) Write(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	e.Error, e.Detail = Scrub(e.Error), Scrub(e.Detail)
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if _, err := l.f.Write(line); err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	return nil
}

// Close closes the file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
