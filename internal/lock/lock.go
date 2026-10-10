// Package lock keeps two connector processes from working on the same data
// directory at once (for example a long-running `run` and a `run --once`
// from cron).
package lock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrLocked means another process holds the lock.
var ErrLocked = errors.New("another krakenkey-connector process is using this data directory")

// Lock is a held lock.
type Lock struct{ f *os.File }

// Acquire takes the lock file <dataDir>/connector.lock without waiting.
func Acquire(dataDir string) (*Lock, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "connector.lock")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lock: %w", err)
	}
	if err := tryLock(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Lock{f: f}, nil
}

// Release drops the lock.
func (l *Lock) Release() error {
	unlock(l.f)
	return l.f.Close()
}
