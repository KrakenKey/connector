// Package securefs holds the file system checks and writes the connector
// uses for its own private files (keys, state, audit log).
package securefs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// ErrInsecure means a path is accessible to users other than the
// connector's, is a symlink, or is owned by someone else.
var ErrInsecure = errors.New("insecure permissions")

// EnsurePrivateDir creates dir with mode 0700 if it is missing, then checks
// it with CheckPrivate.
func EnsurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	return CheckPrivate(dir)
}

// CheckPrivate requires path to be a real file or directory (not a
// symlink), owned by the current user, with no group or other permission
// bits.
func CheckPrivate(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", ErrInsecure, path)
	}
	if !OwnedByMe(info) {
		return fmt.Errorf("%w: %s is not owned by the user running the connector", ErrInsecure, path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		want := "600"
		if info.IsDir() {
			want = "700"
		}
		return fmt.Errorf("%w: %s has mode %04o; run: chmod %s %s", ErrInsecure, path, perm, want, path)
	}
	return nil
}

// CheckTree runs CheckPrivate on root and everything below it.
func CheckTree(root string) error {
	return filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return CheckPrivate(path)
	})
}

// WriteFile writes data to path with mode 0600 through a temp file in the
// same directory, syncs it, renames it into place and syncs the directory,
// so a crash leaves either the old or the new content.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
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
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return SyncDir(dir)
}

// SyncDir flushes a directory so renames and removals in it survive a
// crash.
func SyncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
