//go:build unix

package securefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckPrivate(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "priv")
	if err := EnsurePrivateDir(priv); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(priv, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(priv); !errors.Is(err, ErrInsecure) {
		t.Errorf("0750 dir: %v", err)
	}
	link := filepath.Join(dir, "link")
	_ = os.Symlink(priv, link)
	if err := CheckPrivate(link); !errors.Is(err, ErrInsecure) {
		t.Errorf("symlink: %v", err)
	}
	f := filepath.Join(dir, "f")
	if err := WriteFile(f, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(f); err != nil {
		t.Errorf("WriteFile result not private: %v", err)
	}
	if err := WriteFile(f, []byte("y")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(f); string(b) != "y" {
		t.Errorf("content %q", b)
	}
}
