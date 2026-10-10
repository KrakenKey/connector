package identity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/krakenkey/connector/internal/securefs"
)

// InstallIDFile is the file under the data directory that keeps the
// install id of a connector that is not enrolled.
const InstallIDFile = "install_id"

// InstallID returns the id plugins get to recognize this installation (see
// plugin.InstallIDFrom): the connector's id in KrakenKey when ident is
// set, otherwise a random id created on first use and kept in
// <dataDir>/install_id (mode 0600).
func InstallID(dataDir string, ident *Identity) (string, error) {
	return installID(dataDir, ident, true)
}

// ReadInstallID is InstallID without creating the file: it returns "" if
// the connector is not enrolled and has not run yet.
func ReadInstallID(dataDir string, ident *Identity) (string, error) {
	return installID(dataDir, ident, false)
}

func installID(dataDir string, ident *Identity, create bool) (string, error) {
	if ident != nil && ident.ConnectorID != "" {
		return ident.ConnectorID, nil
	}
	path := filepath.Join(dataDir, InstallIDFile)
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := securefs.CheckPrivate(path); err != nil {
			return "", fmt.Errorf("install id: %w", err)
		}
		id := strings.TrimSpace(string(data))
		if !validInstallID(id) {
			return "", fmt.Errorf("install id: %s does not hold a valid id; delete it to create a new one", path)
		}
		return id, nil
	case !errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("install id: %w", err)
	case !create:
		return "", nil
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("install id: %w", err)
	}
	id := "install-" + hex.EncodeToString(b)
	if err := securefs.WriteFile(path, []byte(id+"\n")); err != nil {
		return "", fmt.Errorf("install id: %w", err)
	}
	return id, nil
}

func validInstallID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	return strings.IndexFunc(id, func(r rune) bool {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.'
		return !ok
	}) < 0
}
