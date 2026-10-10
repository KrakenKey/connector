package appgw

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// vaultSuffixes are the Key Vault DNS suffixes of the Azure clouds.
var vaultSuffixes = []string{".vault.azure.net", ".vault.azure.cn", ".vault.usgovcloudapi.net"}

var (
	vaultNameRE   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$`)
	secretNameRE  = regexp.MustCompile(`^[A-Za-z0-9-]{1,127}$`)
	secretVerRE   = regexp.MustCompile(`^[0-9A-Fa-f]{32}$`)
	errNotVaultID = "not a Key Vault secret ID (want https://<vault>.vault.azure.net/secrets/<name>/<version>)"
)

// SecretID is a parsed Key Vault secret identifier.
type SecretID struct {
	Host    string // lowercase, e.g. myvault.vault.azure.net
	Name    string
	Version string // empty for a versionless ID
}

// String returns the canonical form: https://host/secrets/name/version, or
// https://host/secrets/name/ without a version (the form Azure documents for
// versionless IDs).
func (s SecretID) String() string {
	return "https://" + s.Host + "/secrets/" + s.Name + "/" + s.Version
}

// Versioned reports whether the ID pins a secret version.
func (s SecretID) Versioned() bool { return s.Version != "" }

// Equal compares two IDs the way Key Vault resolves them: host and secret
// name case-insensitively, the version exactly (lowercased).
func (s SecretID) Equal(o SecretID) bool {
	return strings.EqualFold(s.Host, o.Host) && strings.EqualFold(s.Name, o.Name) &&
		strings.EqualFold(s.Version, o.Version)
}

// ParseSecretID parses a Key Vault secret identifier, versioned or not.
// The error says what is wrong without echoing query strings.
func ParseSecretID(raw string) (SecretID, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return SecretID{}, fmt.Errorf("%s", errNotVaultID)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" && u.Port() != "443" {
		return SecretID{}, fmt.Errorf("%s: unexpected user info, port, query or fragment", errNotVaultID)
	}
	host := strings.ToLower(u.Hostname())
	vault := ""
	for _, suf := range vaultSuffixes {
		if v, ok := strings.CutSuffix(host, suf); ok {
			vault = v
			break
		}
	}
	if vault == "" || !vaultNameRE.MatchString(vault) {
		return SecretID{}, fmt.Errorf("%s: host %q is not a Key Vault", errNotVaultID, host)
	}
	parts := strings.Split(strings.TrimPrefix(u.EscapedPath(), "/"), "/")
	// secrets/<name>, secrets/<name>/, secrets/<name>/<version>
	if len(parts) == 3 && parts[2] == "" {
		parts = parts[:2]
	}
	if len(parts) < 2 || len(parts) > 3 || !strings.EqualFold(parts[0], "secrets") {
		return SecretID{}, fmt.Errorf("%s: path must be /secrets/<name>/<version>", errNotVaultID)
	}
	if !secretNameRE.MatchString(parts[1]) {
		return SecretID{}, fmt.Errorf("%s: bad secret name %q", errNotVaultID, parts[1])
	}
	id := SecretID{Host: host, Name: parts[1]}
	if len(parts) == 3 {
		if !secretVerRE.MatchString(parts[2]) {
			return SecretID{}, fmt.Errorf("%s: bad secret version %q", errNotVaultID, parts[2])
		}
		id.Version = strings.ToLower(parts[2])
	}
	return id, nil
}
