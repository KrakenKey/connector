package keyvault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"

	"github.com/krakenkey/connector/pkg/plugin"
)

// Config is the key store block of a certificate in the connector config,
// without the fields the core owns (plugin, key_type).
type Config struct {
	// Vault is the vault name ("my-vault", meaning
	// https://my-vault.vault.azure.net) or the vault URL.
	Vault string `json:"vault"`
	// CertificateName is the name of the Key Vault certificate object.
	CertificateName string `json:"certificate_name"`
	// Exportable marks the private key exportable. Default true.
	Exportable *bool `json:"exportable"`
	// ReuseKey asks Key Vault to keep the same key pair for new versions.
	// Default false.
	ReuseKey bool `json:"reuse_key"`
	// Adopt lets the connector take over a certificate it did not create
	// (no ownership tag, or the tag of another KrakenKey certificate).
	// Default false.
	Adopt bool `json:"adopt"`
}

// settings is a parsed and checked Config.
type settings struct {
	vaultURL   string // https://host, lowercase, no trailing slash
	name       string
	exportable bool
	reuseKey   bool
	adopt      bool
}

var (
	// Key Vault names: 3-24 characters, letters, digits and hyphens,
	// starting with a letter, not ending with a hyphen, no "--".
	vaultNameRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$`)
	// Key Vault object names: 1-127 letters, digits and hyphens.
	objectNameRE = regexp.MustCompile(`^[a-zA-Z0-9-]{1,127}$`)
)

// parseConfig decodes and checks the plugin settings. It returns every
// problem found.
func parseConfig(raw json.RawMessage) (settings, []string) {
	var c Config
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return settings{}, []string{"key_store settings: " + err.Error()}
	}

	var problems []string
	s := settings{exportable: true, reuseKey: c.ReuseKey, adopt: c.Adopt, name: c.CertificateName}
	if c.Exportable != nil {
		s.exportable = *c.Exportable
	}
	if strings.TrimSpace(c.Vault) == "" {
		problems = append(problems, "vault is required (a vault name or its https URL)")
	} else if u, err := vaultURL(c.Vault); err != nil {
		problems = append(problems, "vault: "+err.Error())
	} else {
		s.vaultURL = u
	}
	switch {
	case c.CertificateName == "":
		problems = append(problems, "certificate_name is required")
	case !objectNameRE.MatchString(c.CertificateName):
		problems = append(problems, fmt.Sprintf("certificate_name %q is not a valid Key Vault object name (1-127 letters, digits and hyphens)", c.CertificateName))
	}
	return s, problems
}

// configError turns config problems into an error for calls other than
// Validate.
func configError(problems []string) error {
	return fmt.Errorf("%w: %s", plugin.ErrPermanent, strings.Join(problems, "; "))
}

// vaultURL turns a vault name or URL into the vault's base URL.
func vaultURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "://") {
		if !vaultNameRE.MatchString(s) || strings.Contains(s, "--") {
			return "", fmt.Errorf("%q is not a valid vault name (3-24 letters, digits and hyphens, starting with a letter) or an https URL", s)
		}
		return "https://" + strings.ToLower(s) + ".vault.azure.net", nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid URL", s)
	}
	switch {
	case u.Scheme != "https":
		return "", fmt.Errorf("%q must use https", s)
	case u.Hostname() == "":
		return "", fmt.Errorf("%q has no host", s)
	case u.User != nil:
		return "", fmt.Errorf("%q must not contain credentials", s)
	case u.Path != "" && u.Path != "/", u.RawQuery != "", u.Fragment != "":
		return "", fmt.Errorf("%q must be the vault URL alone, such as https://my-vault.vault.azure.net", s)
	}
	return "https://" + normHost(u), nil
}

// keyParams maps a connector key type to Key Vault key properties.
func keyParams(kt plugin.KeyType) (*azcertificates.KeyProperties, error) {
	rsa := azcertificates.KeyTypeRSA
	ec := azcertificates.KeyTypeEC
	size := func(n int32) *int32 { return &n }
	curve := func(c azcertificates.CurveName) *azcertificates.CurveName { return &c }
	switch kt {
	case plugin.KeyTypeRSA2048:
		return &azcertificates.KeyProperties{KeyType: &rsa, KeySize: size(2048)}, nil
	case plugin.KeyTypeRSA3072:
		return &azcertificates.KeyProperties{KeyType: &rsa, KeySize: size(3072)}, nil
	case plugin.KeyTypeRSA4096:
		return &azcertificates.KeyProperties{KeyType: &rsa, KeySize: size(4096)}, nil
	case plugin.KeyTypeECDSAP256:
		return &azcertificates.KeyProperties{KeyType: &ec, Curve: curve(azcertificates.CurveNameP256)}, nil
	case plugin.KeyTypeECDSAP384:
		return &azcertificates.KeyProperties{KeyType: &ec, Curve: curve(azcertificates.CurveNameP384)}, nil
	}
	return nil, fmt.Errorf("%w: key type %q is not supported (want one of %s)", plugin.ErrPermanent, kt, keyTypeList())
}

func keyTypeList() string {
	s := make([]string, len(plugin.AllKeyTypes))
	for i, k := range plugin.AllKeyTypes {
		s[i] = string(k)
	}
	return strings.Join(s, ", ")
}

// dnsNameRE accepts host names and wildcard names ("*.example.com").
var dnsNameRE = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// checkNames rejects names Key Vault would put in a CSR unchanged but that
// are not DNS names, such as names containing commas or spaces that would
// change the meaning of the subject.
func checkNames(names []string) error {
	if len(names) == 0 {
		return fmt.Errorf("%w: no DNS names for the CSR", plugin.ErrInvalid)
	}
	for _, n := range names {
		if len(n) > 253 || !dnsNameRE.MatchString(n) {
			return fmt.Errorf("%w: %q is not a DNS name", plugin.ErrInvalid, n)
		}
	}
	return nil
}
