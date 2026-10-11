package keyvault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// TargetConfig is a Key Vault target block in the connector config,
// without the fields the core owns (label, plugin, verify, then). The
// implicit target the key store adds gets these settings from the key
// store's own.
type TargetConfig struct {
	// Vault is the vault name or URL, as for the key store.
	Vault string `json:"vault"`
	// CertificateName is the Key Vault certificate the target adds
	// versions to.
	CertificateName string `json:"certificate_name"`
	// Adopt lets the target add versions to a certificate it did not
	// create. Default false.
	Adopt bool `json:"adopt"`
	// Exportable marks the private key of imported versions exportable.
	// Default true: Application Gateway, App Service and Front Door read the
	// key from the certificate's secret.
	Exportable *bool `json:"exportable"`
	// Tags are added to every version the target imports, next to the
	// ownership tag.
	Tags map[string]string `json:"tags"`
}

// targetSettings is a parsed and checked TargetConfig.
type targetSettings struct {
	vaultURL   string
	name       string
	adopt      bool
	exportable bool
	tags       map[string]string
}

// Key Vault allows 15 tags per object, names up to 512 characters and
// values up to 256. One tag is the ownership tag.
const (
	maxTags     = 15
	maxTagName  = 512
	maxTagValue = 256
	maxUserTags = maxTags - 1
)

func parseTargetConfig(raw json.RawMessage) (targetSettings, []string) {
	var c TargetConfig
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return targetSettings{}, []string{"target settings: " + err.Error()}
	}
	var problems []string
	s := targetSettings{name: c.CertificateName, adopt: c.Adopt, exportable: true, tags: c.Tags}
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
	if len(c.Tags) > maxUserTags {
		problems = append(problems, fmt.Sprintf("tags: at most %d tags (Key Vault allows %d, and the connector sets %s)", maxUserTags, maxTags, tagCertificateID))
	}
	names := make([]string, 0, len(c.Tags))
	for k := range c.Tags {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, k := range names {
		v := c.Tags[k]
		switch {
		case k == "" || utf8.RuneCountInString(k) > maxTagName:
			problems = append(problems, fmt.Sprintf("tags: name %q must be 1-%d characters", k, maxTagName))
		case strings.EqualFold(k, tagCertificateID):
			problems = append(problems, fmt.Sprintf("tags: %s is set by the connector", tagCertificateID))
		case utf8.RuneCountInString(v) > maxTagValue:
			problems = append(problems, fmt.Sprintf("tags: value of %q is longer than %d characters", k, maxTagValue))
		}
	}
	return s, problems
}

// id is where the target deploys (see deploymentID).
func (s targetSettings) id() string { return deploymentID(s.vaultURL, s.name) }

// ownerSettings is what the ownership check needs.
func (s targetSettings) owner() settings {
	return settings{vaultURL: s.vaultURL, name: s.name, adopt: s.adopt}
}

// implicitTargetConfig is the target settings for a key store's own
// certificate.
func implicitTargetConfig(s settings) json.RawMessage {
	exportable := s.exportable
	b, _ := json.Marshal(TargetConfig{Vault: s.vaultURL, CertificateName: s.name, Adopt: s.adopt, Exportable: &exportable})
	return b
}
