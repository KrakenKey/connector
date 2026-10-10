package appgw

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	armnetwork "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"

	"github.com/krakenkey/connector/pkg/plugin"
)

// slotKind is what the configured sslCertificates entry holds.
type slotKind int

const (
	// slotAbsent: the gateway has no entry with that name.
	slotAbsent slotKind = iota
	// slotKeyVault: the entry references a Key Vault secret.
	slotKeyVault
	// slotInline: the entry holds an uploaded PFX (or anything else that is
	// not a Key Vault secret ID). ARM never returns the PFX, so it cannot be
	// put back.
	slotInline
)

// slot is the state of the configured sslCertificates entry.
type slot struct {
	kind slotKind
	// secretID is the entry's keyVaultSecretId exactly as the gateway holds
	// it, for slotKeyVault.
	secretID string
}

func keyVaultSlot(id string) slot { return slot{kind: slotKeyVault, secretID: id} }

func (s slot) String() string {
	switch s.kind {
	case slotKeyVault:
		return "Key Vault secret " + s.secretID
	case slotAbsent:
		return "no such certificate entry"
	default:
		return "an uploaded certificate (not from Key Vault)"
	}
}

// equal compares two slots, treating Key Vault IDs that resolve to the same
// secret (and version, if any) as equal.
func (s slot) equal(o slot) bool {
	if s.kind != o.kind {
		return false
	}
	if s.kind != slotKeyVault {
		return true
	}
	a, errA := ParseSecretID(s.secretID)
	b, errB := ParseSecretID(o.secretID)
	if errA != nil || errB != nil {
		return strings.EqualFold(strings.TrimSuffix(s.secretID, "/"), strings.TrimSuffix(o.secretID, "/"))
	}
	return a.Equal(b)
}

// Reasons a previous ref cannot be rolled back to.
const (
	// The entry held an uploaded PFX, which Azure never returns.
	reasonUploaded = "uploaded-certificate"
	// The entry already pointed at the staged secret when Activate first
	// read it, so what was live before is unknown (for example an earlier
	// activation finished after its call gave up).
	reasonAlreadyActive = "already-active"
	// The entry held a versionless ID of the same secret, which now
	// resolves to the new version: restoring it would change nothing.
	reasonVersionlessSameSecret = "versionless-same-secret"
)

// previousRef is what Activate returns for Rollback, JSON encoded.
type previousRef struct {
	V int `json:"v"`
	// Restore is the keyVaultSecretId to put back, exactly as it was.
	Restore string `json:"restore,omitempty"`
	// Unrestorable, when set, says why Rollback cannot restore anything.
	Unrestorable string `json:"unrestorable,omitempty"`
	// Over is the secret ID Activate installed. Rollback only writes when
	// the gateway still shows it.
	Over string `json:"over"`
}

func (p previousRef) encode() string {
	b, _ := json.Marshal(p)
	return string(b)
}

func parsePreviousRef(ref string) (previousRef, error) {
	if ref == "" {
		return previousRef{}, fmt.Errorf("%w: no previous ref, so the state before Activate is unknown and cannot be restored", plugin.ErrPermanent)
	}
	var p previousRef
	dec := json.NewDecoder(strings.NewReader(ref))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || p.V != 1 || p.Over == "" || (p.Restore == "") == (p.Unrestorable == "") {
		return previousRef{}, fmt.Errorf("%w: previous ref is not one this plugin returned", plugin.ErrNotFound)
	}
	if _, err := ParseSecretID(p.Over); err != nil {
		return previousRef{}, fmt.Errorf("%w: previous ref is not one this plugin returned: %v", plugin.ErrNotFound, err)
	}
	return p, nil
}

// unrestorableError explains why a previous ref cannot be rolled back to.
func unrestorableError(reason string) error {
	var why string
	switch reason {
	case reasonUploaded:
		why = "the certificate before activation was uploaded to the gateway directly, and Azure does not return uploaded certificates"
	case reasonAlreadyActive:
		why = "the gateway already pointed at the new secret version when it was activated, so what was live before is unknown"
	case reasonVersionlessSameSecret:
		why = "the gateway used a versionless ID of the same Key Vault secret before, which now resolves to the new version"
	default:
		why = "the previous state was not recorded (" + reason + ")"
	}
	return fmt.Errorf("%w: cannot roll back: %s; the new certificate stays", plugin.ErrPermanent, why)
}

func findCert(gw *armnetwork.ApplicationGateway, name string) (int, *armnetwork.ApplicationGatewaySSLCertificate) {
	if gw.Properties == nil {
		return -1, nil
	}
	for i, c := range gw.Properties.SSLCertificates {
		if c != nil && c.Name != nil && strings.EqualFold(*c.Name, name) {
			return i, c
		}
	}
	return -1, nil
}

// readSlot reports what the named entry holds.
func readSlot(gw *armnetwork.ApplicationGateway, name string) slot {
	_, c := findCert(gw, name)
	if c == nil {
		return slot{kind: slotAbsent}
	}
	if c.Properties != nil && c.Properties.KeyVaultSecretID != nil && *c.Properties.KeyVaultSecretID != "" {
		return keyVaultSlot(*c.Properties.KeyVaultSecretID)
	}
	return slot{kind: slotInline}
}

// writeSlot points the named entry at a Key Vault secret. The entry must
// exist. Its properties are replaced wholesale, which drops any uploaded
// PFX data and password (and the read-only fields).
func writeSlot(gw *armnetwork.ApplicationGateway, name string, want slot) error {
	_, c := findCert(gw, name)
	switch {
	case c == nil:
		return missingEntryError(name)
	case want.kind != slotKeyVault:
		return fmt.Errorf("%w: internal error: cannot write %s", plugin.ErrPermanent, want)
	}
	c.Properties = &armnetwork.ApplicationGatewaySSLCertificatePropertiesFormat{KeyVaultSecretID: to.Ptr(want.secretID)}
	return nil
}

func missingEntryError(name string) error {
	return fmt.Errorf("%w: %s", plugin.ErrPermanent, missingEntryProblem(name))
}

func missingEntryProblem(name string) string {
	return fmt.Sprintf("the gateway has no ssl certificate named %q; add it (pointing at a Key Vault secret) and use it on the HTTPS listeners first", name)
}

func uploadedProblem(name string) string {
	return fmt.Sprintf("ssl certificate %q holds a certificate uploaded to the gateway, which cannot be restored once replaced; "+
		"set replace_uploaded_certificate: true to replace it anyway", name)
}

// sameSecret reports whether a versionless ID names the same secret as id.
func sameSecret(versionless string, id SecretID) bool {
	v, err := ParseSecretID(versionless)
	return err == nil && !v.Versioned() && strings.EqualFold(v.Host, id.Host) && strings.EqualFold(v.Name, id.Name)
}
