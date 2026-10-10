package appgw

import (
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

// Previous refs for states that are not a Key Vault secret ID. A secret ID
// always starts with https://, so these cannot collide with one.
const (
	refAbsent = "absent"
	refInline = "inline"
)

// slot is the state of the configured sslCertificates entry.
type slot struct {
	kind slotKind
	// secretID is the entry's keyVaultSecretId exactly as the gateway holds
	// it, for slotKeyVault.
	secretID string
}

// ref encodes the slot as a previous ref for Rollback.
func (s slot) ref() string {
	switch s.kind {
	case slotKeyVault:
		return s.secretID
	case slotAbsent:
		return refAbsent
	default:
		return refInline
	}
}

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
// secret version as equal.
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
		return strings.EqualFold(s.secretID, o.secretID)
	}
	return a.Equal(b)
}

// parsePreviousRef decodes a previous ref from Activate.
func parsePreviousRef(ref string) (slot, error) {
	switch ref {
	case "":
		return slot{}, fmt.Errorf("%w: no previous ref, so the state before Activate is unknown and cannot be restored", plugin.ErrPermanent)
	case refAbsent:
		return slot{kind: slotAbsent}, nil
	case refInline:
		return slot{kind: slotInline}, nil
	}
	if _, err := ParseSecretID(ref); err != nil {
		return slot{}, fmt.Errorf("%w: previous ref is not one this plugin returned: %v", plugin.ErrNotFound, err)
	}
	return slot{kind: slotKeyVault, secretID: ref}, nil
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
		return slot{kind: slotKeyVault, secretID: *c.Properties.KeyVaultSecretID}
	}
	return slot{kind: slotInline}
}

// writeSlot changes the gateway model so the named entry holds want.
// allowCreate permits adding the entry when it is missing.
func writeSlot(gw *armnetwork.ApplicationGateway, name string, want slot, allowCreate bool) error {
	i, c := findCert(gw, name)
	switch want.kind {
	case slotKeyVault:
		props := &armnetwork.ApplicationGatewaySSLCertificatePropertiesFormat{KeyVaultSecretID: to.Ptr(want.secretID)}
		if c != nil {
			// Replace the properties wholesale: this drops any uploaded PFX
			// data and password (and the read-only fields).
			c.Properties = props
			return nil
		}
		if !allowCreate {
			return fmt.Errorf("%w: the gateway has no ssl certificate named %q; create it or set create_if_missing: true", plugin.ErrPermanent, name)
		}
		if gw.Properties == nil {
			gw.Properties = &armnetwork.ApplicationGatewayPropertiesFormat{}
		}
		gw.Properties.SSLCertificates = append(gw.Properties.SSLCertificates,
			&armnetwork.ApplicationGatewaySSLCertificate{Name: to.Ptr(name), Properties: props})
		return nil

	case slotAbsent:
		if c == nil {
			return nil
		}
		if users := certUsers(gw, c); len(users) > 0 {
			return fmt.Errorf("%w: cannot remove ssl certificate %q to restore the state before activation: it is in use by %s",
				plugin.ErrPermanent, name, strings.Join(users, ", "))
		}
		certs := gw.Properties.SSLCertificates
		gw.Properties.SSLCertificates = append(certs[:i:i], certs[i+1:]...)
		return nil

	default:
		return errInlineNotRestorable
	}
}

var errInlineNotRestorable = fmt.Errorf("%w: the certificate before activation was uploaded to the gateway directly, and Azure does not return uploaded certificates, so it cannot be restored",
	plugin.ErrPermanent)

// certUsers lists the listeners that reference an sslCertificates entry.
func certUsers(gw *armnetwork.ApplicationGateway, c *armnetwork.ApplicationGatewaySSLCertificate) []string {
	if gw.Properties == nil {
		return nil
	}
	refersTo := func(r *armnetwork.SubResource) bool {
		if r == nil || r.ID == nil || c.Name == nil {
			return false
		}
		if c.ID != nil && strings.EqualFold(*r.ID, *c.ID) {
			return true
		}
		return strings.HasSuffix(strings.ToLower(*r.ID), "/sslcertificates/"+strings.ToLower(*c.Name))
	}
	var users []string
	for _, l := range gw.Properties.HTTPListeners {
		if l != nil && l.Properties != nil && refersTo(l.Properties.SSLCertificate) {
			users = append(users, "listener "+deref(l.Name))
		}
	}
	for _, l := range gw.Properties.Listeners {
		if l != nil && l.Properties != nil && refersTo(l.Properties.SSLCertificate) {
			users = append(users, "listener "+deref(l.Name))
		}
	}
	return users
}
