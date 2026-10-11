package keyvault

import (
	"context"
	"fmt"
)

// tagCertificateID marks the certificate versions the connector creates
// with the KrakenKey certificate id they belong to. The connector only
// replaces the policy of, adds versions to, and deletes pending requests
// on certificates whose latest version carries this tag with the id being
// worked on, unless the config says adopt: true.
const tagCertificateID = "krakenkey-connector-certificate-id"

// tagPreviousVersion names, on a version the connector creates, the version
// that was the latest before it, so a rollback knows what consumers used
// before without relying on creation times (Key Vault keeps them to the
// second).
const tagPreviousVersion = "krakenkey-connector-previous-version"

type ownerState int

const (
	// ownerAbsent: no certificate with this name yet.
	ownerAbsent ownerState = iota
	// ownerSelf: the latest version carries this certificate's tag.
	ownerSelf
	// ownerUntagged: the certificate exists without the tag, so someone
	// else created it (by hand, through a Key Vault issuer, or an import).
	ownerUntagged
	// ownerOther: the tag names another KrakenKey certificate.
	ownerOther
	// ownerPendingOnly: a request is pending but no version exists yet
	// to read the tag from, so who started it cannot be told.
	ownerPendingOnly
)

type ownership struct {
	state   ownerState
	otherID string
}

// checkOwner reads the tag of the latest version of a certificate. For a
// certificate without versions it also looks for a pending request, which
// the key store may delete.
func checkOwner(ctx context.Context, c *vaultClients, name, certID string) (ownership, error) {
	return readOwner(ctx, c, name, certID, true)
}

// checkVersionOwner is checkOwner without the pending request, for the
// target, which only imports versions: Key Vault refuses an import while a
// request is pending, and reading pending requests needs more permissions
// than an import (in vaults that use access policies, certificate Create).
func checkVersionOwner(ctx context.Context, c *vaultClients, name, certID string) (ownership, error) {
	return readOwner(ctx, c, name, certID, false)
}

func readOwner(ctx context.Context, c *vaultClients, name, certID string, pending bool) (ownership, error) {
	resp, err := c.certs.GetCertificate(ctx, name, "", nil)
	if isNotFound(err) && !pending {
		return ownership{state: ownerAbsent}, nil
	}
	if isNotFound(err) {
		op, err := c.certs.GetCertificateOperation(ctx, name, nil)
		if isNotFound(err) {
			return ownership{state: ownerAbsent}, nil
		}
		if err != nil {
			return ownership{}, classify(opGetPending, name, err)
		}
		if deref(op.Status) == statusInProgress {
			return ownership{state: ownerPendingOnly}, nil
		}
		return ownership{state: ownerAbsent}, nil
	}
	if err != nil {
		return ownership{}, classify(opGetCertificate, name, err)
	}
	switch id := deref(resp.Tags[tagCertificateID]); id {
	case "":
		return ownership{state: ownerUntagged}, nil
	case certID:
		return ownership{state: ownerSelf}, nil
	default:
		return ownership{state: ownerOther, otherID: id}, nil
	}
}

// problem explains why the connector may not use the certificate, or
// returns "" if it may.
func (o ownership) problem(s settings) string {
	if s.adopt {
		return ""
	}
	where := fmt.Sprintf("certificate %q in %s", s.name, s.vaultURL)
	switch o.state {
	case ownerUntagged:
		return fmt.Sprintf("%s was not created by the connector (its latest version has no %s tag). "+
			"Use another certificate_name, or set adopt: true to let the connector take it over: it replaces the certificate's policy and adds versions",
			where, tagCertificateID)
	case ownerOther:
		return fmt.Sprintf("%s belongs to KrakenKey certificate %s (tag %s); two KrakenKey certificates cannot share one Key Vault certificate. "+
			"Use another certificate_name, or set adopt: true if this certificate replaces %s",
			where, o.otherID, tagCertificateID, o.otherID)
	case ownerPendingOnly:
		return fmt.Sprintf("%s has a pending request but no completed version, so the connector cannot tell who started it. "+
			"Delete the pending request in Key Vault, or set adopt: true",
			where)
	}
	return ""
}

func tagsFor(certID string) map[string]*string {
	return map[string]*string{tagCertificateID: &certID}
}
