package keyvault

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/krakenkey/connector/pkg/plugin"
)

// Key references.
//
// A key created by CreateCSR and not yet completed is a pending request on
// the certificate:
//
//	https://<vault>/certificates/<name>/pending?spki_sha256=<hex>
//
// Key Vault keeps at most one pending request per certificate, so the
// SHA-256 of the CSR's SubjectPublicKeyInfo tells this key's request apart
// from a later one for the same certificate.
//
// After Complete the reference is the certificate version's id, as Key
// Vault returns it:
//
//	https://<vault>/certificates/<name>/<version>
//
// The matching secret, which is what services such as Application Gateway
// read, is https://<vault>/secrets/<name>/<version>.
type keyRef struct {
	vaultURL string
	name     string
	version  string // empty for a pending request
	spki     string // pending only: hex SHA-256 of the SubjectPublicKeyInfo
}

const pendingSegment = "pending"

var (
	versionRE = regexp.MustCompile(`^[a-zA-Z0-9]{1,64}$`)
	spkiRE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func (r keyRef) pending() bool { return r.version == "" }

func (r keyRef) String() string {
	base := r.vaultURL + "/certificates/" + r.name + "/"
	if r.pending() {
		return base + pendingSegment + "?spki_sha256=" + r.spki
	}
	return base + r.version
}

// secretID is the versioned secret id of a completed version.
func (r keyRef) secretID() string {
	return r.vaultURL + "/secrets/" + r.name + "/" + r.version
}

func parseRef(s string) (keyRef, error) {
	bad := func(why string) (keyRef, error) {
		return keyRef{}, fmt.Errorf("%w: key ref %q is not an azure-keyvault reference: %s", plugin.ErrInvalid, s, why)
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return bad("want https://<vault>/certificates/<name>/<version>")
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "certificates" || !objectNameRE.MatchString(parts[1]) {
		return bad("want https://<vault>/certificates/<name>/<version>")
	}
	r := keyRef{vaultURL: "https://" + strings.ToLower(u.Host), name: parts[1]}
	if parts[2] == pendingSegment {
		r.spki = u.Query().Get("spki_sha256")
		if !spkiRE.MatchString(r.spki) || len(u.Query()) != 1 {
			return bad("pending reference without a valid spki_sha256")
		}
		return r, nil
	}
	if !versionRE.MatchString(parts[2]) || u.RawQuery != "" {
		return bad("invalid version")
	}
	r.version = parts[2]
	return r, nil
}

// refFromID builds a completed reference from a certificate id returned by
// Key Vault (https://<vault>/certificates/<name>/<version>).
func refFromID(id string) (keyRef, error) {
	r, err := parseRef(id)
	if err != nil {
		return keyRef{}, fmt.Errorf("%w: Key Vault returned an unexpected certificate id %q", plugin.ErrPermanent, id)
	}
	if r.pending() {
		return keyRef{}, fmt.Errorf("%w: Key Vault returned a certificate id without a version: %q", plugin.ErrPermanent, id)
	}
	return r, nil
}

func spkiHash(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}
