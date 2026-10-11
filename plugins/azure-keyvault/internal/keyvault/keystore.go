// Package keyvault is a KrakenKey connector key store backed by Azure Key
// Vault certificates. Key Vault creates the key pair and the CSR, and keeps
// the issued certificate next to the key, so the private key leaves the
// vault only when the certificate is marked exportable and a target asks
// for PEM or PFX.
package keyvault

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/hashicorp/go-hclog"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/krakenkey/connector/pkg/plugin"
)

const (
	// issuerUnknown makes Key Vault create the key and CSR and wait for
	// the signed certificate to be merged, instead of contacting a CA.
	issuerUnknown = "Unknown"
	// contentTypePKCS12 stores the certificate's secret as a PFX, which
	// is what Application Gateway and App Service read.
	contentTypePKCS12 = "application/x-pkcs12"
	contentTypePEM    = "application/x-pem-file"

	statusInProgress = "inProgress"

	// probeVersion is a secret version that never exists. Reading it
	// answers 404 with permission to read secrets and 403 without, so
	// Validate can check access without fetching a private key.
	probeVersion = "00000000000000000000000000000000"

	// maxCNLength is the X.509 upper bound for a common name.
	maxCNLength = 64
)

// Options configure a KeyStore. The zero value uses
// DefaultAzureCredential and the Azure SDK defaults.
type Options struct {
	// Credential overrides DefaultAzureCredential.
	Credential azcore.TokenCredential
	// ClientOptions are passed to the Key Vault clients (transport, retry).
	ClientOptions azcore.ClientOptions
	// DisableChallengeResourceVerification turns off the SDK check that
	// the vault's authentication challenge names the vault's own domain.
	// Only for tests against a fake vault.
	DisableChallengeResourceVerification bool
	// PollInterval is how often CreateCSR polls for the CSR when Key Vault
	// does not return it right away. Default 2s.
	PollInterval time.Duration
	// Logger receives warnings. Default: discard.
	Logger hclog.Logger
}

// KeyStore implements plugin.KeyStore on Azure Key Vault.
type KeyStore struct {
	plugin.UnimplementedKeyStore

	opts Options

	mu      sync.Mutex
	cred    azcore.TokenCredential
	clients map[string]*vaultClients // by vault URL
}

type vaultClients struct {
	certs   *azcertificates.Client
	secrets *azsecrets.Client
}

var (
	_ plugin.KeyStore                    = (*KeyStore)(nil)
	_ plugin.KeyStoreCapabilityValidator = (*KeyStore)(nil)
)

// New returns a key store.
func New(opts Options) *KeyStore {
	if opts.PollInterval <= 0 {
		opts.PollInterval = 2 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = hclog.NewNullLogger()
	}
	return &KeyStore{opts: opts, cred: opts.Credential, clients: map[string]*vaultClients{}}
}

// clientsFor returns cached clients for a vault. The clients keep the
// vault's authentication challenge, so reusing them saves a round trip.
func (k *KeyStore) clientsFor(vaultURL string) (*vaultClients, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if c, ok := k.clients[vaultURL]; ok {
		return c, nil
	}
	if k.cred == nil {
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("%w: Azure credential: %v", plugin.ErrPermanent, err)
		}
		k.cred = cred
	}
	certs, err := azcertificates.NewClient(vaultURL, k.cred, &azcertificates.ClientOptions{
		ClientOptions:                        k.opts.ClientOptions,
		DisableChallengeResourceVerification: k.opts.DisableChallengeResourceVerification,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: Key Vault client: %v", plugin.ErrPermanent, err)
	}
	secrets, err := azsecrets.NewClient(vaultURL, k.cred, &azsecrets.ClientOptions{
		ClientOptions:                        k.opts.ClientOptions,
		DisableChallengeResourceVerification: k.opts.DisableChallengeResourceVerification,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: Key Vault client: %v", plugin.ErrPermanent, err)
	}
	c := &vaultClients{certs: certs, secrets: secrets}
	k.clients[vaultURL] = c
	return c, nil
}

// Describe reports the capabilities. They cannot depend on a certificate's
// settings (Describe has no config), so the key store always reports
// exportable keys and PEM and PFX export; Export refuses PEM and PFX for
// certificates configured with exportable: false.
func (k *KeyStore) Describe(context.Context) (plugin.KeyStoreCapabilities, error) {
	return plugin.KeyStoreCapabilities{
		Provides:   []plugin.KeyFormat{plugin.KeyFormatVaultRef, plugin.KeyFormatPEM, plugin.KeyFormatPFX},
		Exportable: true,
		KeyTypes:   append([]plugin.KeyType(nil), plugin.AllKeyTypes...),
	}, nil
}

// Validate checks the settings, that the vault answers, that the identity
// can read the certificate's policy, and that the certificate is one the
// connector may use: not soft-deleted, and created by the connector for
// this KrakenKey certificate (or adopt: true).
func (k *KeyStore) Validate(ctx context.Context, req plugin.KeyStoreValidateRequest) ([]string, error) {
	s, problems := parseConfig(req.Config)
	if len(problems) > 0 {
		return problems, nil
	}
	c, err := k.clientsFor(s.vaultURL)
	if err != nil {
		return nil, err
	}
	if s.exportable {
		k.checkSecretAccess(ctx, c, s)
	}
	resp, err := c.certs.GetCertificatePolicy(ctx, s.name, nil)
	if isNotFound(err) {
		// The certificate is created on first issuance. A 404 rather than
		// a 403 also shows the identity may read certificates. A
		// soft-deleted certificate also answers 404 here, but blocks
		// creating one with the same name.
		if _, err := c.certs.GetDeletedCertificate(ctx, s.name, nil); err == nil {
			problems = append(problems, fmt.Sprintf(
				"certificate %q in %s is soft-deleted, so a new one cannot be created with that name; recover or purge it, or use another certificate_name",
				s.name, s.vaultURL))
		}
		return problems, nil
	}
	if err != nil {
		return nil, classify(opGetPolicy, s.name, err)
	}
	if req.CertificateID != "" {
		own, err := checkOwner(ctx, c, s.name, req.CertificateID)
		if err != nil {
			return nil, err
		}
		if p := own.problem(s); p != "" {
			problems = append(problems, p)
		}
	}
	if ip := resp.IssuerParameters; ip != nil && ip.Name != nil {
		switch name := *ip.Name; {
		case strings.EqualFold(name, issuerUnknown), strings.EqualFold(name, "Self"):
		default:
			problems = append(problems, fmt.Sprintf(
				"certificate %q in %s is issued through the Key Vault issuer %q; the connector would replace its policy with issuer %q. Use another certificate_name, or remove the issuer from this certificate",
				s.name, s.vaultURL, name, issuerUnknown))
		}
	}
	return problems, nil
}

// ValidateCapabilities is Validate with the capabilities for these
// settings: keys are exportable only with exportable: true, and the
// certificate is itself a deployment, which the connector adds as an
// implicit target (the vault URL and certificate name, served by this
// plugin's target). Errors from Key Vault are returned as problems, so the
// capabilities still reach the connector.
func (k *KeyStore) ValidateCapabilities(ctx context.Context, req plugin.KeyStoreValidateRequest) (plugin.KeyStoreValidation, error) {
	s, problems := parseConfig(req.Config)
	if len(problems) > 0 {
		return plugin.KeyStoreValidation{Problems: problems}, nil
	}
	caps, _ := k.Describe(ctx)
	caps.Exportable = s.exportable
	caps.ImplicitTarget = &plugin.ImplicitTarget{Config: implicitTargetConfig(s), DeploymentID: deploymentID(s.vaultURL, s.name)}
	problems, err := k.Validate(ctx, req)
	if err != nil {
		problems = append(problems, err.Error())
	}
	return plugin.KeyStoreValidation{Problems: problems, Capabilities: &caps}, nil
}

// checkSecretAccess warns when the identity cannot read the certificate's
// secret. It is not a problem for Validate: a target that takes a vault
// reference (Application Gateway) needs an exportable certificate but not
// the connector reading the secret, and Validate does not know the targets.
func (k *KeyStore) checkSecretAccess(ctx context.Context, c *vaultClients, s settings) {
	_, err := c.secrets.GetSecret(ctx, s.name, probeVersion, nil)
	if hasStatus(err, http.StatusForbidden) {
		k.opts.Logger.Warn("the identity cannot read Key Vault secrets; exporting the key as PEM or PFX will fail (vault references still work)",
			"vault", s.vaultURL, "certificate_name", s.name,
			"grant", opGetSecret.rbac+" (Azure RBAC) or "+opGetSecret.accessPolicy+" (access policy)")
	}
}

// CreateCSR starts a new certificate version with issuer Unknown and
// returns the CSR Key Vault made for it. The certificate must be absent or
// carry this KrakenKey certificate's tag (or adopt: true). Any request
// already pending for it is deleted first (see deleteStalePending).
func (k *KeyStore) CreateCSR(ctx context.Context, req plugin.CSRRequest) (plugin.CSR, error) {
	s, problems := parseConfig(req.Config)
	if len(problems) > 0 {
		return plugin.CSR{}, configError(problems)
	}
	if err := checkNames(req.Names); err != nil {
		return plugin.CSR{}, err
	}
	kp, err := keyParams(req.KeyType)
	if err != nil {
		return plugin.CSR{}, err
	}
	if !certIDRE.MatchString(req.CertificateID) {
		return plugin.CSR{}, fmt.Errorf("%w: certificate id %q is missing or not usable in a tag", plugin.ErrInvalid, req.CertificateID)
	}
	c, err := k.clientsFor(s.vaultURL)
	if err != nil {
		return plugin.CSR{}, err
	}
	own, err := checkOwner(ctx, c, s.name, req.CertificateID)
	if err != nil {
		return plugin.CSR{}, err
	}
	if p := own.problem(s); p != "" {
		return plugin.CSR{}, fmt.Errorf("%w: %s", plugin.ErrPermanent, p)
	}
	if err := k.deleteStalePending(ctx, c, s.name); err != nil {
		return plugin.CSR{}, err
	}
	// The version that is the latest now is what services use until this
	// request is merged; record it for the merged version's tag.
	prev := k.latestVersion(ctx, c, s.name)

	kp.Exportable = &s.exportable
	kp.ReuseKey = &s.reuseKey
	op, err := k.create(ctx, c, s.name, newPolicy(req.Names, kp), withPrevious(tagsFor(req.CertificateID), prev))
	if err != nil {
		return plugin.CSR{}, err
	}
	csr, err := x509.ParseCertificateRequest(op.CSR)
	if err != nil {
		return plugin.CSR{}, fmt.Errorf("%w: Key Vault returned a CSR that does not parse: %v", plugin.ErrPermanent, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return plugin.CSR{}, fmt.Errorf("%w: Key Vault returned a CSR with a bad signature: %v", plugin.ErrPermanent, err)
	}
	ref := keyRef{vaultURL: s.vaultURL, name: s.name, spki: spkiHash(csr.RawSubjectPublicKeyInfo), certID: req.CertificateID, prev: prev}
	return plugin.CSR{
		PEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})),
		KeyRef: ref.String(),
	}, nil
}

// newPolicy is the certificate policy for a new version: issuer Unknown,
// every name as a DNS SAN, stored as PFX, with the subject from
// subjectFor.
func newPolicy(names []string, kp *azcertificates.KeyProperties) *azcertificates.CertificatePolicy {
	sans := make([]*string, len(names))
	for i := range names {
		sans[i] = &names[i]
	}
	issuer := issuerUnknown
	ct := contentTypePKCS12
	return &azcertificates.CertificatePolicy{
		IssuerParameters: &azcertificates.IssuerParameters{Name: &issuer},
		KeyProperties:    kp,
		SecretProperties: &azcertificates.SecretProperties{ContentType: &ct},
		X509CertificateProperties: &azcertificates.X509CertificateProperties{
			Subject:                 subjectFor(names),
			SubjectAlternativeNames: &azcertificates.SubjectAlternativeNames{DNSNames: sans},
		},
	}
}

// subjectFor returns "CN=<name>" for the first name that fits in a common
// name (64 characters), or nil for a subject without a common name when no
// name fits. Clients match DNS SANs, not the common name.
func subjectFor(names []string) *string {
	for _, n := range names {
		if len(n) <= maxCNLength {
			subject := "CN=" + n
			return &subject
		}
	}
	return nil
}

// deleteStalePending removes a request left pending on the certificate.
//
// Key Vault allows one pending request per certificate, so a request still
// pending here blocks the new one. The connector records a key before it
// sends the CSR to KrakenKey, and releases the key of an earlier renewal
// before it asks for a new CSR, so a request still pending at this point
// was never handed to KrakenKey (for example the connector stopped between
// CreateCSR and saving its state). Deleting it and starting over gives a
// fresh key whose CSR matches this request exactly; reusing it would mean
// comparing names, key type, exportability and key reuse field by field to
// save one key generation.
//
// Requests with an issuer other than Unknown were not started by the
// connector, so they are left alone and reported. Callers check first that
// the certificate is the connector's (checkOwner), so requests on
// certificates someone else manages are never deleted.
func (k *KeyStore) deleteStalePending(ctx context.Context, c *vaultClients, name string) error {
	resp, err := c.certs.GetCertificateOperation(ctx, name, nil)
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return classify(opGetPending, name, err)
	}
	if deref(resp.Status) != statusInProgress {
		return nil
	}
	if ip := resp.IssuerParameters; ip == nil || ip.Name == nil || !strings.EqualFold(*ip.Name, issuerUnknown) {
		issuer := "(none)"
		if ip != nil && ip.Name != nil {
			issuer = *ip.Name
		}
		return fmt.Errorf("%w: certificate %q has a pending request through issuer %q that the connector did not start; complete or delete it in Key Vault first",
			plugin.ErrPermanent, name, issuer)
	}
	if _, err := c.certs.DeleteCertificateOperation(ctx, name, nil); err != nil && !isNotFound(err) {
		return classify(opDeletePending, name, err)
	}
	return nil
}

// create starts a new version and waits until its CSR is available.
func (k *KeyStore) create(ctx context.Context, c *vaultClients, name string, pol *azcertificates.CertificatePolicy, tags map[string]*string) (azcertificates.CertificateOperation, error) {
	resp, err := c.certs.CreateCertificate(ctx, name, azcertificates.CreateCertificateParameters{CertificatePolicy: pol, Tags: tags}, nil)
	if err != nil {
		return azcertificates.CertificateOperation{}, classify(opCreate, name, err)
	}
	op := resp.CertificateOperation
	for len(op.CSR) == 0 {
		if err := opFailed(name, op); err != nil {
			return op, err
		}
		select {
		case <-ctx.Done():
			// The request stays pending; the next CreateCSR deletes it.
			return op, fmt.Errorf("%w: Key Vault has not produced the CSR for %q yet: %v", plugin.ErrUnavailable, name, ctx.Err())
		case <-time.After(k.opts.PollInterval):
		}
		got, err := c.certs.GetCertificateOperation(ctx, name, nil)
		if err != nil {
			return op, classify(opGetPending, name, err)
		}
		op = got.CertificateOperation
	}
	return op, nil
}

func opFailed(name string, op azcertificates.CertificateOperation) error {
	switch st := deref(op.Status); st {
	case "", statusInProgress:
		return nil
	default:
		msg := deref(op.StatusDetails)
		if op.Error != nil {
			msg = op.Error.Code
		}
		return fmt.Errorf("%w: certificate request for %q is %s: %s", plugin.ErrPermanent, name, st, msg)
	}
}

// pendingCSR returns the CSR of the request pending on the certificate if
// it belongs to ref, or nil.
func pendingCSR(ctx context.Context, c *vaultClients, ref keyRef) (*x509.CertificateRequest, error) {
	resp, err := c.certs.GetCertificateOperation(ctx, ref.name, nil)
	if isNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, classify(opGetPending, ref.name, err)
	}
	if deref(resp.Status) != statusInProgress || len(resp.CSR) == 0 {
		return nil, nil
	}
	csr, err := x509.ParseCertificateRequest(resp.CSR)
	if err != nil || spkiHash(csr.RawSubjectPublicKeyInfo) != ref.spki {
		return nil, nil
	}
	return csr, nil
}

// getVersion returns a certificate version and its parsed certificate.
// version "" means the latest version.
func getVersion(ctx context.Context, c *vaultClients, name, version string) (azcertificates.Certificate, *x509.Certificate, error) {
	resp, err := c.certs.GetCertificate(ctx, name, version, nil)
	if err != nil {
		return azcertificates.Certificate{}, nil, classify(opGetCertificate, name, err)
	}
	if len(resp.CER) == 0 {
		return resp.Certificate, nil, fmt.Errorf("%w: certificate %q version %q has no certificate yet", plugin.ErrNotFound, name, version)
	}
	leaf, err := x509.ParseCertificate(resp.CER)
	if err != nil {
		return resp.Certificate, nil, fmt.Errorf("%w: certificate %q in Key Vault does not parse: %v", plugin.ErrPermanent, name, err)
	}
	return resp.Certificate, leaf, nil
}

// latestWithKey returns the latest version if its certificate carries the
// key with the given SubjectPublicKeyInfo hash.
func latestWithKey(ctx context.Context, c *vaultClients, name, spki string) (azcertificates.Certificate, *x509.Certificate, error) {
	cert, leaf, err := getVersion(ctx, c, name, "")
	if err != nil {
		if errors.Is(err, plugin.ErrNotFound) {
			return cert, nil, nil
		}
		return cert, nil, err
	}
	if spkiHash(leaf.RawSubjectPublicKeyInfo) != spki {
		return cert, nil, nil
	}
	return cert, leaf, nil
}

func (k *KeyStore) open(cfg []byte, ref string) (settings, keyRef, *vaultClients, error) {
	s, problems := parseConfig(cfg)
	if len(problems) > 0 {
		return s, keyRef{}, nil, configError(problems)
	}
	r, err := parseRef(ref)
	if err != nil {
		return s, r, nil, err
	}
	// The reference says where the key lives; use that vault even if the
	// config has moved on to another one since.
	c, err := k.clientsFor(r.vaultURL)
	return s, r, c, err
}

// PublicKey returns the key's SubjectPublicKeyInfo: from the pending
// request's CSR, or from the certificate of a completed version.
func (k *KeyStore) PublicKey(ctx context.Context, req plugin.PublicKeyRequest) ([]byte, error) {
	_, r, c, err := k.open(req.Config, req.KeyRef)
	if err != nil {
		return nil, err
	}
	if !r.pending() {
		_, leaf, err := getVersion(ctx, c, r.name, r.version)
		if err != nil {
			return nil, err
		}
		return leaf.RawSubjectPublicKeyInfo, nil
	}
	csr, err := pendingCSR(ctx, c, r)
	if err != nil {
		return nil, err
	}
	if csr != nil {
		return csr.RawSubjectPublicKeyInfo, nil
	}
	// The request may have been merged already (a Complete whose result
	// was not recorded).
	_, leaf, err := latestWithKey(ctx, c, r.name, r.spki)
	if err != nil {
		return nil, err
	}
	if leaf == nil {
		return nil, fmt.Errorf("%w: no pending request or version of %q holds this key", plugin.ErrNotFound, r.name)
	}
	return leaf.RawSubjectPublicKeyInfo, nil
}

// Complete merges the issued certificate and chain into the pending
// request and returns the new version's id as the key reference.
//
// For a completed reference (KrakenKey renewed the certificate with the
// same key), it creates a new version that reuses the key and merges the
// new certificate into it.
func (k *KeyStore) Complete(ctx context.Context, req plugin.CompleteRequest) (string, error) {
	s, r, c, err := k.open(req.Config, req.KeyRef)
	if err != nil {
		return "", err
	}
	x5c, leaf, err := parseIssued(req.CertPEM, req.ChainPEM)
	if err != nil {
		return "", err
	}
	leafSPKI := spkiHash(leaf.RawSubjectPublicKeyInfo)

	if r.pending() {
		if leafSPKI != r.spki {
			return "", fmt.Errorf("%w: the certificate's public key does not match the key in %s", plugin.ErrPermanent, r)
		}
		csr, err := pendingCSR(ctx, c, r)
		if err != nil {
			return "", err
		}
		if csr == nil {
			// Merged by an earlier call whose answer was lost?
			cert, latest, err := latestWithKey(ctx, c, r.name, r.spki)
			if err != nil {
				return "", err
			}
			if latest != nil && latest.Equal(leaf) {
				return idRef(cert)
			}
			return "", fmt.Errorf("%w: no pending request of %q holds this key any more", plugin.ErrNotFound, r.name)
		}
		return k.merge(ctx, c, r.name, x5c, withPrevious(tagsFor(r.certID), r.prev))
	}

	// A completed version: the certificate was renewed with the same key.
	cert, cur, err := getVersion(ctx, c, r.name, r.version)
	if err != nil {
		return "", err
	}
	if spkiHash(cur.RawSubjectPublicKeyInfo) != leafSPKI {
		return "", fmt.Errorf("%w: the certificate's public key does not match the key of %s", plugin.ErrPermanent, r)
	}
	if cur.Equal(leaf) {
		return idRef(cert)
	}
	latestCert, latest, err := latestWithKey(ctx, c, r.name, leafSPKI)
	if err != nil {
		return "", err
	}
	if latest != nil && latest.Equal(leaf) {
		return idRef(latestCert)
	}
	return k.renewSameKey(ctx, c, s, r, cert.Tags, leaf, x5c)
}

// renewSameKey attaches a certificate renewed with an existing key: it
// creates a version with reuse_key set, which makes Key Vault sign the CSR
// with the latest version's key, and merges the certificate into it. This
// works for keys that cannot be exported. The new version gets the tags of
// the version it renews.
//
// A request already pending on the certificate is most likely the
// connector's own renewal in progress, so it is not deleted: the call
// returns "unavailable" and is tried again once that request is completed
// or released.
func (k *KeyStore) renewSameKey(ctx context.Context, c *vaultClients, s settings, r keyRef, tags map[string]*string, leaf *x509.Certificate, x5c [][]byte) (string, error) {
	pol, err := c.certs.GetCertificatePolicy(ctx, r.name, nil)
	if err != nil {
		return "", classify(opGetPolicy, r.name, err)
	}
	if pol.KeyProperties == nil {
		return "", fmt.Errorf("%w: certificate %q has no key properties in its policy", plugin.ErrPermanent, r.name)
	}
	names := leaf.DNSNames
	if len(names) == 0 {
		return "", fmt.Errorf("%w: the renewed certificate has no DNS names", plugin.ErrPermanent)
	}
	kp := *pol.KeyProperties
	reuse := true
	kp.ReuseKey = &reuse
	kp.Exportable = &s.exportable
	newPol := newPolicy(names, &kp)
	if pol.X509CertificateProperties != nil && pol.X509CertificateProperties.Subject != nil {
		newPol.X509CertificateProperties.Subject = pol.X509CertificateProperties.Subject
	}
	if err := pendingBlocks(ctx, c, r.name); err != nil {
		return "", err
	}
	tags = withPrevious(tags, k.latestVersion(ctx, c, r.name))
	op, err := k.create(ctx, c, r.name, newPol, tags)
	if err != nil {
		return "", err
	}
	csr, err := x509.ParseCertificateRequest(op.CSR)
	if err != nil || spkiHash(csr.RawSubjectPublicKeyInfo) != spkiHash(leaf.RawSubjectPublicKeyInfo) {
		_, _ = c.certs.DeleteCertificateOperation(ctx, r.name, nil)
		return "", fmt.Errorf("%w: Key Vault did not reuse the key of %s for the renewed certificate (it reuses the latest version's key only); renew with a new key instead",
			plugin.ErrPermanent, r)
	}
	return k.merge(ctx, c, r.name, x5c, tags)
}

// pendingBlocks returns an error if a request is pending on the
// certificate.
func pendingBlocks(ctx context.Context, c *vaultClients, name string) error {
	op, err := c.certs.GetCertificateOperation(ctx, name, nil)
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return classify(opGetPending, name, err)
	}
	if deref(op.Status) != statusInProgress {
		return nil
	}
	if ip := op.IssuerParameters; ip != nil && ip.Name != nil && strings.EqualFold(*ip.Name, issuerUnknown) {
		return fmt.Errorf("%w: certificate %q has a request pending (a renewal in progress); the renewed certificate is attached once it is completed or released",
			plugin.ErrUnavailable, name)
	}
	return fmt.Errorf("%w: certificate %q has a pending request that the connector did not start; complete or delete it in Key Vault first",
		plugin.ErrPermanent, name)
}

// merge merges x5c into the pending request, passing tags for the new
// version: the ownership tag, so later calls can tell the connector created
// it, and tagPreviousVersion, for the target's rollback.
//
// The tags are passed both when the request is created and when it is
// merged. If the merged version still lacks one of them (Key Vault does not
// document which of the two it keeps), they are set on the version
// afterwards. That needs certificates/update/action, which the key store
// has; if it fails, the certificate stays merged and a warning is logged:
// without the tag, the target falls back to creation times for this
// version.
func (k *KeyStore) merge(ctx context.Context, c *vaultClients, name string, x5c [][]byte, tags map[string]*string) (string, error) {
	resp, err := c.certs.MergeCertificate(ctx, name, azcertificates.MergeCertificateParameters{X509Certificates: x5c, Tags: tags}, nil)
	if err != nil {
		return "", classify(opMerge, name, err)
	}
	ref, err := idRef(resp.Certificate)
	if err != nil {
		return "", err
	}
	if missing := missingTags(resp.Tags, tags); len(missing) > 0 {
		all := make(map[string]*string, len(resp.Tags)+len(missing))
		for key, v := range resp.Tags {
			all[key] = v
		}
		for key, v := range missing {
			all[key] = v
		}
		if _, err := c.certs.UpdateCertificate(ctx, name, resp.ID.Version(), azcertificates.UpdateCertificateParameters{Tags: all}, nil); err != nil {
			k.opts.Logger.Warn("could not tag the merged certificate version; a rollback of this version falls back to creation times",
				"certificate_name", name, "error", classify(opUpdateTags, name, err).Error())
		}
	}
	return ref, nil
}

// missingTags returns the tags in want that got lacks or has with another
// value.
func missingTags(got, want map[string]*string) map[string]*string {
	missing := map[string]*string{}
	for key, v := range want {
		if deref(got[key]) != deref(v) {
			missing[key] = v
		}
	}
	return missing
}

// latestVersion returns the id of the certificate's latest completed
// version, or "" when there is none or it cannot be read.
func (k *KeyStore) latestVersion(ctx context.Context, c *vaultClients, name string) string {
	resp, err := c.certs.GetCertificate(ctx, name, "", nil)
	if err != nil || resp.ID == nil || len(resp.CER) == 0 {
		return ""
	}
	return resp.ID.Version()
}

// withPrevious returns tags with tagPreviousVersion set to prev, or
// without it when prev is empty. It does not change tags.
func withPrevious(tags map[string]*string, prev string) map[string]*string {
	out := make(map[string]*string, len(tags)+1)
	for key, v := range tags {
		if key != tagPreviousVersion {
			out[key] = v
		}
	}
	if prev != "" {
		out[tagPreviousVersion] = &prev
	}
	return out
}

func idRef(cert azcertificates.Certificate) (string, error) {
	if cert.ID == nil {
		return "", fmt.Errorf("%w: Key Vault returned a certificate without an id", plugin.ErrPermanent)
	}
	r, err := refFromID(string(*cert.ID))
	if err != nil {
		return "", err
	}
	return r.String(), nil
}

// parseIssued returns the DER certificates for x5c, leaf first.
func parseIssued(certPEM, chainPEM string) ([][]byte, *x509.Certificate, error) {
	leafDER, err := pemCerts(certPEM)
	if err != nil || len(leafDER) != 1 {
		return nil, nil, fmt.Errorf("%w: cert_pem must hold exactly one certificate", plugin.ErrInvalid)
	}
	leaf, err := x509.ParseCertificate(leafDER[0])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: cert_pem: %v", plugin.ErrInvalid, err)
	}
	chain, err := pemCerts(chainPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: chain_pem: %v", plugin.ErrInvalid, err)
	}
	return append(leafDER, chain...), leaf, nil
}

func pemCerts(s string) ([][]byte, error) {
	var out [][]byte
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q", b.Type)
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return nil, err
		}
		out = append(out, b.Bytes)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("trailing data after the PEM certificates")
	}
	return out, nil
}

// Export returns the versioned secret id (vault_ref), or the private key
// as PEM or the PFX from the certificate's secret when exportable.
func (k *KeyStore) Export(ctx context.Context, req plugin.ExportRequest) (plugin.KeyMaterial, error) {
	s, r, c, err := k.open(req.Config, req.KeyRef)
	if err != nil {
		return plugin.KeyMaterial{}, err
	}
	if r.pending() {
		return plugin.KeyMaterial{}, fmt.Errorf("%w: %s has no certificate yet; Complete comes before Export", plugin.ErrPermanent, r)
	}
	switch req.Format {
	case plugin.KeyFormatVaultRef:
		cert, _, err := getVersion(ctx, c, r.name, r.version)
		if err != nil {
			return plugin.KeyMaterial{}, err
		}
		sid := r.secretID()
		if cert.SID != nil && *cert.SID != "" {
			sid = string(*cert.SID)
		}
		return plugin.KeyMaterial{Format: plugin.KeyFormatVaultRef, Ref: sid}, nil
	case plugin.KeyFormatPEM, plugin.KeyFormatPFX:
	default:
		return plugin.KeyMaterial{}, fmt.Errorf("%w: key format %q is not provided by azure-keyvault", plugin.ErrPermanent, req.Format)
	}
	if !s.exportable {
		return plugin.KeyMaterial{}, fmt.Errorf("%w: certificate %q is configured with exportable: false, so its key cannot be exported as %s; use a target that accepts a vault reference, or set exportable: true (applies to keys created afterwards)",
			plugin.ErrPermanent, r.name, req.Format)
	}
	resp, err := c.secrets.GetSecret(ctx, r.name, r.version, nil)
	if err != nil {
		return plugin.KeyMaterial{}, classify(opGetSecret, r.name, err)
	}
	return keyMaterial(r, req.Format, deref(resp.ContentType), deref(resp.Value))
}

// keyMaterial converts a certificate secret into the requested format.
// Errors never include the secret value.
func keyMaterial(r keyRef, format plugin.KeyFormat, contentType, value string) (plugin.KeyMaterial, error) {
	notExportable := fmt.Errorf("%w: the secret of %s holds no private key; the key is not exportable in Key Vault (its policy has exportable: false)", plugin.ErrPermanent, r)
	switch strings.ToLower(contentType) {
	case contentTypePKCS12:
		pfx, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return plugin.KeyMaterial{}, fmt.Errorf("%w: the secret of %s is not base64 PKCS#12", plugin.ErrPermanent, r)
		}
		key, _, _, err := pkcs12.DecodeChain(pfx, "")
		if err != nil || key == nil {
			if _, terr := pkcs12.DecodeTrustStore(pfx, ""); terr == nil {
				return plugin.KeyMaterial{}, notExportable
			}
			return plugin.KeyMaterial{}, fmt.Errorf("%w: the secret of %s is not a readable PKCS#12 bundle", plugin.ErrPermanent, r)
		}
		if format == plugin.KeyFormatPFX {
			return plugin.KeyMaterial{Format: plugin.KeyFormatPFX, Data: pfx}, nil
		}
		return pkcs8PEM(r, key)
	case contentTypePEM:
		key, leaf, chain, err := parsePEMBundle(value)
		if err != nil {
			return plugin.KeyMaterial{}, fmt.Errorf("%w: the secret of %s: %v", plugin.ErrPermanent, r, err)
		}
		if key == nil {
			return plugin.KeyMaterial{}, notExportable
		}
		if format == plugin.KeyFormatPEM {
			return pkcs8PEM(r, key)
		}
		pfx, err := pkcs12.Modern.Encode(key, leaf, chain, "")
		if err != nil {
			return plugin.KeyMaterial{}, fmt.Errorf("%w: building a PFX for %s: %v", plugin.ErrPermanent, r, err)
		}
		return plugin.KeyMaterial{Format: plugin.KeyFormatPFX, Data: pfx}, nil
	}
	return plugin.KeyMaterial{}, fmt.Errorf("%w: the secret of %s has content type %q, not %s or %s", plugin.ErrPermanent, r, contentType, contentTypePKCS12, contentTypePEM)
}

func pkcs8PEM(r keyRef, key any) (plugin.KeyMaterial, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return plugin.KeyMaterial{}, fmt.Errorf("%w: encoding the key of %s: %v", plugin.ErrPermanent, r, err)
	}
	return plugin.KeyMaterial{Format: plugin.KeyFormatPEM, Data: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})}, nil
}

// parsePEMBundle reads a Key Vault PEM secret: a private key followed by
// the certificate chain, leaf first.
func parsePEMBundle(s string) (key any, leaf *x509.Certificate, chain []*x509.Certificate, err error) {
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		switch b.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(b.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(b.Bytes)
		case "CERTIFICATE":
			var c *x509.Certificate
			if c, err = x509.ParseCertificate(b.Bytes); err == nil {
				if leaf == nil {
					leaf = c
				} else {
					chain = append(chain, c)
				}
			}
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unreadable %s block", strings.ToLower(b.Type))
		}
	}
	if leaf == nil {
		return nil, nil, nil, errors.New("no certificate in the PEM secret")
	}
	return key, leaf, chain, nil
}

// Release deletes the request of a pending key that will not be completed.
// Completed versions are left alone: Key Vault keeps older versions as
// history, and deleting single versions is not possible.
func (k *KeyStore) Release(ctx context.Context, req plugin.ReleaseRequest) error {
	r, err := parseRef(req.KeyRef)
	if err != nil {
		// Not a reference this key store made; nothing to release.
		return nil
	}
	if !r.pending() {
		return nil
	}
	c, err := k.clientsFor(r.vaultURL)
	if err != nil {
		return err
	}
	csr, err := pendingCSR(ctx, c, r)
	if err != nil || csr == nil {
		return err
	}
	if _, err := c.certs.DeleteCertificateOperation(ctx, r.name, nil); err != nil && !isNotFound(err) {
		return classify(opDeletePending, r.name, err)
	}
	return nil
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
