package keyvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/krakenkey/connector/pkg/plugin"
)

// Target deploys certificates to a Key Vault certificate as new versions.
// Services that reference the certificate without a version (Application
// Gateway, App Service, Container Apps, API Management, Front Door, the
// AKS Secrets Store CSI driver, the VM Key Vault extension) pick up the
// latest version on their own schedule.
//
// The same plugin is the key store: when a certificate's key is kept in
// Key Vault, the key store has already merged the issued certificate as
// the latest version, and the target for that certificate (the implicit
// target, or a configured one with the same vault and name) finds it in
// place. For any other vault or certificate name, Activate imports the
// certificate and its key as a new version.
//
// Key Vault serves the latest enabled version to versionless consumers and
// cannot make an older version current again, so Rollback imports the
// previous certificate and key once more as a new version. That needs the
// previous key (RollbackNeedsMaterial).
type Target struct {
	plugin.UnimplementedTarget

	ks *KeyStore

	// ttl bounds how long staged material waits in memory for Activate.
	ttl time.Duration
	// core is 1 when the connector hands back rollback material, 2 when it
	// does not, 0 before Describe.
	core atomic.Int32

	mu     sync.Mutex
	staged map[string]*stagedImport
}

// stagedImport is what Stage prepared. It lives only in this process's
// memory; the staged ref the connector stores is a random id.
type stagedImport struct {
	vaultURL string
	name     string
	leaf     *x509.Certificate
	// pfx is the bundle to import, or nil when the certificate is already
	// the latest version.
	pfx   []byte
	at    time.Time
	timer *time.Timer
}

func (s *stagedImport) wipe() {
	for i := range s.pfx {
		s.pfx[i] = 0
	}
	s.pfx = nil
}

// stagedTTL bounds how long staged material waits for Activate. The
// connector activates right after staging.
const stagedTTL = time.Hour

// refPrefix marks a previous ref: "serial:<hex>" of the version that was
// the latest before the certificate went in. The connector stores it, so
// its format is part of the plugin's compatibility.
const refPrefix = "serial:"

var (
	_ plugin.Target                    = (*Target)(nil)
	_ plugin.TargetDeploymentValidator = (*Target)(nil)
)

// NewTarget returns a target that shares ks's credential and clients.
func NewTarget(ks *KeyStore) *Target {
	return &Target{ks: ks, ttl: stagedTTL, staged: map[string]*stagedImport{}}
}

// errOldCore explains why the target refuses a connector without the
// rollback material feature.
var errOldCore = fmt.Errorf("%w: the azure-keyvault target needs a connector that hands back the previous certificate and key on rollback (core feature %q); upgrade the connector",
	plugin.ErrPermanent, plugin.FeatureRollbackMaterial)

// Describe reports the capabilities. Key Vault consumers poll the vault on
// their own schedule (hours for most services), so verification failures
// are reported but not rolled back (PropagatesAsync).
func (t *Target) Describe(ctx context.Context) (plugin.TargetCapabilities, error) {
	if !plugin.HasCoreFeature(ctx, plugin.FeatureRollbackMaterial) {
		t.core.Store(2)
		return plugin.TargetCapabilities{}, errOldCore
	}
	t.core.Store(1)
	return plugin.TargetCapabilities{
		// A vault reference to another Key Vault certificate is read here
		// and imported, so the key does not pass through the connector.
		Accepts:               []plugin.KeyFormat{plugin.KeyFormatVaultRef, plugin.KeyFormatPEM, plugin.KeyFormatPFX},
		NeedsExportableKey:    true,
		SupportsRollback:      true,
		RollbackNeedsMaterial: true,
		KeyTypes:              append([]plugin.KeyType(nil), plugin.AllKeyTypes...),
		PropagatesAsync:       true,
	}, nil
}

// Validate checks the settings.
func (t *Target) Validate(ctx context.Context, req plugin.TargetValidateRequest) ([]string, error) {
	v, err := t.ValidateDeployment(ctx, req)
	return v.Problems, err
}

// ValidateDeployment checks the settings and, for a certificate other than
// the key store's own, that the connector may add versions to it. It
// reports the vault URL and certificate name as the deployment id. Errors
// from Key Vault are returned as problems, so the id still reaches the
// connector.
func (t *Target) ValidateDeployment(ctx context.Context, req plugin.TargetValidateRequest) (plugin.TargetValidation, error) {
	if t.core.Load() == 2 {
		return plugin.TargetValidation{Problems: []string{errOldCore.Error()}}, nil
	}
	s, problems := parseTargetConfig(req.Config)
	if s.vaultURL == "" || s.name == "" || !objectNameRE.MatchString(s.name) {
		return plugin.TargetValidation{Problems: problems}, nil
	}
	v := plugin.TargetValidation{Problems: problems, DeploymentID: s.id()}
	if len(problems) > 0 || (req.KeyStoreDeploymentID != "" && req.KeyStoreDeploymentID == v.DeploymentID) {
		// The key store checks its own certificate.
		return v, nil
	}
	c, err := t.ks.clientsFor(s.vaultURL)
	if err != nil {
		v.Problems = append(v.Problems, err.Error())
		return v, nil
	}
	if req.CertificateID != "" {
		own, err := checkOwner(ctx, c, s.name, req.CertificateID)
		if err != nil {
			v.Problems = append(v.Problems, err.Error())
			return v, nil
		}
		if p := own.problem(s.owner()); p != "" {
			v.Problems = append(v.Problems, p)
		}
		if own.state == ownerAbsent {
			if _, err := c.certs.GetDeletedCertificate(ctx, s.name, nil); err == nil {
				v.Problems = append(v.Problems, fmt.Sprintf(
					"certificate %q in %s is soft-deleted, so the connector cannot import into that name; recover or purge it, or use another certificate_name",
					s.name, s.vaultURL))
			}
		}
	}
	return v, nil
}

func (t *Target) open(raw []byte) (targetSettings, *vaultClients, error) {
	s, problems := parseTargetConfig(raw)
	if len(problems) > 0 {
		return s, nil, configError(problems)
	}
	c, err := t.ks.clientsFor(s.vaultURL)
	return s, c, err
}

// latest returns the latest version and its certificate. A missing
// certificate returns a nil leaf; a disabled latest version returns its
// properties and a nil leaf, since versionless consumers cannot read it.
func latest(ctx context.Context, c *vaultClients, name string) (azcertificates.Certificate, *x509.Certificate, error) {
	cert, leaf, err := getVersion(ctx, c, name, "")
	switch {
	case errors.Is(err, plugin.ErrNotFound):
		return cert, nil, nil
	case err != nil:
		if _, kv, ok := responseError(err); ok && kv.hasCode(codeCertificateDisabled) {
			return cert, nil, nil
		}
		return cert, nil, err
	case cert.Attributes != nil && cert.Attributes.Enabled != nil && !*cert.Attributes.Enabled:
		return cert, nil, nil
	}
	return cert, leaf, nil
}

func serialOf(leaf *x509.Certificate) string { return fmt.Sprintf("%x", leaf.SerialNumber) }

// Current returns the serial of the certificate's latest version, which
// versionless consumers use, or "" when there is none or it is disabled.
func (t *Target) Current(ctx context.Context, req plugin.CurrentRequest) (string, error) {
	s, c, err := t.open(req.Config)
	if err != nil {
		return "", err
	}
	_, leaf, err := latest(ctx, c, s.name)
	if err != nil || leaf == nil {
		return "", err
	}
	return serialOf(leaf), nil
}

// Stage checks the certificate and, unless it is already the latest
// version, gets its key and builds the PKCS#12 bundle to import. Nothing
// changes in Key Vault.
func (t *Target) Stage(ctx context.Context, req plugin.StageRequest) (string, error) {
	s, c, err := t.open(req.Config)
	if err != nil {
		return "", err
	}
	leaf, chain, err := parseCertAndChain(req.CertPEM, req.ChainPEM)
	if err != nil {
		return "", err
	}
	if req.Serial != "" && !strings.EqualFold(strings.TrimLeft(req.Serial, "0"), strings.TrimLeft(serialOf(leaf), "0")) {
		return "", fmt.Errorf("%w: request serial %s does not match the certificate's serial %s", plugin.ErrInvalid, req.Serial, serialOf(leaf))
	}
	st := &stagedImport{vaultURL: s.vaultURL, name: s.name, leaf: leaf}
	_, cur, err := latest(ctx, c, s.name)
	if err != nil {
		return "", err
	}
	if cur == nil || !cur.Equal(leaf) {
		if err := t.checkOwner(ctx, c, s, req.CertificateID); err != nil {
			return "", err
		}
		key, err := t.resolveKey(ctx, req.Key, leaf)
		if err != nil {
			return "", err
		}
		if st.pfx, err = pkcs12.LegacyDES.Encode(key, leaf, chain, ""); err != nil {
			return "", fmt.Errorf("%w: building the PKCS#12 bundle: %v", plugin.ErrPermanent, err)
		}
	}
	return t.keep(st), nil
}

// keep stores staged material under a random ref, wiped after the TTL.
func (t *Target) keep(st *stagedImport) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	ref := "staged-" + hex.EncodeToString(b)
	st.at = time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	st.timer = time.AfterFunc(t.ttl, func() { t.drop(ref, st) })
	t.staged[ref] = st
	return ref
}

func (t *Target) drop(ref string, st *stagedImport) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.staged[ref] == st {
		delete(t.staged, ref)
		st.wipe()
	}
}

// take removes and returns staged material, or nil. The caller wipes it.
func (t *Target) take(ref string) *stagedImport {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.staged[ref]
	delete(t.staged, ref)
	if st != nil {
		st.timer.Stop()
	}
	return st
}

// Activate imports the staged certificate as the latest version, or finds
// it there already, and returns the serial of the version that was the
// latest before it as the previous ref ("" when there was none, so there
// is nothing to roll back to). If the import fails, the latest version is
// unchanged: Key Vault adds the version or does nothing.
func (t *Target) Activate(ctx context.Context, req plugin.ActivateRequest) (string, error) {
	s, c, err := t.open(req.Config)
	if err != nil {
		return "", err
	}
	st := t.take(req.StagedRef)
	if st == nil {
		return "", fmt.Errorf("%w: staged ref %q (staged material lives in the plugin's memory and is gone after a restart)", plugin.ErrNotFound, req.StagedRef)
	}
	defer st.wipe()
	if st.vaultURL != s.vaultURL || !strings.EqualFold(st.name, s.name) {
		return "", fmt.Errorf("%w: staged for %s, but the target now points at %s", plugin.ErrPermanent, deploymentID(st.vaultURL, st.name), s.id())
	}
	cert, cur, err := latest(ctx, c, s.name)
	if err != nil {
		return "", err
	}
	if cur != nil && cur.Equal(st.leaf) {
		// In place: the key store merged it, or an earlier import whose
		// answer was lost. What was live before is the version before it.
		return t.previousRef(ctx, c, s.name, cert), nil
	}
	if st.pfx == nil {
		return "", fmt.Errorf("%w: certificate %s is no longer the latest version of %q in %s; staging again",
			plugin.ErrUnavailable, serialOf(st.leaf), s.name, s.vaultURL)
	}
	if err := t.checkOwner(ctx, c, s, req.CertificateID); err != nil {
		return "", err
	}
	prev := ""
	if cur != nil {
		prev = refPrefix + serialOf(cur)
	}
	if err := t.importPFX(ctx, c, s, req.CertificateID, st.pfx, st.leaf); err != nil {
		return "", err
	}
	return prev, nil
}

// previousRef returns the ref of the newest enabled version created before
// the given one, which versionless consumers used until it was added. It
// returns "" when there is none, and also when the versions cannot be
// listed (logged): the deployment stands, but cannot be rolled back.
func (t *Target) previousRef(ctx context.Context, c *vaultClients, name string, cur azcertificates.Certificate) string {
	if cur.ID == nil || cur.Attributes == nil || cur.Attributes.Created == nil {
		return ""
	}
	curVersion := cur.ID.Version()
	created := *cur.Attributes.Created
	var best *azcertificates.CertificateProperties
	pager := c.certs.NewListCertificatePropertiesVersionsPager(name, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			t.ks.opts.Logger.Warn("cannot list the certificate's versions; this deployment cannot be rolled back",
				"certificate_name", name, "error", classify(opListVersions, name, err).Error())
			return ""
		}
		for _, v := range page.Value {
			if v == nil || v.ID == nil || v.Attributes == nil || v.Attributes.Created == nil || v.ID.Version() == curVersion {
				continue
			}
			if v.Attributes.Enabled != nil && !*v.Attributes.Enabled {
				continue
			}
			if !v.Attributes.Created.Before(created) {
				continue
			}
			if best == nil || v.Attributes.Created.After(*best.Attributes.Created) {
				best = v
			}
		}
	}
	if best == nil {
		return ""
	}
	_, leaf, err := getVersion(ctx, c, name, best.ID.Version())
	if err != nil {
		t.ks.opts.Logger.Warn("cannot read the previous version; this deployment cannot be rolled back",
			"certificate_name", name, "error", err.Error())
		return ""
	}
	return refPrefix + serialOf(leaf)
}

// Rollback imports the certificate that was the latest version before the
// Activate that returned previousRef again, as a new latest version. Key
// Vault cannot make an older version current again, and disabling the new
// version would break versionless consumers instead of sending them back,
// so this needs the previous certificate and key from the connector.
func (t *Target) Rollback(ctx context.Context, req plugin.RollbackRequest) error {
	s, c, err := t.open(req.Config)
	if err != nil {
		return err
	}
	if req.PreviousRef == "" {
		return fmt.Errorf("%w: no earlier version was recorded, and Key Vault cannot remove a version that services may use; the new version stays", plugin.ErrPermanent)
	}
	prev, ok := strings.CutPrefix(req.PreviousRef, refPrefix)
	if _, err := hex.DecodeString(padHex(prev)); !ok || prev == "" || err != nil {
		return fmt.Errorf("%w: previous ref %q is not one this plugin returns (want %s<hex serial>)", plugin.ErrInvalid, req.PreviousRef, refPrefix)
	}
	var leaf *x509.Certificate
	var chain []*x509.Certificate
	if req.HasPreviousMaterial() {
		if req.PreviousSerial != "" && !sameSerial(req.PreviousSerial, prev) {
			return fmt.Errorf("%w: was handed certificate %s, but %s was the latest version before", plugin.ErrPermanent, req.PreviousSerial, prev)
		}
		if leaf, chain, err = parseCertAndChain(req.PreviousCertPEM, req.PreviousChainPEM); err != nil {
			return err
		}
		if !sameSerial(serialOf(leaf), prev) {
			return fmt.Errorf("%w: was handed certificate %s, but %s was the latest version before", plugin.ErrPermanent, serialOf(leaf), prev)
		}
	}
	_, cur, err := latest(ctx, c, s.name)
	if err != nil {
		return err
	}
	if cur != nil && sameSerial(serialOf(cur), prev) {
		return nil // already back
	}
	if leaf == nil {
		return fmt.Errorf("%w: cannot make certificate %s the latest version of %q again: Key Vault cannot reinstate an older version, so it must be imported again, and the connector did not hand back that certificate and its key (a key that cannot be exported, or nothing deployed before)",
			plugin.ErrPermanent, prev, s.name)
	}
	if err := t.checkOwner(ctx, c, s, req.CertificateID); err != nil {
		return err
	}
	key, err := t.resolveKey(ctx, req.PreviousKey, leaf)
	if err != nil {
		return fmt.Errorf("cannot put certificate %s back: %w", prev, err)
	}
	pfx, err := pkcs12.LegacyDES.Encode(key, leaf, chain, "")
	if err != nil {
		return fmt.Errorf("%w: building the PKCS#12 bundle: %v", plugin.ErrPermanent, err)
	}
	defer wipeBytes(pfx)
	return t.importPFX(ctx, c, s, req.CertificateID, pfx, leaf)
}

// Discard drops staged material. Unknown refs are fine.
func (t *Target) Discard(_ context.Context, req plugin.DiscardRequest) error {
	if st := t.take(req.StagedRef); st != nil {
		st.wipe()
	}
	return nil
}

// checkOwner refuses to add versions to a certificate the connector did
// not create for this KrakenKey certificate, unless adopt is set.
func (t *Target) checkOwner(ctx context.Context, c *vaultClients, s targetSettings, certID string) error {
	if s.adopt {
		return nil
	}
	if !certIDRE.MatchString(certID) {
		return fmt.Errorf("%w: certificate id %q is missing or not usable in a tag", plugin.ErrInvalid, certID)
	}
	own, err := checkOwner(ctx, c, s.name, certID)
	if err != nil {
		return err
	}
	if p := own.problem(s.owner()); p != "" {
		return fmt.Errorf("%w: %s", plugin.ErrPermanent, p)
	}
	return nil
}

// importPFX imports pfx as a new version, tagged with the ownership tag
// and the configured tags. When the call fails, it checks whether the
// version went in anyway (a lost answer) before reporting the failure.
func (t *Target) importPFX(ctx context.Context, c *vaultClients, s targetSettings, certID string, pfx []byte, leaf *x509.Certificate) error {
	if !certIDRE.MatchString(certID) {
		return fmt.Errorf("%w: certificate id %q is missing or not usable in a tag", plugin.ErrInvalid, certID)
	}
	tags := map[string]*string{}
	for k, v := range s.tags {
		tags[k] = &v
	}
	tags[tagCertificateID] = &certID
	kp, err := importKeyProperties(leaf, s.exportable)
	if err != nil {
		return err
	}
	ct := contentTypePKCS12
	value := base64.StdEncoding.EncodeToString(pfx)
	_, err = c.certs.ImportCertificate(ctx, s.name, azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: &value,
		CertificatePolicy: &azcertificates.CertificatePolicy{
			KeyProperties:    kp,
			SecretProperties: &azcertificates.SecretProperties{ContentType: &ct},
		},
		Tags: tags,
	}, nil)
	if err == nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if _, cur, cerr := latest(cctx, c, s.name); cerr == nil && cur != nil && cur.Equal(leaf) {
		return nil
	}
	return classify(opImport, s.name, err)
}

// importKeyProperties describes the key of an imported version.
func importKeyProperties(leaf *x509.Certificate, exportable bool) (*azcertificates.KeyProperties, error) {
	reuse := false
	kp := &azcertificates.KeyProperties{Exportable: &exportable, ReuseKey: &reuse}
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		kty := azcertificates.KeyTypeRSA
		size := int32(pub.N.BitLen())
		kp.KeyType, kp.KeySize = &kty, &size
	case *ecdsa.PublicKey:
		kty := azcertificates.KeyTypeEC
		var crv azcertificates.CurveName
		switch pub.Curve {
		case elliptic.P256():
			crv = azcertificates.CurveNameP256
		case elliptic.P384():
			crv = azcertificates.CurveNameP384
		case elliptic.P521():
			crv = azcertificates.CurveNameP521
		default:
			return nil, fmt.Errorf("%w: unsupported elliptic curve", plugin.ErrPermanent)
		}
		kp.KeyType, kp.Curve = &kty, &crv
	default:
		return nil, fmt.Errorf("%w: Key Vault imports RSA and EC keys only", plugin.ErrPermanent)
	}
	return kp, nil
}

// resolveKey returns the private key for leaf from key material: a Key
// Vault secret id (read here, so the key does not pass through the
// connector), a PKCS#8 PEM key, or a PKCS#12 bundle. Errors never include
// key bytes or secret values.
func (t *Target) resolveKey(ctx context.Context, km plugin.KeyMaterial, leaf *x509.Certificate) (crypto.Signer, error) {
	var key any
	switch km.Format {
	case plugin.KeyFormatVaultRef:
		ref, err := parseSecretRef(km.Ref)
		if err != nil {
			return nil, err
		}
		c, err := t.ks.clientsFor(ref.vaultURL)
		if err != nil {
			return nil, err
		}
		resp, err := c.secrets.GetSecret(ctx, ref.name, ref.version, nil)
		if err != nil {
			return nil, classify(opGetSecret, ref.name, err)
		}
		key, err = secretKey(deref(resp.ContentType), deref(resp.Value))
		if err != nil {
			return nil, fmt.Errorf("%w: the secret %s: %v", plugin.ErrPermanent, ref, err)
		}
		if key == nil {
			return nil, fmt.Errorf("%w: the secret %s holds no private key: the key is not exportable in Key Vault, so it cannot be imported elsewhere or again", plugin.ErrPermanent, ref)
		}
	case plugin.KeyFormatPEM:
		b, _ := pem.Decode(km.Data)
		if b == nil || b.Type != "PRIVATE KEY" {
			return nil, fmt.Errorf("%w: the key is not a PKCS#8 PEM block", plugin.ErrInvalid)
		}
		k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: the PEM key does not parse", plugin.ErrInvalid)
		}
		key = k
	case plugin.KeyFormatPFX:
		k, _, _, err := pkcs12.DecodeChain(km.Data, km.Password)
		if err != nil || k == nil {
			return nil, fmt.Errorf("%w: the PKCS#12 bundle holds no readable private key", plugin.ErrInvalid)
		}
		key = k
	default:
		return nil, fmt.Errorf("%w: the key is needed to import the certificate (got format %q)", plugin.ErrPermanent, km.Format)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported private key type", plugin.ErrPermanent)
	}
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || string(spki) != string(leaf.RawSubjectPublicKeyInfo) {
		return nil, fmt.Errorf("%w: the private key does not belong to certificate %s", plugin.ErrPermanent, serialOf(leaf))
	}
	return signer, nil
}

// secretKey reads the private key from a certificate's secret, or returns
// nil when the secret holds none (a key that cannot be exported).
func secretKey(contentType, value string) (any, error) {
	switch strings.ToLower(contentType) {
	case contentTypePKCS12:
		pfx, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, errors.New("not base64 PKCS#12")
		}
		key, _, _, err := pkcs12.DecodeChain(pfx, "")
		if err != nil || key == nil {
			if _, terr := pkcs12.DecodeTrustStore(pfx, ""); terr == nil {
				return nil, nil
			}
			return nil, errors.New("not a readable PKCS#12 bundle")
		}
		return key, nil
	case contentTypePEM:
		key, _, _, err := parsePEMBundle(value)
		return key, err
	}
	return nil, fmt.Errorf("content type %q is not %s or %s", contentType, contentTypePKCS12, contentTypePEM)
}

// parseCertAndChain parses the leaf and intermediates.
func parseCertAndChain(certPEM, chainPEM string) (*x509.Certificate, []*x509.Certificate, error) {
	leafDER, err := pemCerts(certPEM)
	if err != nil || len(leafDER) != 1 {
		return nil, nil, fmt.Errorf("%w: cert_pem must hold exactly one certificate", plugin.ErrInvalid)
	}
	leaf, err := x509.ParseCertificate(leafDER[0])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: cert_pem: %v", plugin.ErrInvalid, err)
	}
	chainDER, err := pemCerts(chainPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: chain_pem: %v", plugin.ErrInvalid, err)
	}
	chain := make([]*x509.Certificate, 0, len(chainDER))
	for _, der := range chainDER {
		c, _ := x509.ParseCertificate(der) // pemCerts parsed it already
		chain = append(chain, c)
	}
	return leaf, chain, nil
}

func sameSerial(a, b string) bool {
	return strings.EqualFold(strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0"))
}

func padHex(s string) string {
	if len(s)%2 == 1 {
		return "0" + s
	}
	return s
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
