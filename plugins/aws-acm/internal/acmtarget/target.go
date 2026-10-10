// Package acmtarget is a KrakenKey connector target that re-imports
// certificates into an existing AWS Certificate Manager (ACM) certificate.
//
// Re-importing keeps the certificate's ARN, so every service that uses it
// (load balancers, CloudFront, API Gateway and others) picks up the new
// certificate without any change on their side. ACM has no staging and
// never returns an imported private key, so Stage only checks the
// material, Activate re-imports it, and Rollback re-imports the previous
// certificate and key that the connector hands back
// (RollbackNeedsMaterial).
package acmtarget

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/krakenkey/connector/pkg/plugin"
)

// DefaultVerifyWindow is how long the connector keeps checking the
// endpoint after a re-import when the config does not say. Load balancers
// pick up a re-imported certificate within minutes; CloudFront can take
// longer, so set verify.window higher for distributions.
const DefaultVerifyWindow = 10 * time.Minute

// stagedTTL bounds how long checked material waits in memory for Activate.
// The connector activates right after staging, so anything older was
// abandoned.
const stagedTTL = time.Hour

// confirmTimeout bounds the DescribeCertificate call that checks whether an
// ImportCertificate with an unknown outcome went through.
const confirmTimeout = 30 * time.Second

// ACM is the part of the ACM API the target uses.
type ACM interface {
	DescribeCertificate(ctx context.Context, in *acm.DescribeCertificateInput, opts ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
	ImportCertificate(ctx context.Context, in *acm.ImportCertificateInput, opts ...func(*acm.Options)) (*acm.ImportCertificateOutput, error)
}

// Target re-imports certificates into ACM. Use New; the zero value is not
// usable.
type Target struct {
	plugin.UnimplementedTarget

	// LoadOptions and ClientOptions adjust how AWS clients are built, for
	// example to point them at a test endpoint with BaseEndpoint. Production
	// use leaves them empty: credentials and settings come from the default
	// chain (environment, shared config, web identity, ECS task role, EC2
	// instance profile).
	LoadOptions   []func(*awsconfig.LoadOptions) error
	ClientOptions []func(*acm.Options)
	// Now defaults to time.Now.
	Now func() time.Time

	mu      sync.Mutex
	clients map[string]ACM
	staged  map[string]*staged
}

// staged is checked material waiting for Activate. It lives only in this
// process's memory; the staged ref the connector stores is a random id.
type staged struct {
	arn string
	m   *material
	at  time.Time
}

var _ plugin.Target = (*Target)(nil)

// New returns a target that uses the default AWS credential chain.
func New() *Target {
	return &Target{clients: map[string]ACM{}, staged: map[string]*staged{}}
}

func (t *Target) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// client returns a cached ACM client for region.
func (t *Target) client(ctx context.Context, region string) (ACM, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.clients[region]; ok {
		return c, nil
	}
	opts := append([]func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}, t.LoadOptions...)
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: load AWS configuration: %v", plugin.ErrPermanent, err)
	}
	c := acm.NewFromConfig(cfg, t.ClientOptions...)
	t.clients[region] = c
	return c, nil
}

func (t *Target) describe(ctx context.Context, cfg Config) (*types.CertificateDetail, error) {
	c, err := t.client(ctx, cfg.Region)
	if err != nil {
		return nil, err
	}
	out, err := c.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: aws.String(cfg.CertificateARN)})
	if err != nil {
		return nil, mapErr("DescribeCertificate", cfg.CertificateARN, err)
	}
	if out.Certificate == nil {
		return nil, fmt.Errorf("%w: acm:DescribeCertificate on %s returned no certificate", plugin.ErrUnavailable, cfg.CertificateARN)
	}
	return out.Certificate, nil
}

func config(raw []byte) (Config, error) {
	cfg, err := parseConfig(raw)
	if err != nil {
		return cfg, fmt.Errorf("%w: %v", plugin.ErrPermanent, err)
	}
	return cfg, nil
}

// Describe reports a PEM target that needs the previous material to roll
// back.
func (t *Target) Describe(context.Context) (plugin.TargetCapabilities, error) {
	return plugin.TargetCapabilities{
		Accepts:               []plugin.KeyFormat{plugin.KeyFormatPEM},
		NeedsExportableKey:    true,
		SupportsRollback:      true,
		RollbackNeedsMaterial: true,
		// ACM imports all of these. Some services take fewer: CloudFront
		// (and edge-optimized API Gateway) has no ECDSA P-384, and API
		// Gateway regional domains take RSA up to 2048 bits. See README.
		KeyTypes: []plugin.KeyType{
			plugin.KeyTypeECDSAP256, plugin.KeyTypeECDSAP384,
			plugin.KeyTypeRSA2048, plugin.KeyTypeRSA3072, plugin.KeyTypeRSA4096,
		},
		DefaultVerifyWindow: DefaultVerifyWindow,
	}, nil
}

// Validate checks the settings and that the ACM certificate exists, is an
// imported certificate, and lives in the configured region. It changes
// nothing.
func (t *Target) Validate(ctx context.Context, req plugin.TargetValidateRequest) ([]string, error) {
	cfg, err := parseConfig(req.Config)
	if err != nil {
		return []string{err.Error()}, nil
	}
	d, err := t.describe(ctx, cfg)
	if errors.Is(err, errCertNotFound) {
		return []string{fmt.Sprintf("ACM certificate %s does not exist in %s", cfg.CertificateARN, cfg.Region)}, nil
	}
	if err != nil {
		return nil, err
	}
	var problems []string
	if p := typeProblem(d); p != "" {
		problems = append(problems, fmt.Sprintf("ACM certificate %s: %s", cfg.CertificateARN, p))
	}
	if got := aws.ToString(d.CertificateArn); got != "" && got != cfg.CertificateARN {
		problems = append(problems, fmt.Sprintf("ACM returned certificate %s for %s", got, cfg.CertificateARN))
	}
	return problems, nil
}

// Current returns the serial of the certificate ACM holds under the ARN.
func (t *Target) Current(ctx context.Context, req plugin.CurrentRequest) (string, error) {
	cfg, err := config(req.Config)
	if err != nil {
		return "", err
	}
	d, err := t.describe(ctx, cfg)
	if err != nil {
		return "", err
	}
	return acmSerial(aws.ToString(d.Serial)), nil
}

// Stage checks the certificate, chain and key, and that ACM will accept
// them as a replacement for the certificate under the ARN. ACM has no
// staging, so nothing changes in AWS; the material waits in memory for
// Activate.
func (t *Target) Stage(ctx context.Context, req plugin.StageRequest) (string, error) {
	cfg, err := config(req.Config)
	if err != nil {
		return "", err
	}
	if req.Key.Format != plugin.KeyFormatPEM || len(req.Key.Data) == 0 {
		return "", fmt.Errorf("%w: ACM needs the private key as PEM, got %s", plugin.ErrPermanent, req.Key.Format)
	}
	m, err := parseMaterial(req.CertPEM, req.ChainPEM, req.Key.Data, t.now())
	if err != nil {
		return "", fmt.Errorf("%w: %v", plugin.ErrPermanent, err)
	}
	if req.Serial != "" && hexSerial(req.Serial) != m.serial {
		m.wipe()
		return "", fmt.Errorf("%w: request serial %s does not match the certificate's serial %s", plugin.ErrInvalid, req.Serial, m.serial)
	}
	d, err := t.describe(ctx, cfg)
	if err != nil {
		m.wipe()
		return "", err
	}
	if p := replaceProblem(d, m.leaf); p != "" {
		m.wipe()
		return "", fmt.Errorf("%w: ACM certificate %s: %s", plugin.ErrPermanent, cfg.CertificateARN, p)
	}

	b := make([]byte, 12)
	_, _ = rand.Read(b)
	ref := "staged-" + hex.EncodeToString(b)
	t.mu.Lock()
	defer t.mu.Unlock()
	for r, s := range t.staged {
		if t.now().Sub(s.at) > stagedTTL {
			s.m.wipe()
			delete(t.staged, r)
		}
	}
	t.staged[ref] = &staged{arn: cfg.CertificateARN, m: m, at: t.now()}
	return ref, nil
}

func (t *Target) take(ref string) *staged {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.staged[ref]
	delete(t.staged, ref)
	return s
}

// Activate re-imports the staged certificate under the configured ARN and
// returns the serial ACM held before as the previous ref. Tags and service
// associations stay as they are. If it fails, ACM still holds the previous
// certificate: ImportCertificate either replaces it or does nothing.
func (t *Target) Activate(ctx context.Context, req plugin.ActivateRequest) (string, error) {
	cfg, err := config(req.Config)
	if err != nil {
		return "", err
	}
	s := t.take(req.StagedRef)
	if s == nil {
		return "", fmt.Errorf("%w: staged ref %q (staged material lives in the plugin's memory and is gone after a restart)", plugin.ErrNotFound, req.StagedRef)
	}
	defer s.m.wipe()
	if s.arn != cfg.CertificateARN {
		return "", fmt.Errorf("%w: staged for %s, but the target now points at %s", plugin.ErrPermanent, s.arn, cfg.CertificateARN)
	}
	d, err := t.describe(ctx, cfg)
	if err != nil {
		return "", err
	}
	if p := typeProblem(d); p != "" {
		return "", fmt.Errorf("%w: ACM certificate %s: %s", plugin.ErrPermanent, cfg.CertificateARN, p)
	}
	prev := acmSerial(aws.ToString(d.Serial))
	if err := t.importCert(ctx, cfg, s.m); err != nil {
		return "", err
	}
	return prev, nil
}

// Rollback re-imports the certificate that was live before the Activate
// that returned previousRef (its serial). ACM never returns an imported
// private key, so this needs the previous certificate and key from the
// connector.
func (t *Target) Rollback(ctx context.Context, req plugin.RollbackRequest) error {
	cfg, err := config(req.Config)
	if err != nil {
		return err
	}
	if req.PreviousRef == "" {
		return fmt.Errorf("%w: no previous certificate was recorded, and ACM cannot remove an imported certificate that services may use", plugin.ErrPermanent)
	}
	prev := hexSerial(req.PreviousRef)
	if prev == "" {
		return fmt.Errorf("%w: previous ref %q is not a certificate serial", plugin.ErrInvalid, req.PreviousRef)
	}
	d, err := t.describe(ctx, cfg)
	if err != nil {
		return err
	}
	if acmSerial(aws.ToString(d.Serial)) == prev {
		return nil // already back
	}
	if !req.HasPreviousMaterial() {
		return fmt.Errorf("%w: cannot restore certificate %s: ACM does not return imported private keys, and the connector did not hand back the previous certificate and key",
			plugin.ErrPermanent, prev)
	}
	if req.PreviousKey.Format != plugin.KeyFormatPEM || len(req.PreviousKey.Data) == 0 {
		return fmt.Errorf("%w: ACM needs the previous private key as PEM, got %s", plugin.ErrPermanent, req.PreviousKey.Format)
	}
	m, err := parseMaterial(req.PreviousCertPEM, req.PreviousChainPEM, req.PreviousKey.Data, t.now())
	if err != nil {
		return fmt.Errorf("%w: previous certificate %s: %v", plugin.ErrPermanent, prev, err)
	}
	defer m.wipe()
	if m.serial != prev || (req.PreviousSerial != "" && hexSerial(req.PreviousSerial) != prev) {
		return fmt.Errorf("%w: was handed certificate %s, but %s was live before", plugin.ErrPermanent, m.serial, prev)
	}
	if p := typeProblem(d); p != "" {
		return fmt.Errorf("%w: ACM certificate %s: %s", plugin.ErrPermanent, cfg.CertificateARN, p)
	}
	return t.importCert(ctx, cfg, m)
}

// Discard drops staged material. Unknown refs are fine.
func (t *Target) Discard(_ context.Context, req plugin.DiscardRequest) error {
	if s := t.take(req.StagedRef); s != nil {
		s.m.wipe()
	}
	return nil
}

// importCert re-imports m under the configured ARN. Tags are not passed:
// ACM refuses them on reimport and keeps the existing ones. When the
// outcome is unknown (no answer from ACM), it asks ACM which certificate
// it holds now, so a re-import that went through is not reported as a
// failure.
func (t *Target) importCert(ctx context.Context, cfg Config, m *material) error {
	c, err := t.client(ctx, cfg.Region)
	if err != nil {
		return err
	}
	in := &acm.ImportCertificateInput{
		CertificateArn: aws.String(cfg.CertificateARN),
		Certificate:    m.certPEM,
		PrivateKey:     m.keyPEM,
	}
	if len(m.chainPEM) > 0 {
		in.CertificateChain = m.chainPEM
	}
	out, err := c.ImportCertificate(ctx, in)
	if err != nil {
		if !isAPIError(err) && t.confirmImported(ctx, cfg, m.serial) {
			return nil
		}
		return mapErr("ImportCertificate", cfg.CertificateARN, err)
	}
	if got := aws.ToString(out.CertificateArn); got != "" && got != cfg.CertificateARN {
		return fmt.Errorf("%w: ACM imported into %s instead of %s", plugin.ErrPermanent, got, cfg.CertificateARN)
	}
	return nil
}

// confirmImported reports whether ACM holds serial under the ARN now. It
// runs with its own short deadline so it also works after the caller's
// context ran out.
func (t *Target) confirmImported(ctx context.Context, cfg Config, serial string) bool {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), confirmTimeout)
	defer cancel()
	d, err := t.describe(cctx, cfg)
	return err == nil && acmSerial(aws.ToString(d.Serial)) == serial
}
