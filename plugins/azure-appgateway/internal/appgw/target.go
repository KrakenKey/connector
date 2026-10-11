// Package appgw is a KrakenKey connector target that points an Azure
// Application Gateway v2 SSL certificate entry at a specific Key Vault
// secret version.
//
// Pinning a version makes the change take effect with the gateway update
// itself: any gateway update makes the gateway read Key Vault again, while
// its four-hourly poll only matters for versionless secret IDs. Rolling back
// is pointing the entry at the previous version again.
package appgw

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	armnetwork "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/hashicorp/go-hclog"

	"github.com/krakenkey/connector/pkg/plugin"
)

// Defaults for Options.
const (
	DefaultPollFrequency   = 15 * time.Second
	DefaultMaxAttempts     = 3
	DefaultReportReserve   = 20 * time.Second
	DefaultVerifyWindow    = 10 * time.Minute
	telemetryApplicationID = "krakenkey-connector"
)

// Options configure a Target. The zero value uses DefaultAzureCredential
// against Azure's public cloud.
type Options struct {
	// Credential overrides azidentity.DefaultAzureCredential.
	Credential azcore.TokenCredential
	// ClientOptions overrides the ARM client options, for example to point
	// the client at another endpoint in tests.
	ClientOptions *arm.ClientOptions
	// PollFrequency is the wait between long-running operation polls when
	// Azure sends no Retry-After. Default 15s.
	PollFrequency time.Duration
	// MaxAttempts bounds how often an update is tried when the gateway
	// changed between read and write (HTTP 412). Default 3.
	MaxAttempts int
	// ReportReserve is the time kept back from the call deadline while
	// polling, so the gateway can be read again to report what state it is
	// in when the operation does not finish in time. Default 20s.
	ReportReserve time.Duration
	// Logger receives warnings the protocol has no field for. Default: none.
	Logger hclog.Logger
}

// Target implements plugin.Target for Application Gateway.
type Target struct {
	plugin.UnimplementedTarget

	opts Options

	credOnce sync.Once
	cred     azcore.TokenCredential
	credErr  error

	mu      sync.Mutex
	clients map[string]*armnetwork.ApplicationGatewaysClient
}

var _ plugin.Target = (*Target)(nil)

// New returns a Target.
func New(opts Options) *Target {
	if opts.PollFrequency <= 0 {
		opts.PollFrequency = DefaultPollFrequency
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = DefaultMaxAttempts
	}
	if opts.ReportReserve <= 0 {
		opts.ReportReserve = DefaultReportReserve
	}
	if opts.Logger == nil {
		opts.Logger = hclog.NewNullLogger()
	}
	return &Target{opts: opts, clients: map[string]*armnetwork.ApplicationGatewaysClient{}}
}

// Describe reports the target's capabilities.
func (t *Target) Describe(context.Context) (plugin.TargetCapabilities, error) {
	return plugin.TargetCapabilities{
		Accepts: []plugin.KeyFormat{plugin.KeyFormatVaultRef},
		// Application Gateway reads the PFX from the Key Vault secret, so
		// the Key Vault certificate must have an exportable key.
		NeedsExportableKey: true,
		SupportsRollback:   true,
		// Microsoft documents RSA listener certificates. ECDSA is not
		// documented for Application Gateway v2 listeners, so it is not
		// offered here.
		KeyTypes:            []plugin.KeyType{plugin.KeyTypeRSA2048, plugin.KeyTypeRSA3072, plugin.KeyTypeRSA4096},
		DefaultVerifyWindow: DefaultVerifyWindow,
	}, nil
}

// Validate reads the gateway and reports configuration problems. A 403 is
// returned as an error wrapping ErrPermanent that names the permission.
func (t *Target) Validate(ctx context.Context, req plugin.TargetValidateRequest) ([]string, error) {
	cfg, err := ParseConfig(req.Config)
	if err != nil {
		return []string{strings.TrimPrefix(err.Error(), plugin.ErrPermanent.Error()+": ")}, nil
	}
	client, err := t.client(cfg.SubscriptionID)
	if err != nil {
		return nil, err
	}
	resp, err := client.Get(ctx, cfg.ResourceGroup, cfg.Gateway, nil)
	if err != nil {
		if isStatus(err, http.StatusNotFound) {
			return []string{fmt.Sprintf("application gateway %s/%s not found in subscription %s", cfg.ResourceGroup, cfg.Gateway, cfg.SubscriptionID)}, nil
		}
		return nil, classify(opRead, cfg, err)
	}
	gw := resp.ApplicationGateway
	var problems []string
	if p := skuProblem(&gw); p != "" {
		problems = append(problems, p)
	}
	if p := identityProblem(&gw); p != "" {
		problems = append(problems, p)
	}
	cur := readSlot(&gw, cfg.SSLCertificate)
	switch cur.kind {
	case slotAbsent:
		problems = append(problems, missingEntryProblem(cfg.SSLCertificate))
	case slotInline:
		if !cfg.ReplaceUploadedCertificate {
			problems = append(problems, uploadedProblem(cfg.SSLCertificate))
		}
	case slotKeyVault:
		if id, err := ParseSecretID(cur.secretID); err == nil && !id.Versioned() {
			// Not a problem: the first activation pins a version. But if this
			// is the secret the key store writes to, it already resolves to
			// the new version, so that first activation cannot be rolled back.
			t.opts.Logger.Warn("ssl certificate uses a versionless Key Vault secret ID; if the key store writes to the same secret, "+
				"the first activation cannot be rolled back", "gateway", cfg.Gateway, "ssl_certificate", cfg.SSLCertificate, "secret_id", cur.secretID)
		}
	}
	return problems, nil
}

// Current returns the serial of the leaf in the entry's publicCertData,
// which the gateway fills in from the certificate it loaded. Empty when the
// entry is missing or the gateway reports no certificate data.
func (t *Target) Current(ctx context.Context, req plugin.CurrentRequest) (string, error) {
	cfg, err := ParseConfig(req.Config)
	if err != nil {
		return "", err
	}
	client, err := t.client(cfg.SubscriptionID)
	if err != nil {
		return "", err
	}
	resp, err := client.Get(ctx, cfg.ResourceGroup, cfg.Gateway, nil)
	if err != nil {
		return "", classify(opRead, cfg, err)
	}
	_, c := findCert(&resp.ApplicationGateway, cfg.SSLCertificate)
	if c == nil || c.Properties == nil || c.Properties.PublicCertData == nil || *c.Properties.PublicCertData == "" {
		return "", nil
	}
	serial, err := leafSerial(*c.Properties.PublicCertData)
	if err != nil {
		// "Cannot tell" is not an error in the protocol.
		return "", nil
	}
	return serial, nil
}

// Stage checks the Key Vault reference and returns it as the staged ref.
// The gateway is not touched.
func (t *Target) Stage(_ context.Context, req plugin.StageRequest) (string, error) {
	if _, err := ParseConfig(req.Config); err != nil {
		return "", err
	}
	if req.Key.Format != plugin.KeyFormatVaultRef {
		return "", fmt.Errorf("%w: azure-appgateway accepts only a Key Vault reference (vault_ref), got %q", plugin.ErrPermanent, req.Key.Format)
	}
	id, err := ParseSecretID(req.Key.Ref)
	if err != nil {
		return "", fmt.Errorf("%w: key store reference: %v", plugin.ErrPermanent, err)
	}
	if !id.Versioned() {
		return "", fmt.Errorf("%w: key store reference %s has no secret version; the gateway must be pinned to a version so the change is immediate and can be rolled back",
			plugin.ErrPermanent, id)
	}
	return id.String(), nil
}

// Activate points the entry at the staged secret version and returns a
// previous ref recording what the entry held before and what it installed.
// When what was there before cannot be put back, the previous ref says so
// and Rollback refuses it.
func (t *Target) Activate(ctx context.Context, req plugin.ActivateRequest) (string, error) {
	cfg, err := ParseConfig(req.Config)
	if err != nil {
		return "", err
	}
	id, err := ParseSecretID(req.StagedRef)
	if err != nil || !id.Versioned() {
		return "", fmt.Errorf("%w: staged ref is not a versioned Key Vault secret ID from Stage", plugin.ErrInvalid)
	}
	want := keyVaultSlot(id.String())
	before, err := t.transition(ctx, cfg, want, nil, true)
	if err != nil {
		return "", err
	}
	ref := previousRef{V: 1, Over: want.secretID}
	switch {
	case before.equal(want):
		ref.Unrestorable = reasonAlreadyActive
		t.opts.Logger.Warn("the gateway already pointed at the staged secret version; what was live before is unknown, so this activation cannot be rolled back",
			"gateway", cfg.Gateway, "ssl_certificate", cfg.SSLCertificate, "secret_id", want.secretID)
	case before.kind == slotInline:
		ref.Unrestorable = reasonUploaded
	case sameSecret(before.secretID, id):
		ref.Unrestorable = reasonVersionlessSameSecret
		t.opts.Logger.Warn("the gateway used a versionless ID of the same secret, which now resolves to the new version; this activation cannot be rolled back",
			"gateway", cfg.Gateway, "ssl_certificate", cfg.SSLCertificate, "previous_secret_id", before.secretID)
	default:
		ref.Restore = before.secretID
	}
	return ref.encode(), nil
}

// Rollback puts back the secret ID the entry held before Activate, exactly
// as it was, provided the gateway still shows what Activate installed. If
// someone changed the entry since, it refuses rather than overwrite that.
func (t *Target) Rollback(ctx context.Context, req plugin.RollbackRequest) error {
	cfg, err := ParseConfig(req.Config)
	if err != nil {
		return err
	}
	ref, err := parsePreviousRef(req.PreviousRef)
	if err != nil {
		return err
	}
	if ref.Unrestorable != "" {
		return unrestorableError(ref.Unrestorable)
	}
	expect := keyVaultSlot(ref.Over)
	_, err = t.transition(ctx, cfg, keyVaultSlot(ref.Restore), &expect, false)
	return err
}

// Discard has nothing to delete: Stage creates nothing.
func (t *Target) Discard(context.Context, plugin.DiscardRequest) error { return nil }

// transition points the configured entry at want and returns what the
// entry held when it was first read. It reads the gateway, changes the
// model and writes it back with If-Match on the ETag it read, reading again
// and retrying when the gateway changed in between (HTTP 412). If the entry
// already shows want, nothing is written.
//
// expect, if set, is what the entry must show before it is changed;
// anything else is refused.
//
// If the long-running update fails or its outcome is unknown, the gateway
// is read again; when it shows the new state and revert is set, the old
// state is written back so a failed Activate leaves what was live before.
func (t *Target) transition(ctx context.Context, cfg Config, want slot, expect *slot, revert bool) (slot, error) {
	client, err := t.client(cfg.SubscriptionID)
	if err != nil {
		return slot{}, err
	}
	var first *slot
	for attempt := 1; ; attempt++ {
		resp, err := client.Get(ctx, cfg.ResourceGroup, cfg.Gateway, nil)
		if err != nil {
			return slot{}, classify(opRead, cfg, err)
		}
		gw := resp.ApplicationGateway
		if p := skuProblem(&gw); p != "" {
			return slot{}, fmt.Errorf("%w: %s", plugin.ErrPermanent, p)
		}
		if p := identityProblem(&gw); p != "" {
			return slot{}, fmt.Errorf("%w: %s", plugin.ErrPermanent, p)
		}
		cur := readSlot(&gw, cfg.SSLCertificate)
		if first == nil {
			first = &cur
		}
		switch {
		case cur.equal(want):
			// Already there (on a retry: someone else, or a write of ours
			// that went through). Report the state from the first read.
			return *first, nil
		case cur.kind == slotAbsent:
			return slot{}, missingEntryError(cfg.SSLCertificate)
		case expect != nil && !cur.equal(*expect):
			return slot{}, fmt.Errorf("%w: ssl certificate %q now shows %s, not %s as left by the activation; it was changed since, so it is not overwritten",
				plugin.ErrPermanent, cfg.SSLCertificate, cur, *expect)
		case !cur.equal(*first):
			return slot{}, fmt.Errorf("%w: ssl certificate %q changed from %s to %s while it was being updated; nothing was changed",
				plugin.ErrUnavailable, cfg.SSLCertificate, *first, cur)
		case cur.kind == slotInline && !cfg.ReplaceUploadedCertificate:
			return slot{}, fmt.Errorf("%w: %s", plugin.ErrPermanent, uploadedProblem(cfg.SSLCertificate))
		}
		if err := writeSlot(&gw, cfg.SSLCertificate, want); err != nil {
			return slot{}, err
		}

		err = t.put(ctx, client, cfg, gw)
		switch {
		case err == nil:
			return *first, nil
		case errors.Is(err, errPreconditionFailed):
			if attempt < t.opts.MaxAttempts {
				continue
			}
			return slot{}, fmt.Errorf("%w: application gateway %s/%s changed while it was being updated, %d times in a row; nothing was changed",
				plugin.ErrUnavailable, cfg.ResourceGroup, cfg.Gateway, attempt)
		case errors.As(err, new(notStartedError)):
			// ARM refused the PUT, so the gateway is as it was.
			return slot{}, err
		default:
			return slot{}, t.afterFailedUpdate(ctx, client, cfg, *first, want, revert, err)
		}
	}
}

var errPreconditionFailed = errors.New("gateway changed since it was read (HTTP 412)")

// notStartedError is an update ARM refused outright, so nothing changed.
type notStartedError struct{ err error }

func (e notStartedError) Error() string { return e.err.Error() }
func (e notStartedError) Unwrap() error { return e.err }

// unknownOutcomeError is a PUT without a clear answer (a transport error,
// a timeout or a 408 or 5xx from the front door): ARM may or may not have
// accepted it.
type unknownOutcomeError struct{ err error }

func (e unknownOutcomeError) Error() string {
	return "the update request got no clear answer: " + describe(e.err)
}
func (e unknownOutcomeError) Unwrap() error { return e.err }

// put writes the gateway with If-Match and waits for the long-running
// operation. The PUT is sent once: the SDK's retries are off for it, since
// a retry after a lost response would be refused with 412 and hide that
// the first attempt went through. It returns errPreconditionFailed for a
// 412, a notStartedError (wrapping a plugin error kind) for any other 4xx
// except 408, an unknownOutcomeError when the PUT got no clear answer, and
// otherwise an error describing a failed or unfinished operation.
func (t *Target) put(ctx context.Context, client *armnetwork.ApplicationGatewaysClient, cfg Config, gw armnetwork.ApplicationGateway) error {
	putCtx := policy.WithRetryOptions(ctx, policy.RetryOptions{MaxRetries: -1})
	if gw.Etag != nil && *gw.Etag != "" {
		putCtx = policy.WithHTTPHeader(putCtx, http.Header{"If-Match": []string{*gw.Etag}})
	}
	poller, err := client.BeginCreateOrUpdate(putCtx, cfg.ResourceGroup, cfg.Gateway, gw, nil)
	if err != nil {
		ae, ok := responseError(err)
		switch {
		case ok && ae.Status == http.StatusPreconditionFailed:
			return errPreconditionFailed
		case ok && ae.Status >= 400 && ae.Status < 500 && ae.Status != http.StatusRequestTimeout:
			return notStartedError{classify(opUpdate, cfg, err)}
		default:
			return unknownOutcomeError{err}
		}
	}
	return t.wait(ctx, poller)
}

// errStillRunning means the operation did not finish before the deadline.
var errStillRunning = errors.New("the update is still running")

// wait polls until the operation finishes, keeping ReportReserve of the
// deadline back so the caller can still read the gateway afterwards.
func (t *Target) wait(ctx context.Context, poller *runtime.Poller[armnetwork.ApplicationGatewaysClientCreateOrUpdateResponse]) error {
	pollCtx := ctx
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) > 2*t.opts.ReportReserve {
		var cancel context.CancelFunc
		pollCtx, cancel = context.WithDeadline(ctx, dl.Add(-t.opts.ReportReserve))
		defer cancel()
	}
	pollErrors := 0
	for {
		resp, err := poller.Poll(pollCtx)
		if err != nil {
			if pollCtx.Err() != nil {
				return errStillRunning
			}
			// A failed status poll says nothing about the operation; keep
			// asking a few times before giving up.
			if pollErrors++; pollErrors >= maxPollErrors || !transientPollError(err) {
				return pollError{err}
			}
		} else {
			pollErrors = 0
		}
		if poller.Done() {
			_, err := poller.Result(pollCtx)
			if err != nil && pollCtx.Err() != nil {
				return errStillRunning
			}
			return err
		}
		delay := t.opts.PollFrequency
		if ra := retryAfter(resp); ra > 0 && ra < time.Minute {
			delay = ra
		}
		timer := time.NewTimer(delay)
		select {
		case <-pollCtx.Done():
			timer.Stop()
			return errStillRunning
		case <-timer.C:
		}
	}
}

const maxPollErrors = 5

// pollError is a status poll that kept failing; the operation's outcome is
// unknown.
type pollError struct{ err error }

func (e pollError) Error() string { return "checking the update's status failed: " + describe(e.err) }
func (e pollError) Unwrap() error { return e.err }

func transientPollError(err error) bool {
	ae, ok := responseError(err)
	return !ok || ae.Status == http.StatusTooManyRequests || ae.Status >= 500
}

// describe summarizes an ARM error in one line.
func describe(err error) string {
	if ae, ok := responseError(err); ok {
		return ae.String()
	}
	if msg, _, ok := credentialError(err); ok {
		return msg
	}
	return scrub(oneLine(err.Error()))
}

func retryAfter(resp *http.Response) time.Duration {
	if resp == nil {
		return 0
	}
	var secs int
	if _, err := fmt.Sscanf(resp.Header.Get("Retry-After"), "%d", &secs); err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// afterFailedUpdate reads the gateway after an update that failed or did
// not finish, and reports what state the entry is in. When the failed
// update left the new state in place and revert is set, it writes the old
// state back once.
func (t *Target) afterFailedUpdate(ctx context.Context, client *armnetwork.ApplicationGatewaysClient, cfg Config,
	before, want slot, revert bool, opErr error,
) error {
	where := fmt.Sprintf("application gateway %s/%s", cfg.ResourceGroup, cfg.Gateway)
	var cause string
	switch {
	case errors.Is(opErr, errStillRunning):
		cause = "the update did not finish before the call deadline and is still running in Azure"
	case errors.As(opErr, new(pollError)), errors.As(opErr, new(unknownOutcomeError)):
		cause = opErr.Error()
	default:
		cause = "the update failed: " + describe(opErr)
	}

	if ctx.Err() != nil {
		return fmt.Errorf("%w: %s: %s; the gateway could not be read again to check its state", plugin.ErrUnavailable, where, cause)
	}
	resp, err := client.Get(ctx, cfg.ResourceGroup, cfg.Gateway, nil)
	if err != nil {
		return fmt.Errorf("%w: %s: %s; reading the gateway afterwards failed too: %v", plugin.ErrUnavailable, where, cause, classify(opRead, cfg, err))
	}
	gw := resp.ApplicationGateway
	now := readSlot(&gw, cfg.SSLCertificate)
	state := provisioningState(&gw)

	switch {
	case errors.Is(opErr, errStillRunning), state == "Updating":
		if now.equal(want) {
			return fmt.Errorf("%w: %s: %s; the gateway model already shows %s (provisioning state %s) and is likely to switch to it",
				plugin.ErrUnavailable, where, cause, want, state)
		}
		return fmt.Errorf("%w: %s: %s; the gateway still shows %s (provisioning state %s)", plugin.ErrUnavailable, where, cause, now, state)

	case now.equal(before):
		return fmt.Errorf("%w: %s: %s; the gateway still shows %s, nothing was changed", plugin.ErrUnavailable, where, cause, now)

	case now.equal(want) && revert:
		if before.kind == slotInline {
			return fmt.Errorf("%w: %s: %s; the gateway now shows %s (provisioning state %s) and the uploaded certificate it had before cannot be restored",
				plugin.ErrPermanent, where, cause, want, state)
		}
		if err := writeSlot(&gw, cfg.SSLCertificate, before); err != nil {
			return fmt.Errorf("%w: %s: %s; restoring %s failed: %v", plugin.ErrUnavailable, where, cause, before, err)
		}
		if err := t.put(ctx, client, cfg, gw); err != nil {
			return fmt.Errorf("%w: %s: %s; the gateway shows %s (provisioning state %s), and restoring %s failed: %v",
				plugin.ErrUnavailable, where, cause, want, state, before, err)
		}
		return fmt.Errorf("%w: %s: %s; restored %s", plugin.ErrUnavailable, where, cause, before)

	default:
		return fmt.Errorf("%w: %s: %s; the gateway now shows %s (provisioning state %s)", plugin.ErrUnavailable, where, cause, now, state)
	}
}

func provisioningState(gw *armnetwork.ApplicationGateway) string {
	if gw.Properties == nil || gw.Properties.ProvisioningState == nil {
		return "unknown"
	}
	return string(*gw.Properties.ProvisioningState)
}

// skuProblem reports a gateway that is not v2. Key Vault certificates are
// supported on v2 gateways only.
func skuProblem(gw *armnetwork.ApplicationGateway) string {
	var tier, name string
	if gw.Properties != nil && gw.Properties.SKU != nil {
		if gw.Properties.SKU.Tier != nil {
			tier = string(*gw.Properties.SKU.Tier)
		}
		if gw.Properties.SKU.Name != nil {
			name = string(*gw.Properties.SKU.Name)
		}
	}
	sku := tier
	if sku == "" {
		sku = name
	}
	if strings.HasSuffix(strings.ToLower(sku), "_v2") {
		return ""
	}
	if sku == "" {
		sku = "unknown"
	}
	return fmt.Sprintf("the gateway's SKU is %s; Key Vault certificates need a v2 SKU (Standard_v2 or WAF_v2)", sku)
}

// identityProblem reports a gateway without a user-assigned managed
// identity, which it needs to read certificates from Key Vault.
func identityProblem(gw *armnetwork.ApplicationGateway) string {
	id := gw.Identity
	// ARM returns the type in whatever case it was set with ("userAssigned"
	// from the Azure CLI, "UserAssigned" from templates), so compare
	// case-insensitively.
	if id != nil && id.Type != nil &&
		strings.Contains(strings.ToLower(string(*id.Type)), strings.ToLower(string(armnetwork.ResourceIdentityTypeUserAssigned))) &&
		len(id.UserAssignedIdentities) > 0 {
		return ""
	}
	return "the gateway has no user-assigned managed identity; it needs one with the Key Vault Secrets User role " +
		"(or a Get secrets access policy) on the vault to read certificates"
}

// client returns an Application Gateways client for the subscription.
func (t *Target) client(subscriptionID string) (*armnetwork.ApplicationGatewaysClient, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.clients[subscriptionID]; ok {
		return c, nil
	}
	cred, err := t.credential()
	if err != nil {
		return nil, err
	}
	var opts arm.ClientOptions
	if t.opts.ClientOptions != nil {
		opts = *t.opts.ClientOptions.Clone()
	}
	// The gateway exists, so Microsoft.Network is registered; never try to
	// register resource providers on the user's subscription.
	opts.DisableRPRegistration = true
	if opts.Telemetry.ApplicationID == "" {
		opts.Telemetry.ApplicationID = telemetryApplicationID
	}
	c, err := armnetwork.NewApplicationGatewaysClient(subscriptionID, cred, &opts)
	if err != nil {
		return nil, fmt.Errorf("%w: creating the Azure client: %v", plugin.ErrPermanent, err)
	}
	t.clients[subscriptionID] = c
	return c, nil
}

func (t *Target) credential() (azcore.TokenCredential, error) {
	t.credOnce.Do(func() {
		if t.opts.Credential != nil {
			t.cred = t.opts.Credential
			return
		}
		t.cred, t.credErr = azidentity.NewDefaultAzureCredential(nil)
	})
	if t.credErr != nil {
		return nil, fmt.Errorf("%w: no usable Azure credential: %s", plugin.ErrPermanent, scrub(t.credErr.Error()))
	}
	return t.cred, nil
}
