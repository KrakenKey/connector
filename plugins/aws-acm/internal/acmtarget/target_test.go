package acmtarget

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/acm"

	"github.com/krakenkey/connector/pkg/plugin"
	"github.com/krakenkey/connector/plugins/aws-acm/internal/fakeacm"
	"github.com/krakenkey/connector/plugins/aws-acm/internal/testcert"
)

var names = []string{"api.example.com", "www.example.com"}

type env struct {
	t    *testing.T
	acm  *fakeacm.Server
	ca   *testcert.CA
	tg   *Target
	arn  string
	cfg  json.RawMessage
	orig testcert.Leaf
}

// testTarget returns a target that talks to endpoint with fixed
// credentials and fast retries.
func testTarget(endpoint string) *Target {
	tg := New()
	tg.LoadOptions = []func(*awsconfig.LoadOptions) error{
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("AKIDTEST", "secret", "")),
		awsconfig.WithRetryer(func() aws.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.MaxAttempts = 2
				o.MaxBackoff = 10 * time.Millisecond
			})
		}),
	}
	tg.ClientOptions = []func(*acm.Options){func(o *acm.Options) { o.BaseEndpoint = aws.String(endpoint) }}
	return tg
}

// setup imports an ECDSA P-256 certificate into a fake ACM and points a
// target at it.
func setup(t *testing.T) *env {
	t.Helper()
	srv := fakeacm.New()
	t.Cleanup(srv.Close)
	e := &env{t: t, acm: srv, ca: testcert.NewCA(t)}
	e.orig = e.ca.Issue(t, names, testcert.Options{})
	arn, err := srv.Import(e.orig.CertPEM, e.ca.IntermediatePEM, e.orig.KeyPEM, map[string]string{"team": "web"})
	if err != nil {
		t.Fatal(err)
	}
	e.arn = arn
	e.cfg = cfgFor(srv.Region, arn)
	e.tg = testTarget(srv.URL)
	return e
}

func cfgFor(region, arn string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"region":%q,"certificate_arn":%q}`, region, arn))
}

func (e *env) stageReq(l testcert.Leaf) plugin.StageRequest {
	return plugin.StageRequest{
		Config: e.cfg, CertificateID: "7", Label: "alb",
		CertPEM: l.CertPEM, ChainPEM: e.ca.IntermediatePEM, FullChainPEM: l.CertPEM + e.ca.IntermediatePEM,
		Key:    plugin.KeyMaterial{Format: plugin.KeyFormatPEM, Data: l.KeyPEM},
		Serial: l.Serial,
	}
}

func (e *env) current() string {
	e.t.Helper()
	s, err := e.tg.Current(context.Background(), plugin.CurrentRequest{Config: e.cfg})
	if err != nil {
		e.t.Fatalf("Current: %v", err)
	}
	return s
}

// deploy stages and activates l and returns the previous ref.
func (e *env) deploy(l testcert.Leaf) string {
	e.t.Helper()
	ctx := context.Background()
	ref, err := e.tg.Stage(ctx, e.stageReq(l))
	if err != nil {
		e.t.Fatalf("Stage: %v", err)
	}
	prev, err := e.tg.Activate(ctx, plugin.ActivateRequest{Config: e.cfg, StagedRef: ref})
	if err != nil {
		e.t.Fatalf("Activate: %v", err)
	}
	return prev
}

func (e *env) rollbackReq(prevRef string, l *testcert.Leaf) plugin.RollbackRequest {
	req := plugin.RollbackRequest{Config: e.cfg, PreviousRef: prevRef, CertificateID: "7", Label: "alb"}
	if l != nil {
		req.PreviousCertPEM, req.PreviousChainPEM = l.CertPEM, e.ca.IntermediatePEM
		req.PreviousFullChainPEM = l.CertPEM + e.ca.IntermediatePEM
		req.PreviousKey = plugin.KeyMaterial{Format: plugin.KeyFormatPEM, Data: l.KeyPEM}
		req.PreviousSerial = l.Serial
	}
	return req
}

func countCalls(calls []string, op string) int {
	n := 0
	for _, c := range calls {
		if c == op {
			n++
		}
	}
	return n
}

func TestParseConfig(t *testing.T) {
	good := "arn:aws:acm:eu-west-1:123456789012:certificate/abc"
	cases := []struct {
		raw  string
		want string // substring of the error, "" for success
	}{
		{fmt.Sprintf(`{"region":"eu-west-1","certificate_arn":%q}`, good), ""},
		{fmt.Sprintf(`{"region":" eu-west-1 ","certificate_arn":" %s "}`, good), ""},
		{`{}`, "region is required; certificate_arn is required"},
		{``, "region is required"},
		{fmt.Sprintf(`{"certificate_arn":%q}`, good), "region is required"},
		{`{"region":"eu-west-1"}`, "certificate_arn is required"},
		{`{"region":"eu-west-1","certificate_arn":"arn:aws:iam::123456789012:server-certificate/x"}`, "not an ACM certificate ARN"},
		{`{"region":"eu-west-1","certificate_arn":"arn:aws:acm:eu-west-1:123456789012:certificate/"}`, "not an ACM certificate ARN"},
		{fmt.Sprintf(`{"region":"us-east-1","certificate_arn":%q}`, good), "does not match the region in certificate_arn (eu-west-1)"},
		{fmt.Sprintf(`{"region":"eu-west-1","certificate_arn":%q,"create_if_missing":true}`, good), "create_if_missing is not supported"},
		{fmt.Sprintf(`{"region":"eu-west-1","certificate_arn":%q,"tags":{"a":"b"}}`, good), `unknown field "tags"`},
		{`[1]`, "not a JSON object"},
		{`{"region":1}`, "settings"},
	}
	for _, c := range cases {
		cfg, err := parseConfig(json.RawMessage(c.raw))
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.raw, err)
		case c.want == "" && (cfg.Region != "eu-west-1" || cfg.CertificateARN != good):
			t.Errorf("%s: parsed %+v", c.raw, cfg)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: error %v, want %q", c.raw, err, c.want)
		}
	}
}

func TestDescribe(t *testing.T) {
	caps, err := New().Describe(plugin.WithCoreFeatures(context.Background(), plugin.CoreFeatures...))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(caps.Accepts, []plugin.KeyFormat{plugin.KeyFormatPEM}) || !caps.NeedsExportableKey ||
		!caps.SupportsRollback || !caps.RollbackNeedsMaterial || caps.PropagatesAsync ||
		caps.DefaultVerifyWindow != 10*time.Minute {
		t.Errorf("capabilities = %+v", caps)
	}
	for _, k := range []plugin.KeyType{plugin.KeyTypeRSA2048, plugin.KeyTypeECDSAP256, plugin.KeyTypeECDSAP384} {
		if !slices.Contains(caps.KeyTypes, k) {
			t.Errorf("key type %s missing", k)
		}
	}
}

func TestValidate(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	validate := func(cfg json.RawMessage) ([]string, error) {
		return e.tg.Validate(ctx, plugin.TargetValidateRequest{Config: cfg, CertificateID: "7", Label: "alb"})
	}

	if p, err := validate(e.cfg); err != nil || len(p) != 0 {
		t.Fatalf("Validate = %v, %v", p, err)
	}
	if p, err := validate(json.RawMessage(`{"region":"us-east-1"}`)); err != nil || len(p) != 1 || !strings.Contains(p[0], "certificate_arn is required") {
		t.Errorf("missing ARN: %v, %v", p, err)
	}
	if p, err := validate(cfgFor("us-east-1", e.acm.ARN("missing"))); err != nil || len(p) != 1 || !strings.Contains(p[0], "does not exist in us-east-1") {
		t.Errorf("missing certificate: %v, %v", p, err)
	}

	issued := e.acm.AddIssued("AMAZON_ISSUED", names)
	if p, err := validate(cfgFor("us-east-1", issued)); err != nil || len(p) != 1 || !strings.Contains(p[0], "AMAZON_ISSUED") {
		t.Errorf("AMAZON_ISSUED: %v, %v", p, err)
	}
	private := e.acm.AddIssued("PRIVATE", names)
	if p, err := validate(cfgFor("us-east-1", private)); err != nil || len(p) != 1 || !strings.Contains(p[0], "PRIVATE") {
		t.Errorf("PRIVATE: %v, %v", p, err)
	}

	e.acm.Fail("DescribeCertificate", fakeacm.Fault{Code: "AccessDeniedException", Message: "User is not authorized", Times: 1})
	_, err := validate(e.cfg)
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "allow acm:DescribeCertificate") || !strings.Contains(err.Error(), e.arn) {
		t.Errorf("access denied: %v", err)
	}
	e.acm.Fail("DescribeCertificate", fakeacm.Fault{Code: "ThrottlingException", Message: "Rate exceeded"})
	_, err = validate(e.cfg)
	if !errors.Is(err, plugin.ErrUnavailable) || plugin.IsPermanent(err) {
		t.Errorf("throttling: %v", err)
	}
}

func TestCurrent(t *testing.T) {
	e := setup(t)
	if got := e.current(); got != e.orig.Serial {
		t.Errorf("Current = %q, want %s", got, e.orig.Serial)
	}
	e.acm.Fail("DescribeCertificate", fakeacm.Fault{Code: "AccessDeniedException", Message: "no", Times: 1})
	if _, err := e.tg.Current(context.Background(), plugin.CurrentRequest{Config: e.cfg}); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("Current with access denied: %v", err)
	}
}

func TestDescribeRefusesAnOlderConnector(t *testing.T) {
	tg := New()
	_, err := tg.Describe(context.Background()) // no core features: a connector that predates them
	if !plugin.IsPermanent(err) || !strings.Contains(err.Error(), plugin.FeatureRollbackMaterial) {
		t.Errorf("Describe from an older connector: %v", err)
	}
	p, err := tg.Validate(context.Background(), plugin.TargetValidateRequest{Config: cfgFor("us-east-1", "arn:aws:acm:us-east-1:1:certificate/x")})
	if err != nil || len(p) != 1 || !strings.Contains(p[0], "upgrade the connector") {
		t.Errorf("Validate after a refused Describe = %v, %v", p, err)
	}
}

func TestNormalizeSerial(t *testing.T) {
	for in, want := range map[string]string{
		"00:a1:0b": "a10b", "0A:1B": "a1b", "0a": "a", "": "", "zz": "", " 01 ": "1",
		"07:71:71:f4:6b:e7:bf:63:87:e6:ad:3c:b2:0f:d0:5b": "77171f46be7bf6387e6ad3cb20fd05b",
		// Colon-free values are hex too, never decimal.
		"1234": "1234",
		"-12":  "",
	} {
		if got := acmSerial(in); got != want {
			t.Errorf("acmSerial(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"7d0fe6": "7d0fe6", "007d": "7d", "12": "12", "x": "", "": ""} {
		if got := hexSerial(in); got != want {
			t.Errorf("hexSerial(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestActivateReimportsKeepingARNAndTags(t *testing.T) {
	e := setup(t)
	next := e.ca.Issue(t, names, testcert.Options{})
	before := len(e.acm.Calls())

	prev := e.deploy(next)
	if prev != "serial:"+e.orig.Serial {
		t.Errorf("previous ref = %q, want serial:%s", prev, e.orig.Serial)
	}
	c := e.acm.Cert(e.arn)
	if c == nil || c.Leaf.SerialNumber.Cmp(next.Cert.SerialNumber) != 0 || c.Imports != 2 {
		t.Fatalf("ACM holds %+v, want the new certificate under the same ARN", c)
	}
	if c.Tags["team"] != "web" {
		t.Errorf("tags lost: %v", c.Tags)
	}
	if strings.Contains(string(c.CertPEM), "Intermediate") || !strings.Contains(string(c.ChainPEM), "BEGIN CERTIFICATE") {
		t.Error("certificate and chain not imported separately")
	}
	if got := e.current(); got != next.Serial {
		t.Errorf("Current = %s, want %s", got, next.Serial)
	}
	if got := countCalls(e.acm.Calls()[before:], "ImportCertificate"); got != 1 {
		t.Errorf("ImportCertificate called %d times", got)
	}
}

func TestStageChangesNothing(t *testing.T) {
	e := setup(t)
	ref, err := e.tg.Stage(context.Background(), e.stageReq(e.ca.Issue(t, names, testcert.Options{})))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ref, "PRIVATE") || len(ref) > 64 {
		t.Errorf("staged ref carries more than an id: %q", ref)
	}
	if countCalls(e.acm.Calls(), "ImportCertificate") != 0 || e.acm.Cert(e.arn).Imports != 1 {
		t.Error("Stage changed ACM")
	}
	if err := e.tg.Discard(context.Background(), plugin.DiscardRequest{Config: e.cfg, StagedRef: ref}); err != nil {
		t.Fatal(err)
	}
	if err := e.tg.Discard(context.Background(), plugin.DiscardRequest{Config: e.cfg, StagedRef: ref}); err != nil {
		t.Fatalf("second Discard: %v", err)
	}
	if _, err := e.tg.Activate(context.Background(), plugin.ActivateRequest{Config: e.cfg, StagedRef: ref}); !errors.Is(err, plugin.ErrNotFound) {
		t.Errorf("Activate after Discard: %v", err)
	}
}

func TestStageRefusals(t *testing.T) {
	e := setup(t)
	other := e.ca.Issue(t, names, testcert.Options{})
	cases := map[string]struct {
		req  func() plugin.StageRequest
		want string
	}{
		"vault ref": {func() plugin.StageRequest {
			r := e.stageReq(other)
			r.Key = plugin.KeyMaterial{Format: plugin.KeyFormatVaultRef, Ref: "kv://x"}
			return r
		}, "needs the private key as PEM"},
		"key does not match": {func() plugin.StageRequest {
			r := e.stageReq(other)
			r.Key.Data = e.ca.Issue(t, names, testcert.Options{}).KeyPEM
			return r
		}, "does not belong to certificate"},
		"garbage key": {func() plugin.StageRequest {
			r := e.stageReq(other)
			r.Key.Data = []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
			return r
		}, "private key does not parse"},
		"expired": {func() plugin.StageRequest {
			return e.stageReq(e.ca.Issue(t, names, testcert.Options{NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-time.Hour)}))
		}, "validity period"},
		"key type changes": {func() plugin.StageRequest {
			return e.stageReq(e.ca.Issue(t, names, testcert.Options{Key: "rsa-2048"}))
		}, "has a EC_prime256v1 key and this one RSA_2048"},
		"drops a name": {func() plugin.StageRequest {
			return e.stageReq(e.ca.Issue(t, names[:1], testcert.Options{}))
		}, "does not cover www.example.com"},
		"drops server auth": {func() plugin.StageRequest {
			return e.stageReq(e.ca.Issue(t, names, testcert.Options{ExtUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}))
		}, "TLS_WEB_SERVER_AUTHENTICATION"},
		"serial mismatch": {func() plugin.StageRequest {
			r := e.stageReq(other)
			r.Serial = "abc"
			return r
		}, "does not match"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := e.tg.Stage(context.Background(), c.req())
			if !plugin.IsPermanent(err) || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want a permanent error containing %q", err, c.want)
			}
			if err != nil && strings.Contains(err.Error(), "PRIVATE KEY") {
				t.Errorf("error carries key material: %v", err)
			}
		})
	}
	if countCalls(e.acm.Calls(), "ImportCertificate") != 0 {
		t.Error("a refused Stage imported something")
	}
}

func TestStageAcceptsWildcardAndAddedNames(t *testing.T) {
	e := setup(t)
	l := e.ca.Issue(t, []string{"*.example.com", "example.com"}, testcert.Options{})
	if _, err := e.tg.Stage(context.Background(), e.stageReq(l)); err != nil {
		t.Errorf("wildcard covering the current names: %v", err)
	}
	l = e.ca.Issue(t, append([]string{"new.example.com"}, names...), testcert.Options{})
	if _, err := e.tg.Stage(context.Background(), e.stageReq(l)); err != nil {
		t.Errorf("added name: %v", err)
	}
}

func TestStageRefusesAmazonIssued(t *testing.T) {
	e := setup(t)
	e.cfg = cfgFor("us-east-1", e.acm.AddIssued("AMAZON_ISSUED", names))
	_, err := e.tg.Stage(context.Background(), e.stageReq(e.ca.Issue(t, names, testcert.Options{})))
	if !plugin.IsPermanent(err) || !strings.Contains(err.Error(), "AMAZON_ISSUED") {
		t.Errorf("err = %v", err)
	}
}

func TestActivateFailures(t *testing.T) {
	cases := map[string]struct {
		fault fakeacm.Fault
		check func(error) bool
		want  string
	}{
		"access denied": {
			fakeacm.Fault{Code: "AccessDeniedException", Message: "not authorized to perform acm:ImportCertificate"},
			plugin.IsPermanent, "allow acm:ImportCertificate",
		},
		"throttled": {
			fakeacm.Fault{Code: "ThrottlingException", Message: "Rate exceeded"},
			func(err error) bool { return errors.Is(err, plugin.ErrUnavailable) }, "ThrottlingException",
		},
		"limit": {
			fakeacm.Fault{Code: "LimitExceededException", Message: "import quota"},
			plugin.IsPermanent, "LimitExceededException",
		},
		"server error": {
			fakeacm.Fault{Code: "InternalServerException", Message: "oops", Status: http.StatusInternalServerError},
			func(err error) bool { return errors.Is(err, plugin.ErrUnavailable) }, "InternalServerException",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := setup(t)
			ref, err := e.tg.Stage(context.Background(), e.stageReq(e.ca.Issue(t, names, testcert.Options{})))
			if err != nil {
				t.Fatal(err)
			}
			e.acm.Fail("ImportCertificate", c.fault)
			_, err = e.tg.Activate(context.Background(), plugin.ActivateRequest{Config: e.cfg, StagedRef: ref})
			if !c.check(err) || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
			if got := e.current(); got != e.orig.Serial {
				t.Errorf("ACM serves %s after a failed Activate, want the old %s", got, e.orig.Serial)
			}
			if c := e.acm.Cert(e.arn); c.Tags["team"] != "web" {
				t.Error("tags changed")
			}
		})
	}
}

func TestActivateWithUnknownOutcome(t *testing.T) {
	// ACM applied the import, but the answer never arrived. Activate asks
	// ACM and reports success instead of a failure that would leave the
	// connector believing the old certificate is live.
	e := setup(t)
	next := e.ca.Issue(t, names, testcert.Options{})
	ref, err := e.tg.Stage(context.Background(), e.stageReq(next))
	if err != nil {
		t.Fatal(err)
	}
	e.acm.Fail("ImportCertificate", fakeacm.Fault{Hang: true, After: true, Times: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	prev, err := e.tg.Activate(ctx, plugin.ActivateRequest{Config: e.cfg, StagedRef: ref})
	if err != nil || prev != "serial:"+e.orig.Serial {
		t.Errorf("Activate = %q, %v; want success with previous serial:%s", prev, err, e.orig.Serial)
	}
	if got := e.current(); got != next.Serial {
		t.Errorf("serves %s, want %s", got, next.Serial)
	}

	// Timed out and not applied: ErrUnavailable, nothing changed.
	e2 := setup(t)
	ref, err = e2.tg.Stage(context.Background(), e2.stageReq(e2.ca.Issue(t, names, testcert.Options{})))
	if err != nil {
		t.Fatal(err)
	}
	e2.acm.Fail("ImportCertificate", fakeacm.Fault{Hang: true})
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	_, err = e2.tg.Activate(ctx2, plugin.ActivateRequest{Config: e2.cfg, StagedRef: ref})
	if !errors.Is(err, plugin.ErrUnavailable) {
		t.Errorf("timed out Activate: %v", err)
	}
	if got := e2.current(); got != e2.orig.Serial {
		t.Errorf("serves %s, want %s", got, e2.orig.Serial)
	}
}

func TestRollback(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	next := e.ca.Issue(t, names, testcert.Options{})
	prev := e.deploy(next)

	// Without the material ACM cannot go back.
	err := e.tg.Rollback(ctx, e.rollbackReq(prev, nil))
	if !plugin.IsPermanent(err) || !strings.Contains(err.Error(), "does not return imported private keys") {
		t.Errorf("rollback without material: %v", err)
	}
	if got := e.current(); got != next.Serial {
		t.Fatal("rollback without material changed ACM")
	}

	// Material for another certificate is refused.
	wrong := e.ca.Issue(t, names, testcert.Options{})
	if err := e.tg.Rollback(ctx, e.rollbackReq(prev, &wrong)); !plugin.IsPermanent(err) || !strings.Contains(err.Error(), "was live before") {
		t.Errorf("rollback with the wrong material: %v", err)
	}

	before := e.acm.Cert(e.arn).Imports
	if err := e.tg.Rollback(ctx, e.rollbackReq(prev, &e.orig)); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	c := e.acm.Cert(e.arn)
	if got := e.current(); got != e.orig.Serial || c.Imports != before+1 || c.ARN != e.arn || c.Tags["team"] != "web" {
		t.Errorf("after rollback ACM serves %s (imports %d), want %s under the same ARN with its tags", got, c.Imports, e.orig.Serial)
	}

	// Rolling back again is a no-op, even without material.
	if err := e.tg.Rollback(ctx, e.rollbackReq(prev, nil)); err != nil {
		t.Errorf("second Rollback: %v", err)
	}
	if e.acm.Cert(e.arn).Imports != before+1 {
		t.Error("second Rollback imported again")
	}

	// Material that does not match the previous ref is refused even when
	// ACM already holds the previous serial.
	if err := e.tg.Rollback(ctx, e.rollbackReq(prev, &wrong)); !plugin.IsPermanent(err) || !strings.Contains(err.Error(), "was live before") {
		t.Errorf("no-op rollback with the wrong material: %v", err)
	}
	if err := e.tg.Rollback(ctx, e.rollbackReq(e.orig.Serial, &e.orig)); !errors.Is(err, plugin.ErrInvalid) {
		t.Errorf("rollback with a bare serial as previous ref: %v", err)
	}
	if err := e.tg.Rollback(ctx, e.rollbackReq("", &e.orig)); !plugin.IsPermanent(err) {
		t.Errorf("rollback with no previous ref: %v", err)
	}
	if err := e.tg.Rollback(ctx, e.rollbackReq("not-hex", &e.orig)); !errors.Is(err, plugin.ErrInvalid) {
		t.Errorf("rollback with a bad previous ref: %v", err)
	}
}

func TestRollbackFailureIsMapped(t *testing.T) {
	e := setup(t)
	prev := e.deploy(e.ca.Issue(t, names, testcert.Options{}))
	e.acm.Fail("ImportCertificate", fakeacm.Fault{Code: "ThrottlingException", Message: "Rate exceeded"})
	if err := e.tg.Rollback(context.Background(), e.rollbackReq(prev, &e.orig)); !errors.Is(err, plugin.ErrUnavailable) {
		t.Errorf("throttled rollback: %v", err)
	}
	e.acm.Fail("ImportCertificate", fakeacm.Fault{Code: "AccessDeniedException", Message: "no"})
	if err := e.tg.Rollback(context.Background(), e.rollbackReq(prev, &e.orig)); !plugin.IsPermanent(err) || !strings.Contains(err.Error(), "acm:ImportCertificate") {
		t.Errorf("denied rollback: %v", err)
	}
}

func TestDeadlineIsHonored(t *testing.T) {
	e := setup(t)
	e.acm.Fail("DescribeCertificate", fakeacm.Fault{Hang: true})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := e.tg.Current(ctx, plugin.CurrentRequest{Config: e.cfg})
	if !errors.Is(err, plugin.ErrUnavailable) || time.Since(start) > 5*time.Second {
		t.Errorf("Current with a hanging ACM: %v after %s", err, time.Since(start))
	}
}

func TestSecretsStayOutOfLogsAndErrors(t *testing.T) {
	e := setup(t)
	l := e.ca.Issue(t, names, testcert.Options{})
	req := e.stageReq(l)
	var out strings.Builder
	slog.New(slog.NewJSONHandler(&out, nil)).Info("x", "req", req, "rb", e.rollbackReq("1", &l))
	if strings.Contains(out.String(), "PRIVATE KEY") {
		t.Errorf("logged key material: %s", out.String())
	}
	// A staged key is wiped after Activate.
	ref, err := e.tg.Stage(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	e.tg.mu.Lock()
	s := e.tg.staged[ref]
	e.tg.mu.Unlock()
	if _, err := e.tg.Activate(context.Background(), plugin.ActivateRequest{Config: e.cfg, StagedRef: ref}); err != nil {
		t.Fatal(err)
	}
	if s.m.keyPEM != nil {
		t.Error("staged key not wiped after Activate")
	}
}

func TestStagedMaterialExpires(t *testing.T) {
	e := setup(t)
	now := time.Now()
	e.tg.Now = func() time.Time { return now }
	old, err := e.tg.Stage(context.Background(), e.stageReq(e.ca.Issue(t, names, testcert.Options{})))
	if err != nil {
		t.Fatal(err)
	}
	e.tg.mu.Lock()
	s := e.tg.staged[old]
	e.tg.mu.Unlock()
	now = now.Add(2 * time.Hour)
	// No other Stage in between: Activate itself sweeps.
	if _, err := e.tg.Activate(context.Background(), plugin.ActivateRequest{Config: e.cfg, StagedRef: old}); !errors.Is(err, plugin.ErrNotFound) {
		t.Errorf("Activate of abandoned staged material: %v", err)
	}
	if s.m.keyPEM != nil {
		t.Error("expired staged key not wiped")
	}
}

func TestStagedMaterialIsWipedWithoutFurtherCalls(t *testing.T) {
	e := setup(t)
	e.tg.ttl = 50 * time.Millisecond
	ref, err := e.tg.Stage(context.Background(), e.stageReq(e.ca.Issue(t, names, testcert.Options{})))
	if err != nil {
		t.Fatal(err)
	}
	e.tg.mu.Lock()
	s := e.tg.staged[ref]
	e.tg.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.tg.mu.Lock()
		_, still := e.tg.staged[ref]
		wiped := s.m.keyPEM == nil
		e.tg.mu.Unlock()
		if !still && wiped {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("staged key still in memory after its TTL")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Regression for a review probe: ACM applies the import, but the call ends
// with a throttling error. Activate must notice the import went through,
// and a repeated Activate must not report the new serial as the previous
// one.
func TestImportAppliedButThrottled(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	next := e.ca.Issue(t, names, testcert.Options{})
	ref, err := e.tg.Stage(ctx, e.stageReq(next))
	if err != nil {
		t.Fatal(err)
	}
	e.acm.Fail("ImportCertificate", fakeacm.Fault{After: true, Code: "ThrottlingException", Message: "Rate exceeded", Times: 2})
	prev, err := e.tg.Activate(ctx, plugin.ActivateRequest{Config: e.cfg, StagedRef: ref})
	if err != nil || prev != "serial:"+e.orig.Serial {
		t.Fatalf("Activate = %q, %v; want success with previous serial:%s", prev, err, e.orig.Serial)
	}
	if got := e.current(); got != next.Serial {
		t.Fatalf("ACM serves %s, want %s", got, next.Serial)
	}

	// Activating the same certificate again: nothing to import, and the
	// previous certificate is unknown.
	before := e.acm.Cert(e.arn).Imports
	ref, err = e.tg.Stage(ctx, e.stageReq(next))
	if err != nil {
		t.Fatal(err)
	}
	prev, err = e.tg.Activate(ctx, plugin.ActivateRequest{Config: e.cfg, StagedRef: ref})
	if err != nil || prev != "" {
		t.Errorf("second Activate = %q, %v; want an empty previous ref", prev, err)
	}
	if e.acm.Cert(e.arn).Imports != before {
		t.Error("second Activate imported again")
	}

	// A rollback to the original still works with its material.
	if err := e.tg.Rollback(ctx, e.rollbackReq("serial:"+e.orig.Serial, &e.orig)); err != nil || e.current() != e.orig.Serial {
		t.Errorf("Rollback = %v; ACM serves %s", err, e.current())
	}
}

func TestPermanentImportErrorStillChecksACM(t *testing.T) {
	// Even a refusal is checked: the error may come from a retry after a
	// first attempt that went through.
	e := setup(t)
	next := e.ca.Issue(t, names, testcert.Options{})
	ref, err := e.tg.Stage(context.Background(), e.stageReq(next))
	if err != nil {
		t.Fatal(err)
	}
	e.acm.Fail("ImportCertificate", fakeacm.Fault{After: true, Code: "ValidationException", Message: "odd", Times: 1})
	calls := len(e.acm.Calls())
	if _, err := e.tg.Activate(context.Background(), plugin.ActivateRequest{Config: e.cfg, StagedRef: ref}); err != nil {
		t.Errorf("Activate after an applied but refused import: %v", err)
	}
	if got := e.acm.Calls()[calls:]; countCalls(got, "DescribeCertificate") != 2 {
		t.Errorf("calls = %v, want a DescribeCertificate check after the failed import", got)
	}
}

func TestUnknownErrorCodesUseTheHTTPStatus(t *testing.T) {
	e := setup(t)
	e.acm.Fail("DescribeCertificate", fakeacm.Fault{Code: "SomethingNewException", Message: "x", Status: http.StatusServiceUnavailable})
	if _, err := e.tg.Current(context.Background(), plugin.CurrentRequest{Config: e.cfg}); !errors.Is(err, plugin.ErrUnavailable) || plugin.IsPermanent(err) {
		t.Errorf("unknown code with 503: %v", err)
	}
	e.acm.Fail("DescribeCertificate", fakeacm.Fault{Code: "SomethingNewException", Message: "x", Status: http.StatusBadRequest})
	if _, err := e.tg.Current(context.Background(), plugin.CurrentRequest{Config: e.cfg}); !plugin.IsPermanent(err) {
		t.Errorf("unknown code with 400: %v", err)
	}
}
