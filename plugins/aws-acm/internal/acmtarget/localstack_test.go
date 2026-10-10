package acmtarget

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/smithy-go/middleware"

	"github.com/krakenkey/connector/pkg/plugin"
	"github.com/krakenkey/connector/plugins/aws-acm/internal/testcert"
)

// LocalStackImage is the image the LocalStack tests are run against in CI
// (see .github/workflows/ci.yaml and the README). 4.14.0 is the last
// community release that starts without a LocalStack account token.
const LocalStackImage = "localstack/localstack:4.14.0"

// localStackEndpoint returns the LocalStack endpoint from
// KK_TEST_LOCALSTACK_ENDPOINT, or skips the test.
func localStackEndpoint(t *testing.T) string {
	t.Helper()
	ep := os.Getenv("KK_TEST_LOCALSTACK_ENDPOINT")
	if ep == "" {
		t.Skip("KK_TEST_LOCALSTACK_ENDPOINT is not set; start " + LocalStackImage +
			" (docker run --rm -p 4566:4566 -e SERVICES=acm " + LocalStackImage +
			") and set it to http://localhost:4566 to run the LocalStack tests. The fake ACM tests cover the same logic without Docker.")
	}
	return ep
}

func TestLocalStack(t *testing.T) {
	ep := localStackEndpoint(t)
	ctx := context.Background()
	const region = "us-east-1"
	raw := acm.NewFromConfig(aws.Config{
		Region:      region,
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
	}, func(o *acm.Options) { o.BaseEndpoint = aws.String(ep) })

	ca := testcert.NewCA(t)
	// A fresh name per run, so certificates left by earlier runs against
	// the same LocalStack do not count.
	host := fmt.Sprintf("ls-%d.example.com", time.Now().UnixNano())
	names := []string{host}
	first := ca.Issue(t, names, testcert.Options{})
	out, err := raw.ImportCertificate(ctx, &acm.ImportCertificateInput{
		Certificate: []byte(first.CertPEM), CertificateChain: []byte(ca.IntermediatePEM), PrivateKey: first.KeyPEM,
		Tags: []types.Tag{{Key: aws.String("owner"), Value: aws.String("connector-test")}},
	})
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	arn := aws.ToString(out.CertificateArn)
	t.Logf("imported %s", arn)

	tg := testTarget(ep)
	tg.ClientOptions = append(tg.ClientOptions, func(o *acm.Options) {
		o.APIOptions = append(o.APIOptions, normalizeLocalStack)
	})
	e := &env{t: t, ca: ca, tg: tg, arn: arn, cfg: cfgFor(region, arn), orig: first}

	if p, err := tg.Validate(ctx, plugin.TargetValidateRequest{Config: e.cfg}); err != nil || len(p) != 0 {
		t.Fatalf("Validate = %v, %v", p, err)
	}
	if got := e.current(); got != first.Serial {
		t.Fatalf("Current = %q, want %s", got, first.Serial)
	}

	// Re-import keeps the ARN and the tags.
	next := ca.Issue(t, names, testcert.Options{})
	prev := e.deploy(next)
	if prev != "serial:"+first.Serial {
		t.Errorf("previous ref = %q, want serial:%s", prev, first.Serial)
	}
	if got := e.current(); got != next.Serial {
		t.Errorf("Current after Activate = %q, want %s", got, next.Serial)
	}
	d, err := raw.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: aws.String(arn)})
	if err != nil || aws.ToString(d.Certificate.CertificateArn) != arn {
		t.Errorf("DescribeCertificate after re-import: %v", err)
	}
	// The re-import must not send tags (ACM refuses them on reimport and
	// keeps the existing ones). LocalStack, unlike ACM, drops the tags when
	// a certificate is re-imported, so only the call is checked here; the
	// fake ACM tests check that tags survive.
	if _, err := raw.ListTagsForCertificate(ctx, &acm.ListTagsForCertificateInput{CertificateArn: aws.String(arn)}); err != nil {
		t.Errorf("ListTagsForCertificate after re-import: %v", err)
	}
	list, err := raw.ListCertificates(ctx, &acm.ListCertificatesInput{})
	if err == nil {
		n := 0
		for _, c := range list.CertificateSummaryList {
			if aws.ToString(c.DomainName) == host {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%d certificates for the test name, want 1 (re-import must not create another)", n)
		}
	}

	// Rollback: refused without material, restores with it.
	if err := tg.Rollback(ctx, e.rollbackReq(prev, nil)); !plugin.IsPermanent(err) {
		t.Errorf("Rollback without material: %v", err)
	}
	if err := tg.Rollback(ctx, e.rollbackReq(prev, &first)); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if got := e.current(); got != first.Serial {
		t.Errorf("Current after rollback = %q, want %s", got, first.Serial)
	}

	// A certificate ACM issued itself is refused.
	req, err := raw.RequestCertificate(ctx, &acm.RequestCertificateInput{DomainName: aws.String("issued.example.com")})
	if err != nil {
		t.Fatalf("RequestCertificate: %v", err)
	}
	issued := cfgFor(region, aws.ToString(req.CertificateArn))
	if p, err := tg.Validate(ctx, plugin.TargetValidateRequest{Config: issued}); err != nil || len(p) != 1 || !strings.Contains(p[0], "AMAZON_ISSUED") {
		t.Errorf("Validate of an ACM-issued certificate = %v, %v", p, err)
	}

	// A certificate that does not exist.
	missing := cfgFor(region, "arn:aws:acm:us-east-1:000000000000:certificate/00000000-0000-0000-0000-000000000000")
	if p, err := tg.Validate(ctx, plugin.TargetValidateRequest{Config: missing}); err != nil || len(p) != 1 || !strings.Contains(p[0], "does not exist") {
		t.Errorf("Validate of a missing certificate = %v, %v", p, err)
	}
}

// normalizeLocalStack rewrites the two DescribeCertificate fields where
// LocalStack differs from ACM, so the plugin's ACM parsing is tested
// unchanged: LocalStack writes the serial in decimal ("6493...") where ACM
// writes colon-separated hex, and the key algorithm with a dash
// ("EC-prime256v1") where ACM uses an underscore.
func normalizeLocalStack(stack *middleware.Stack) error {
	return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("NormalizeLocalStack",
		func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
			out, md, err := next.HandleInitialize(ctx, in)
			if r, ok := out.Result.(*acm.DescribeCertificateOutput); ok && err == nil && r.Certificate != nil {
				d := r.Certificate
				if s := aws.ToString(d.Serial); s != "" && !strings.Contains(s, ":") {
					if n, ok := new(big.Int).SetString(s, 10); ok {
						b := n.Bytes()
						parts := make([]string, len(b))
						for i, x := range b {
							parts[i] = fmt.Sprintf("%02x", x)
						}
						d.Serial = aws.String(strings.Join(parts, ":"))
					}
				}
				d.KeyAlgorithm = types.KeyAlgorithm(strings.ReplaceAll(string(d.KeyAlgorithm), "-", "_"))
			}
			return out, md, err
		}), middleware.After)
}
