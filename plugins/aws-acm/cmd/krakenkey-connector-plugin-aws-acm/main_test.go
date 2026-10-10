package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	goplugin "github.com/hashicorp/go-plugin"

	"github.com/krakenkey/connector/pkg/plugin"
	"github.com/krakenkey/connector/plugins/aws-acm/internal/fakeacm"
	"github.com/krakenkey/connector/plugins/aws-acm/internal/testcert"
)

// TestHarness builds the plugin binary and drives it the way the
// connector does: over go-plugin gRPC with the SDK's host-side client. The
// binary finds the fake ACM through the standard AWS_ENDPOINT_URL_ACM
// variable, and gets credentials from the environment.
func TestHarness(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the plugin binary")
	}
	bin := filepath.Join(t.TempDir(), "krakenkey-connector-plugin-aws-acm")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	srv := fakeacm.New()
	defer srv.Close()
	ca := testcert.NewCA(t)
	names := []string{"api.example.com"}
	first := ca.Issue(t, names, testcert.Options{})
	arn, err := srv.Import(first.CertPEM, ca.IntermediatePEM, first.KeyPEM, map[string]string{"env": "test"})
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		"AWS_ENDPOINT_URL_ACM="+srv.URL,
		"AWS_ACCESS_KEY_ID=AKIDTEST",
		"AWS_SECRET_ACCESS_KEY=test-secret",
		"AWS_EC2_METADATA_DISABLED=true",
		"AWS_CONFIG_FILE="+filepath.Join(t.TempDir(), "none"),
		"AWS_SHARED_CREDENTIALS_FILE="+filepath.Join(t.TempDir(), "none"),
	)
	client := goplugin.NewClient(plugin.ClientConfig(cmd, nil))
	defer client.Kill()
	rpc, err := client.Client()
	if err != nil {
		t.Fatalf("start plugin: %v", err)
	}
	tg, err := plugin.DispenseTarget(rpc)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cfg := json.RawMessage(fmt.Sprintf(`{"region":%q,"certificate_arn":%q}`, srv.Region, arn))

	caps, err := tg.Describe(ctx)
	if err != nil || !caps.RollbackNeedsMaterial || !caps.SupportsRollback {
		t.Fatalf("Describe = %+v, %v", caps, err)
	}
	ks := plugin.KeyStoreCapabilities{Provides: []plugin.KeyFormat{plugin.KeyFormatPEM}, Exportable: true, KeyTypes: []plugin.KeyType{plugin.KeyTypeECDSAP256}}
	if f, err := plugin.Match(ks, caps, plugin.KeyTypeECDSAP256); err != nil || f != plugin.KeyFormatPEM {
		t.Errorf("Match = %q, %v", f, err)
	}
	if why := plugin.RollbackUnavailable(ks, caps); why != "" {
		t.Errorf("rollback unavailable with an exportable key store: %s", why)
	}

	if p, err := tg.Validate(ctx, plugin.TargetValidateRequest{Config: cfg, CertificateID: "1", Label: "alb"}); err != nil || len(p) != 0 {
		t.Fatalf("Validate = %v, %v", p, err)
	}
	issued := json.RawMessage(fmt.Sprintf(`{"region":%q,"certificate_arn":%q}`, srv.Region, srv.AddIssued("AMAZON_ISSUED", names)))
	if p, err := tg.Validate(ctx, plugin.TargetValidateRequest{Config: issued}); err != nil || len(p) != 1 || !strings.Contains(p[0], "AMAZON_ISSUED") {
		t.Errorf("Validate of an ACM-issued certificate = %v, %v", p, err)
	}

	next := ca.Issue(t, names, testcert.Options{})
	ref, err := tg.Stage(ctx, plugin.StageRequest{
		Config: cfg, CertificateID: "1", Label: "alb",
		CertPEM: next.CertPEM, ChainPEM: ca.IntermediatePEM, FullChainPEM: next.CertPEM + ca.IntermediatePEM,
		Key: plugin.KeyMaterial{Format: plugin.KeyFormatPEM, Data: next.KeyPEM}, Serial: next.Serial,
	})
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	prev, err := tg.Activate(ctx, plugin.ActivateRequest{Config: cfg, StagedRef: ref, CertificateID: "1", Label: "alb"})
	if err != nil || prev != first.Serial {
		t.Fatalf("Activate = %q, %v", prev, err)
	}
	if cur, err := tg.Current(ctx, plugin.CurrentRequest{Config: cfg}); err != nil || cur != next.Serial {
		t.Errorf("Current = %q, %v; want %s", cur, err, next.Serial)
	}
	if c := srv.Cert(arn); c.Tags["env"] != "test" || c.Imports != 2 {
		t.Errorf("ACM certificate after Activate: imports %d tags %v", c.Imports, c.Tags)
	}

	// Rollback without material is refused across the wire as permanent.
	err = tg.Rollback(ctx, plugin.RollbackRequest{Config: cfg, PreviousRef: prev})
	if !plugin.IsPermanent(err) || !strings.Contains(err.Error(), "does not return imported private keys") {
		t.Errorf("Rollback without material: %v", err)
	}
	err = tg.Rollback(ctx, plugin.RollbackRequest{
		Config: cfg, PreviousRef: prev,
		PreviousCertPEM: first.CertPEM, PreviousChainPEM: ca.IntermediatePEM, PreviousFullChainPEM: first.CertPEM + ca.IntermediatePEM,
		PreviousKey: plugin.KeyMaterial{Format: plugin.KeyFormatPEM, Data: first.KeyPEM}, PreviousSerial: first.Serial,
	})
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if cur, _ := tg.Current(ctx, plugin.CurrentRequest{Config: cfg}); cur != first.Serial {
		t.Errorf("Current after rollback = %q, want %s", cur, first.Serial)
	}
	if err := tg.Discard(ctx, plugin.DiscardRequest{Config: cfg, StagedRef: "unknown"}); err != nil {
		t.Errorf("Discard: %v", err)
	}

	// Error kinds survive the wire.
	srv.Fail("DescribeCertificate", fakeacm.Fault{Code: "AccessDeniedException", Message: "not authorized"})
	_, err = tg.Current(ctx, plugin.CurrentRequest{Config: cfg})
	if !plugin.IsPermanent(err) || !strings.Contains(err.Error(), "acm:DescribeCertificate") {
		t.Errorf("Current with access denied: %v", err)
	}
	srv.Fail("DescribeCertificate", fakeacm.Fault{Code: "ThrottlingException", Message: "Rate exceeded"})
	_, err = tg.Current(ctx, plugin.CurrentRequest{Config: cfg})
	if !errors.Is(err, plugin.ErrUnavailable) {
		t.Errorf("Current when throttled: %v", err)
	}
}
