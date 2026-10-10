package keyvault

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/krakenkey/connector/pkg/plugin"
	"github.com/krakenkey/connector/plugins/azure-keyvault/internal/fakevault"
)

type fakeCred struct{ err error }

func (f fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: fakevault.Token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type env struct {
	ks  *KeyStore
	srv *fakevault.Server
	ctx context.Context
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvCred(t, fakeCred{})
}

func newEnvCred(t *testing.T, cred azcore.TokenCredential) *env {
	t.Helper()
	srv, err := fakevault.New(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	ks := New(Options{
		Credential: cred,
		ClientOptions: azcore.ClientOptions{
			Transport: &http.Client{Transport: srv.Transport()},
			Retry:     policy.RetryOptions{MaxRetries: -1},
		},
		DisableChallengeResourceVerification: true,
		PollInterval:                         5 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return &env{ks: ks, srv: srv, ctx: ctx}
}

func (e *env) config(extra string) json.RawMessage {
	c := `{"vault":"` + e.srv.URL + `","certificate_name":"web"`
	if extra != "" {
		c += "," + extra
	}
	return json.RawMessage(c + "}")
}

func (e *env) csr(t *testing.T, cfg json.RawMessage, kt plugin.KeyType, names ...string) (plugin.CSR, *x509.CertificateRequest) {
	t.Helper()
	if len(names) == 0 {
		names = []string{"www.example.com", "example.com"}
	}
	got, err := e.ks.CreateCSR(e.ctx, plugin.CSRRequest{Config: cfg, CertificateID: "7", Names: names, KeyType: kt})
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	b, _ := pem.Decode([]byte(got.PEM))
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("CSR is not PEM: %q", got.PEM)
	}
	req, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return got, req
}

// issue creates a key, signs its CSR and completes it.
func (e *env) issue(t *testing.T, cfg json.RawMessage) (ref, leafPEM, chainPEM string, req *x509.CertificateRequest) {
	t.Helper()
	csr, req := e.csr(t, cfg, plugin.KeyTypeECDSAP256)
	leafPEM, chainPEM, err := fakevault.Sign(csr.PEM)
	if err != nil {
		t.Fatal(err)
	}
	ref, err = e.ks.Complete(e.ctx, plugin.CompleteRequest{Config: cfg, KeyRef: csr.KeyRef, CertPEM: leafPEM, ChainPEM: chainPEM})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	return ref, leafPEM, chainPEM, req
}

func mustDER(t *testing.T, s string) []byte {
	t.Helper()
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		t.Fatal("no PEM block")
	}
	return b.Bytes
}

func TestDescribe(t *testing.T) {
	caps, err := New(Options{}).Describe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !caps.Exportable || !slices.Equal(caps.Provides, []plugin.KeyFormat{plugin.KeyFormatVaultRef, plugin.KeyFormatPEM, plugin.KeyFormatPFX}) ||
		!slices.Equal(caps.KeyTypes, plugin.AllKeyTypes) {
		t.Errorf("caps = %+v", caps)
	}
	// A vault reference is preferred when the target accepts one.
	f, err := plugin.Match(caps, plugin.TargetCapabilities{Accepts: []plugin.KeyFormat{plugin.KeyFormatPFX, plugin.KeyFormatVaultRef}}, plugin.KeyTypeRSA2048)
	if err != nil || f != plugin.KeyFormatVaultRef {
		t.Errorf("Match = %s, %v", f, err)
	}
}

func TestIssueAndExport(t *testing.T) {
	e := newEnv(t)
	cfg := e.config("")
	csr, req := e.csr(t, cfg, plugin.KeyTypeECDSAP256)

	if req.Subject.CommonName != "www.example.com" || !slices.Equal(req.DNSNames, []string{"www.example.com", "example.com"}) {
		t.Errorf("CSR subject %q, names %v", req.Subject.CommonName, req.DNSNames)
	}
	if !strings.HasPrefix(csr.KeyRef, e.srv.URL+"/certificates/web/pending?spki_sha256=") {
		t.Errorf("pending key ref = %s", csr.KeyRef)
	}
	spki, err := e.ks.PublicKey(e.ctx, plugin.PublicKeyRequest{Config: cfg, KeyRef: csr.KeyRef})
	if err != nil || !bytes.Equal(spki, req.RawSubjectPublicKeyInfo) {
		t.Fatalf("PublicKey(pending) = %x, %v", spki, err)
	}

	leafPEM, chainPEM, err := fakevault.Sign(csr.PEM)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := e.ks.Complete(e.ctx, plugin.CompleteRequest{Config: cfg, KeyRef: csr.KeyRef, CertPEM: leafPEM, ChainPEM: chainPEM})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	versions := e.srv.Versions("web")
	if len(versions) != 1 || ref != e.srv.URL+"/certificates/web/"+versions[0] {
		t.Fatalf("completed ref = %s, versions %v", ref, versions)
	}
	if e.srv.HasPending("web") {
		t.Error("request still pending after Complete")
	}

	spki, err = e.ks.PublicKey(e.ctx, plugin.PublicKeyRequest{Config: cfg, KeyRef: ref})
	if err != nil || !bytes.Equal(spki, req.RawSubjectPublicKeyInfo) {
		t.Fatalf("PublicKey(completed) = %x, %v", spki, err)
	}

	km, err := e.ks.Export(e.ctx, plugin.ExportRequest{Config: cfg, KeyRef: ref, Format: plugin.KeyFormatVaultRef})
	if err != nil {
		t.Fatalf("Export(vault_ref): %v", err)
	}
	if want := e.srv.URL + "/secrets/web/" + versions[0]; km.Ref != want || len(km.Data) != 0 {
		t.Errorf("vault ref = %q, want %q", km.Ref, want)
	}

	km, err = e.ks.Export(e.ctx, plugin.ExportRequest{Config: cfg, KeyRef: ref, Format: plugin.KeyFormatPEM})
	if err != nil {
		t.Fatalf("Export(pem): %v", err)
	}
	b, _ := pem.Decode(km.Data)
	if b == nil || b.Type != "PRIVATE KEY" {
		t.Fatalf("PEM export is not a PKCS#8 block")
	}
	key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(key.(*ecdsa.PrivateKey).Public())
	if !bytes.Equal(pub, req.RawSubjectPublicKeyInfo) {
		t.Error("exported key does not match the CSR")
	}

	km, err = e.ks.Export(e.ctx, plugin.ExportRequest{Config: cfg, KeyRef: ref, Format: plugin.KeyFormatPFX})
	if err != nil {
		t.Fatalf("Export(pfx): %v", err)
	}
	pkey, leaf, chain, err := pkcs12.DecodeChain(km.Data, km.Password)
	if err != nil {
		t.Fatal(err)
	}
	if pkey == nil || !bytes.Equal(leaf.Raw, mustDER(t, leafPEM)) || len(chain) != 1 || !bytes.Equal(chain[0].Raw, mustDER(t, chainPEM)) {
		t.Error("PFX does not hold the key, the leaf and the chain passed to Complete")
	}

	// Completed versions stay in Key Vault.
	before := len(e.srv.Calls())
	if err := e.ks.Release(e.ctx, plugin.ReleaseRequest{Config: cfg, KeyRef: ref}); err != nil {
		t.Fatal(err)
	}
	if len(e.srv.Calls()) != before || len(e.srv.Versions("web")) != 1 {
		t.Error("Release of a completed version called Key Vault")
	}
}

func TestKeyTypes(t *testing.T) {
	e := newEnv(t)
	for _, kt := range plugin.AllKeyTypes {
		t.Run(string(kt), func(t *testing.T) {
			_, req := e.csr(t, e.config(""), kt)
			switch pub := req.PublicKey.(type) {
			case *rsa.PublicKey:
				if want := map[plugin.KeyType]int{"rsa-2048": 2048, "rsa-3072": 3072, "rsa-4096": 4096}[kt]; pub.N.BitLen() != want {
					t.Errorf("RSA size %d, want %d", pub.N.BitLen(), want)
				}
			case *ecdsa.PublicKey:
				if want := map[plugin.KeyType]elliptic.Curve{"ecdsa-p256": elliptic.P256(), "ecdsa-p384": elliptic.P384()}[kt]; pub.Curve != want {
					t.Errorf("curve %s", pub.Curve.Params().Name)
				}
			default:
				t.Errorf("%s: public key %T", kt, pub)
			}
		})
	}
	if _, err := e.ks.CreateCSR(e.ctx, plugin.CSRRequest{Config: e.config(""), Names: []string{"a.example"}, KeyType: "ecdsa-p521"}); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("unsupported key type: err = %v", err)
	}
}

func TestWildcardNames(t *testing.T) {
	e := newEnv(t)
	_, req := e.csr(t, e.config(""), plugin.KeyTypeECDSAP384, "*.example.com", "example.com")
	if req.Subject.CommonName != "*.example.com" || !slices.Equal(req.DNSNames, []string{"*.example.com", "example.com"}) {
		t.Errorf("CSR subject %q, names %v", req.Subject.CommonName, req.DNSNames)
	}
	for _, names := range [][]string{nil, {"a.example.com, O=Evil"}, {"*.*.example.com"}} {
		if _, err := e.ks.CreateCSR(e.ctx, plugin.CSRRequest{Config: e.config(""), Names: names, KeyType: plugin.KeyTypeECDSAP256}); !errors.Is(err, plugin.ErrInvalid) {
			t.Errorf("%q: err = %v, want ErrInvalid", names, err)
		}
	}
	if calls := e.srv.Calls(); len(calls) != 2 {
		t.Errorf("rejected names reached Key Vault: %v", calls)
	}
}

func TestNotExportable(t *testing.T) {
	e := newEnv(t)
	cfg := e.config(`"exportable":false`)
	ref, _, _, _ := e.issue(t, cfg)

	km, err := e.ks.Export(e.ctx, plugin.ExportRequest{Config: cfg, KeyRef: ref, Format: plugin.KeyFormatVaultRef})
	if err != nil || !strings.Contains(km.Ref, "/secrets/web/") {
		t.Fatalf("Export(vault_ref) = %v, %v", km, err)
	}
	for _, f := range []plugin.KeyFormat{plugin.KeyFormatPEM, plugin.KeyFormatPFX} {
		_, err := e.ks.Export(e.ctx, plugin.ExportRequest{Config: cfg, KeyRef: ref, Format: f})
		if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "exportable: false") {
			t.Errorf("Export(%s) err = %v, want ErrPermanent", f, err)
		}
	}
	for _, c := range e.srv.Calls() {
		if strings.HasPrefix(c, fakevault.OpGetSecret) {
			t.Error("non-exportable export read the secret")
		}
	}

	// The config says exportable now, but the version was created without
	// export: Key Vault's secret has no key.
	_, err = e.ks.Export(e.ctx, plugin.ExportRequest{Config: e.config(""), KeyRef: ref, Format: plugin.KeyFormatPEM})
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "holds no private key") {
		t.Errorf("Export of a non-exportable version: %v", err)
	}
}

func TestExportErrors(t *testing.T) {
	e := newEnv(t)
	cfg := e.config("")
	csr, _ := e.csr(t, cfg, plugin.KeyTypeECDSAP256)
	if _, err := e.ks.Export(e.ctx, plugin.ExportRequest{Config: cfg, KeyRef: csr.KeyRef, Format: plugin.KeyFormatVaultRef}); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("Export(pending): %v", err)
	}
	if _, err := e.ks.Export(e.ctx, plugin.ExportRequest{Config: cfg, KeyRef: e.srv.URL + "/certificates/web/abc123", Format: "jks"}); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("Export(jks): %v", err)
	}
	if _, err := e.ks.Export(e.ctx, plugin.ExportRequest{Config: cfg, KeyRef: e.srv.URL + "/certificates/web/abc123", Format: plugin.KeyFormatVaultRef}); !errors.Is(err, plugin.ErrNotFound) {
		t.Errorf("Export(unknown version): %v", err)
	}
	if _, err := e.ks.Export(e.ctx, plugin.ExportRequest{Config: cfg, KeyRef: "local/1", Format: plugin.KeyFormatVaultRef}); !errors.Is(err, plugin.ErrInvalid) {
		t.Errorf("Export(foreign ref): %v", err)
	}
	if _, err := e.ks.Export(e.ctx, plugin.ExportRequest{Config: json.RawMessage(`{}`), KeyRef: csr.KeyRef, Format: plugin.KeyFormatVaultRef}); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("Export(bad config): %v", err)
	}
}

func TestInterruptedPendingRequest(t *testing.T) {
	e := newEnv(t)
	cfg := e.config("")
	first, _ := e.csr(t, cfg, plugin.KeyTypeECDSAP256)
	// The connector stopped before recording first; the next run asks for
	// a new CSR, which replaces the stale request.
	second, req2 := e.csr(t, cfg, plugin.KeyTypeECDSAP256)
	if first.KeyRef == second.KeyRef {
		t.Fatal("new request reused the stale key")
	}
	if !slices.Contains(e.srv.Calls(), fakevault.OpDeletePending+" web") {
		t.Error("stale request was not deleted")
	}

	if _, err := e.ks.PublicKey(e.ctx, plugin.PublicKeyRequest{Config: cfg, KeyRef: first.KeyRef}); !errors.Is(err, plugin.ErrNotFound) {
		t.Errorf("PublicKey(stale) err = %v, want ErrNotFound", err)
	}
	// Releasing the stale key must not touch the new request.
	if err := e.ks.Release(e.ctx, plugin.ReleaseRequest{Config: cfg, KeyRef: first.KeyRef}); err != nil {
		t.Fatal(err)
	}
	if !e.srv.HasPending("web") {
		t.Fatal("Release of the stale key deleted the new request")
	}
	leaf, chain, err := fakevault.Sign(second.PEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ks.Complete(e.ctx, plugin.CompleteRequest{Config: cfg, KeyRef: first.KeyRef, CertPEM: leaf, ChainPEM: chain}); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("Complete(stale ref, other key) err = %v, want ErrPermanent", err)
	}
	ref, err := e.ks.Complete(e.ctx, plugin.CompleteRequest{Config: cfg, KeyRef: second.KeyRef, CertPEM: leaf, ChainPEM: chain})
	if err != nil {
		t.Fatal(err)
	}
	spki, err := e.ks.PublicKey(e.ctx, plugin.PublicKeyRequest{Config: cfg, KeyRef: ref})
	if err != nil || !bytes.Equal(spki, req2.RawSubjectPublicKeyInfo) {
		t.Errorf("PublicKey = %v", err)
	}
}

func TestPendingRequestFromAnotherIssuer(t *testing.T) {
	e := newEnv(t)
	cfg := e.config("")
	e.csr(t, cfg, plugin.KeyTypeECDSAP256)
	e.srv.SetPendingIssuer("web", "DigiCert")
	_, err := e.ks.CreateCSR(e.ctx, plugin.CSRRequest{Config: cfg, Names: []string{"a.example"}, KeyType: plugin.KeyTypeECDSAP256})
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "DigiCert") {
		t.Errorf("err = %v, want ErrPermanent naming the issuer", err)
	}
	if !e.srv.HasPending("web") {
		t.Error("request from another issuer was deleted")
	}
}

func TestReleasePending(t *testing.T) {
	e := newEnv(t)
	cfg := e.config("")
	csr, _ := e.csr(t, cfg, plugin.KeyTypeECDSAP256)
	if err := e.ks.Release(e.ctx, plugin.ReleaseRequest{Config: cfg, KeyRef: csr.KeyRef}); err != nil {
		t.Fatal(err)
	}
	if e.srv.HasPending("web") {
		t.Error("pending request not deleted")
	}
	// Idempotent, and unknown references are not an error.
	for _, ref := range []string{csr.KeyRef, "", "local/7/abc", e.srv.URL + "/certificates/other/pending?spki_sha256=" + strings.Repeat("0", 64)} {
		if err := e.ks.Release(e.ctx, plugin.ReleaseRequest{Config: cfg, KeyRef: ref}); err != nil {
			t.Errorf("Release(%q): %v", ref, err)
		}
	}
	if _, err := e.ks.PublicKey(e.ctx, plugin.PublicKeyRequest{Config: cfg, KeyRef: csr.KeyRef}); !errors.Is(err, plugin.ErrNotFound) {
		t.Errorf("PublicKey after Release: %v", err)
	}
}

func TestCompleteIsIdempotent(t *testing.T) {
	e := newEnv(t)
	cfg := e.config("")
	csr, _ := e.csr(t, cfg, plugin.KeyTypeECDSAP256)
	leaf, chain, err := fakevault.Sign(csr.PEM)
	if err != nil {
		t.Fatal(err)
	}
	req := plugin.CompleteRequest{Config: cfg, KeyRef: csr.KeyRef, CertPEM: leaf, ChainPEM: chain}
	ref1, err := e.ks.Complete(e.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	// The answer was lost; the core retries with the pending ref.
	ref2, err := e.ks.Complete(e.ctx, req)
	if err != nil || ref2 != ref1 {
		t.Errorf("second Complete = %s, %v; want %s", ref2, err, ref1)
	}
	// PublicKey of the pending ref still finds the key in the new version.
	if _, err := e.ks.PublicKey(e.ctx, plugin.PublicKeyRequest{Config: cfg, KeyRef: csr.KeyRef}); err != nil {
		t.Errorf("PublicKey(pending ref after merge): %v", err)
	}
	ref3, err := e.ks.Complete(e.ctx, plugin.CompleteRequest{Config: cfg, KeyRef: ref1, CertPEM: leaf, ChainPEM: chain})
	if err != nil || ref3 != ref1 {
		t.Errorf("Complete(completed ref, same cert) = %s, %v", ref3, err)
	}
	if n := len(e.srv.Versions("web")); n != 1 {
		t.Errorf("%d versions, want 1", n)
	}
}

func TestCompleteRejectsBadInput(t *testing.T) {
	e := newEnv(t)
	cfg := e.config("")
	csr, _ := e.csr(t, cfg, plugin.KeyTypeECDSAP256)
	if _, err := e.ks.Complete(e.ctx, plugin.CompleteRequest{Config: cfg, KeyRef: csr.KeyRef, CertPEM: "nope"}); !errors.Is(err, plugin.ErrInvalid) {
		t.Errorf("bad PEM: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, chain, err := fakevault.SignPublicKey(other.Public(), "www.example.com", []string{"www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ks.Complete(e.ctx, plugin.CompleteRequest{Config: cfg, KeyRef: csr.KeyRef, CertPEM: leaf, ChainPEM: chain}); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("certificate for another key: %v", err)
	}
	if !e.srv.HasPending("web") {
		t.Error("failed Complete dropped the request")
	}
}

func TestRenewedWithSameKey(t *testing.T) {
	e := newEnv(t)
	cfg := e.config(`"exportable":false`)
	ref, _, _, req := e.issue(t, cfg)

	// KrakenKey renewed the certificate from the same CSR.
	leaf, chain, err := fakevault.SignPublicKey(req.PublicKey, req.Subject.CommonName, req.DNSNames)
	if err != nil {
		t.Fatal(err)
	}
	newRef, err := e.ks.Complete(e.ctx, plugin.CompleteRequest{Config: cfg, KeyRef: ref, CertPEM: leaf, ChainPEM: chain})
	if err != nil {
		t.Fatalf("Complete(renewed): %v", err)
	}
	versions := e.srv.Versions("web")
	if newRef == ref || len(versions) != 2 || newRef != e.srv.URL+"/certificates/web/"+versions[1] {
		t.Fatalf("new ref %s, versions %v", newRef, versions)
	}
	spki, err := e.ks.PublicKey(e.ctx, plugin.PublicKeyRequest{Config: cfg, KeyRef: newRef})
	if err != nil || !bytes.Equal(spki, req.RawSubjectPublicKeyInfo) {
		t.Errorf("PublicKey(new ref) = %v", err)
	}
	// Retried after a lost answer: no third version.
	again, err := e.ks.Complete(e.ctx, plugin.CompleteRequest{Config: cfg, KeyRef: ref, CertPEM: leaf, ChainPEM: chain})
	if err != nil || again != newRef || len(e.srv.Versions("web")) != 2 {
		t.Errorf("retry = %s, %v", again, err)
	}
}

func TestRenewedWithSameKeyNotReused(t *testing.T) {
	e := newEnv(t)
	cfg := e.config("")
	ref, _, _, req := e.issue(t, cfg)
	e.srv.IgnoreReuseKey()
	leaf, chain, err := fakevault.SignPublicKey(req.PublicKey, req.Subject.CommonName, req.DNSNames)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.ks.Complete(e.ctx, plugin.CompleteRequest{Config: cfg, KeyRef: ref, CertPEM: leaf, ChainPEM: chain})
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "did not reuse") {
		t.Errorf("err = %v", err)
	}
	if e.srv.HasPending("web") {
		t.Error("request with the wrong key left pending")
	}
}

func TestCSRPolling(t *testing.T) {
	e := newEnv(t)
	e.srv.HideCSR(3)
	_, req := e.csr(t, e.config(""), plugin.KeyTypeECDSAP256)
	if req.Subject.CommonName != "www.example.com" {
		t.Errorf("CN = %q", req.Subject.CommonName)
	}

	// Key Vault is slow and the call times out: transient.
	e.srv.HideCSR(1 << 20)
	ctx, cancel := context.WithTimeout(e.ctx, 100*time.Millisecond)
	defer cancel()
	_, err := e.ks.CreateCSR(ctx, plugin.CSRRequest{Config: e.config(""), Names: []string{"a.example"}, KeyType: plugin.KeyTypeECDSAP256})
	if !errors.Is(err, plugin.ErrUnavailable) || errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want ErrUnavailable only", err)
	}
}

func TestValidate(t *testing.T) {
	e := newEnv(t)
	problems, err := e.ks.Validate(e.ctx, plugin.KeyStoreValidateRequest{Config: e.config("")})
	if err != nil || len(problems) != 0 {
		t.Errorf("new certificate: %q, %v", problems, err)
	}
	e.issue(t, e.config(""))
	problems, err = e.ks.Validate(e.ctx, plugin.KeyStoreValidateRequest{Config: e.config("")})
	if err != nil || len(problems) != 0 {
		t.Errorf("existing certificate: %q, %v", problems, err)
	}

	problems, err = e.ks.Validate(e.ctx, plugin.KeyStoreValidateRequest{Config: json.RawMessage(`{"vault":"x"}`)})
	if err != nil || len(problems) != 2 {
		t.Errorf("bad config: %q, %v", problems, err)
	}

	e.srv.SetPolicyIssuer("web", "DigiCert")
	problems, err = e.ks.Validate(e.ctx, plugin.KeyStoreValidateRequest{Config: e.config("")})
	if err != nil || len(problems) != 1 || !strings.Contains(problems[0], "DigiCert") {
		t.Errorf("other issuer: %q, %v", problems, err)
	}

	e.srv.Deny(fakevault.OpGetPolicy)
	_, err = e.ks.Validate(e.ctx, plugin.KeyStoreValidateRequest{Config: e.config("")})
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "Microsoft.KeyVault/vaults/certificates/read") ||
		!strings.Contains(err.Error(), "certificate permission Get") {
		t.Errorf("403: %v", err)
	}
}

func TestErrorKinds(t *testing.T) {
	type call func(e *env, cfg json.RawMessage, ref string) error
	createCSR := func(e *env, cfg json.RawMessage, _ string) error {
		_, err := e.ks.CreateCSR(e.ctx, plugin.CSRRequest{Config: cfg, Names: []string{"a.example"}, KeyType: plugin.KeyTypeECDSAP256})
		return err
	}
	publicKey := func(e *env, cfg json.RawMessage, ref string) error {
		_, err := e.ks.PublicKey(e.ctx, plugin.PublicKeyRequest{Config: cfg, KeyRef: ref})
		return err
	}
	exportPEM := func(e *env, cfg json.RawMessage, ref string) error {
		_, err := e.ks.Export(e.ctx, plugin.ExportRequest{Config: cfg, KeyRef: ref, Format: plugin.KeyFormatPEM})
		return err
	}
	validate := func(e *env, cfg json.RawMessage, _ string) error {
		_, err := e.ks.Validate(e.ctx, plugin.KeyStoreValidateRequest{Config: cfg})
		return err
	}
	tests := []struct {
		name   string
		op     string
		status int
		call   call
		kind   error
		msg    string
	}{
		{"create 403", fakevault.OpCreate, 403, createCSR, plugin.ErrPermanent, "certificates/create/action"},
		{"create 409", fakevault.OpCreate, 409, createCSR, plugin.ErrUnavailable, "409"},
		{"create 429", fakevault.OpCreate, 429, createCSR, plugin.ErrUnavailable, "throttling"},
		{"create 500", fakevault.OpCreate, 500, createCSR, plugin.ErrUnavailable, "500"},
		{"create 400", fakevault.OpCreate, 400, createCSR, plugin.ErrPermanent, "400"},
		{"pending read 403", fakevault.OpGetPending, 403, createCSR, plugin.ErrPermanent, "certificates/read"},
		{"cert 404", fakevault.OpGetCert, 404, publicKey, plugin.ErrNotFound, "404"},
		{"cert 503", fakevault.OpGetCert, 503, publicKey, plugin.ErrUnavailable, "503"},
		{"cert 401", fakevault.OpGetCert, 401, publicKey, plugin.ErrPermanent, "tenant"},
		{"secret 403", fakevault.OpGetSecret, 403, exportPEM, plugin.ErrPermanent, "secrets/getSecret/action"},
		{"secret 429", fakevault.OpGetSecret, 429, exportPEM, plugin.ErrUnavailable, "429"},
		{"policy 502", fakevault.OpGetPolicy, 502, validate, plugin.ErrUnavailable, "502"},
	}
	e := newEnv(t)
	cfg := e.config("")
	ref, _, _, _ := e.issue(t, cfg)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.srv.FailNext(tt.op, tt.status)
			err := tt.call(e, cfg, ref)
			if !errors.Is(err, tt.kind) || !strings.Contains(err.Error(), tt.msg) {
				t.Errorf("err = %v, want %v containing %q", err, tt.kind, tt.msg)
			}
		})
	}
}

func TestSoftDeletedCertificate(t *testing.T) {
	e := newEnv(t)
	e.srv.FailNextWith(fakevault.OpCreate, http.StatusConflict, "Certificate web is currently in a deleted but recoverable state, and its name cannot be reused; in this state, the certificate can only be recovered or purged.")
	_, err := e.ks.CreateCSR(e.ctx, plugin.CSRRequest{Config: e.config(""), Names: []string{"a.example"}, KeyType: plugin.KeyTypeECDSAP256})
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "recover or purge") {
		t.Errorf("err = %v", err)
	}
}

func TestCredentialErrors(t *testing.T) {
	e := newEnvCred(t, fakeCred{err: azidentity.NewCredentialUnavailableError("no managed identity endpoint")})
	_, err := e.ks.Validate(e.ctx, plugin.KeyStoreValidateRequest{Config: e.config("")})
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "no usable Azure credential") {
		t.Errorf("unavailable credential: %v", err)
	}

	e = newEnvCred(t, fakeCred{err: errors.New("dial tcp 169.254.169.254:80: i/o timeout")})
	_, err = e.ks.Validate(e.ctx, plugin.KeyStoreValidateRequest{Config: e.config("")})
	if !errors.Is(err, plugin.ErrUnavailable) {
		t.Errorf("network error: %v", err)
	}

	e = newEnv(t)
	ctx, cancel := context.WithCancel(e.ctx)
	cancel()
	_, err = e.ks.Validate(ctx, plugin.KeyStoreValidateRequest{Config: e.config("")})
	if !errors.Is(err, plugin.ErrUnavailable) || errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
}

func TestPEMSecret(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafPEM, chainPEM, err := fakevault.SignPublicKey(key.Public(), "a.example", []string{"a.example"})
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(key)
	bundle := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})) + leafPEM + chainPEM
	r := keyRef{vaultURL: "https://kv1.vault.azure.net", name: "web", version: "v1"}

	km, err := keyMaterial(r, plugin.KeyFormatPEM, "application/x-pem-file", bundle)
	if err != nil || !strings.Contains(string(km.Data), "BEGIN PRIVATE KEY") {
		t.Fatalf("PEM: %v", err)
	}
	km, err = keyMaterial(r, plugin.KeyFormatPFX, "application/x-pem-file", bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, chain, err := pkcs12.DecodeChain(km.Data, km.Password); err != nil || len(chain) != 1 {
		t.Errorf("PFX from PEM: %v", err)
	}
	if _, err := keyMaterial(r, plugin.KeyFormatPEM, "application/x-pem-file", leafPEM); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("PEM without key: %v", err)
	}
	if _, err := keyMaterial(r, plugin.KeyFormatPEM, "text/plain", "secret-value"); !errors.Is(err, plugin.ErrPermanent) || strings.Contains(err.Error(), "secret-value") {
		t.Errorf("unknown content type: %v", err)
	}
	if _, err := keyMaterial(r, plugin.KeyFormatPFX, "application/x-pkcs12", "!!not base64 secret!!"); !errors.Is(err, plugin.ErrPermanent) || strings.Contains(err.Error(), "secret!!") {
		t.Errorf("bad base64: %v", err)
	}
}
