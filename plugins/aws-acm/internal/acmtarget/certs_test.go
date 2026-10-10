package acmtarget

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/acm/types"
)

// Real ACM reports EC keys with a hyphen in DescribeCertificate
// ("EC-prime256v1") while the SDK enum uses an underscore.
func TestSameKeyAlgorithm(t *testing.T) {
	cases := []struct {
		a, b types.KeyAlgorithm
		want bool
	}{
		{"EC-prime256v1", types.KeyAlgorithmEcPrime256v1, true},
		{"EC-secp384r1", types.KeyAlgorithmEcSecp384r1, true},
		{types.KeyAlgorithmRsa2048, types.KeyAlgorithmRsa2048, true},
		{"EC-prime256v1", types.KeyAlgorithmRsa2048, false},
		{"EC-prime256v1", types.KeyAlgorithmEcSecp384r1, false},
	}
	for _, c := range cases {
		if got := sameKeyAlgorithm(c.a, c.b); got != c.want {
			t.Errorf("sameKeyAlgorithm(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// A placeholder imported without a key usage extension shows as ANY in ACM,
// and ACM refuses to re-import a certificate that restricts key usage.
func TestReplaceProblemKeyUsageAny(t *testing.T) {
	leaf := &x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	d := &types.CertificateDetail{KeyUsages: []types.KeyUsage{{Name: types.KeyUsageNameAny}}}
	if p := keyUsageProblem(d, leaf); !strings.Contains(p, "ANY") {
		t.Fatalf("got %q, want a key usage ANY problem", p)
	}
	d = &types.CertificateDetail{ExtendedKeyUsages: []types.ExtendedKeyUsage{{Name: types.ExtendedKeyUsageNameAny}}}
	if p := keyUsageProblem(d, leaf); !strings.Contains(p, "extended key usage") {
		t.Fatalf("got %q, want an extended key usage ANY problem", p)
	}
	d = &types.CertificateDetail{KeyUsages: []types.KeyUsage{{Name: types.KeyUsageNameDigitalSignature}}, ExtendedKeyUsages: []types.ExtendedKeyUsage{{Name: types.ExtendedKeyUsageNameNone}}}
	if p := keyUsageProblem(d, leaf); p != "" {
		t.Fatalf("got %q, want no problem", p)
	}
}
