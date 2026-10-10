package plugin

import (
	"errors"
	"strings"
	"testing"
)

func TestMatch(t *testing.T) {
	localPEM := KeyStoreCapabilities{
		Provides:   []KeyFormat{KeyFormatPEM},
		Exportable: true,
		KeyTypes:   []KeyType{KeyTypeECDSAP256, KeyTypeRSA2048, KeyTypeRSA3072},
	}
	vaultLocked := KeyStoreCapabilities{
		Provides:   []KeyFormat{KeyFormatVaultRef, KeyFormatPFX},
		Exportable: false,
		KeyTypes:   []KeyType{KeyTypeECDSAP256, KeyTypeRSA2048},
	}
	vaultExportable := vaultLocked
	vaultExportable.Exportable = true

	fileTarget := TargetCapabilities{Accepts: []KeyFormat{KeyFormatPEM}, NeedsExportableKey: true}
	rsaOnlyPEM := TargetCapabilities{Accepts: []KeyFormat{KeyFormatPEM}, KeyTypes: []KeyType{KeyTypeRSA2048, KeyTypeRSA3072}}
	vaultTarget := TargetCapabilities{Accepts: []KeyFormat{KeyFormatVaultRef}}
	vaultTargetNeedsExport := TargetCapabilities{Accepts: []KeyFormat{KeyFormatVaultRef}, NeedsExportableKey: true}
	pfxOrRef := TargetCapabilities{Accepts: []KeyFormat{KeyFormatPFX, KeyFormatVaultRef}}
	pfxOnly := TargetCapabilities{Accepts: []KeyFormat{KeyFormatPFX}}

	tests := []struct {
		name    string
		ks      KeyStoreCapabilities
		target  TargetCapabilities
		keyType KeyType
		want    KeyFormat
		errs    []string // substrings, one per expected reason
	}{
		{name: "local key to file target", ks: localPEM, target: fileTarget, keyType: KeyTypeECDSAP256, want: KeyFormatPEM},
		{name: "rsa key to rsa-only target", ks: localPEM, target: rsaOnlyPEM, keyType: KeyTypeRSA3072, want: KeyFormatPEM},
		{name: "vault ref preferred over pfx", ks: vaultLocked, target: pfxOrRef, keyType: KeyTypeRSA2048, want: KeyFormatVaultRef},
		{name: "vault ref needs no export", ks: vaultLocked, target: vaultTarget, keyType: KeyTypeECDSAP256, want: KeyFormatVaultRef},
		{name: "exportable vault to pfx target", ks: vaultExportable, target: pfxOnly, keyType: KeyTypeRSA2048, want: KeyFormatPFX},
		{name: "no key type given, overlap exists", ks: localPEM, target: rsaOnlyPEM, want: KeyFormatPEM},
		{
			name: "ec key to rsa-only target", ks: localPEM, target: rsaOnlyPEM, keyType: KeyTypeECDSAP256,
			errs: []string{"target cannot serve ecdsa-p256 keys (accepts rsa-2048, rsa-3072)"},
		},
		{
			name: "key store cannot make the key type", ks: localPEM, target: fileTarget, keyType: KeyTypeRSA4096,
			errs: []string{"key store cannot create rsa-4096 keys (supports ecdsa-p256, rsa-2048, rsa-3072)"},
		},
		{
			name: "non-exportable key to file target", ks: vaultLocked, target: fileTarget, keyType: KeyTypeECDSAP256,
			errs: []string{
				"target needs the private key, but the key store does not allow export",
				"no key format in common: key store provides vault_ref, pfx, target accepts pem",
			},
		},
		{
			name: "non-exportable key to pfx-only target", ks: vaultLocked, target: pfxOnly, keyType: KeyTypeRSA2048,
			errs: []string{"target accepts only pfx, which carries the private key, and the key store does not allow export"},
		},
		{
			name: "vault target that needs export", ks: vaultLocked, target: vaultTargetNeedsExport, keyType: KeyTypeRSA2048,
			errs: []string{"target needs the private key, but the key store does not allow export"},
		},
		{
			name: "pem key store to vault-only target", ks: localPEM, target: vaultTarget, keyType: KeyTypeECDSAP256,
			errs: []string{"no key format in common: key store provides pem, target accepts vault_ref"},
		},
		{
			name: "no key type overlap", ks: KeyStoreCapabilities{Provides: []KeyFormat{KeyFormatPEM}, Exportable: true, KeyTypes: []KeyType{KeyTypeECDSAP256}},
			target: rsaOnlyPEM,
			errs:   []string{"no key type in common: key store creates ecdsa-p256, target accepts rsa-2048, rsa-3072"},
		},
		{
			name: "every problem reported", ks: vaultLocked, target: TargetCapabilities{Accepts: []KeyFormat{KeyFormatPEM}, NeedsExportableKey: true, KeyTypes: []KeyType{KeyTypeRSA3072}},
			keyType: KeyTypeECDSAP384,
			errs: []string{
				"key store cannot create ecdsa-p384 keys",
				"target cannot serve ecdsa-p384 keys",
				"target needs the private key",
				"no key format in common",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Match(tt.ks, tt.target, tt.keyType)
			if len(tt.errs) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Fatalf("format = %q, want %q", got, tt.want)
				}
				return
			}
			var inc *IncompatibleError
			if !errors.As(err, &inc) {
				t.Fatalf("error = %v, want *IncompatibleError", err)
			}
			if len(inc.Reasons) != len(tt.errs) {
				t.Fatalf("reasons = %q, want %d of them", inc.Reasons, len(tt.errs))
			}
			for i, want := range tt.errs {
				if !strings.Contains(inc.Reasons[i], want) {
					t.Errorf("reason %d = %q, want it to contain %q", i, inc.Reasons[i], want)
				}
			}
			if got != "" {
				t.Errorf("format = %q on error", got)
			}
		})
	}
}

func TestParseKeyType(t *testing.T) {
	for _, s := range []string{"ecdsa-p256", "ECDSA-P384", " rsa-2048 ", "rsa-3072", "rsa-4096"} {
		if _, err := ParseKeyType(s); err != nil {
			t.Errorf("ParseKeyType(%q): %v", s, err)
		}
	}
	for _, s := range []string{"", "rsa-1024", "ed25519"} {
		if _, err := ParseKeyType(s); err == nil {
			t.Errorf("ParseKeyType(%q) succeeded", s)
		}
	}
	if !KeyTypeRSA2048.IsRSA() || KeyTypeRSA2048.IsECDSA() || !KeyTypeECDSAP256.IsECDSA() {
		t.Error("IsRSA/IsECDSA wrong")
	}
}

func TestRollbackUnavailable(t *testing.T) {
	exportable := KeyStoreCapabilities{Provides: []KeyFormat{KeyFormatPEM}, Exportable: true}
	locked := KeyStoreCapabilities{Provides: []KeyFormat{KeyFormatVaultRef}}
	plain := TargetCapabilities{SupportsRollback: true}
	material := TargetCapabilities{SupportsRollback: true, RollbackNeedsMaterial: true}
	none := TargetCapabilities{}

	tests := []struct {
		name string
		ks   KeyStoreCapabilities
		t    TargetCapabilities
		want string
	}{
		{"plain target, exportable", exportable, plain, ""},
		{"plain target, locked", locked, plain, ""},
		{"material target, exportable", exportable, material, ""},
		{"material target, locked", locked, material, "does not allow export"},
		{"no rollback", exportable, none, "does not support rollback"},
	}
	for _, tt := range tests {
		got := RollbackUnavailable(tt.ks, tt.t)
		if (tt.want == "") != (got == "") || !strings.Contains(got, tt.want) {
			t.Errorf("%s: RollbackUnavailable = %q, want %q", tt.name, got, tt.want)
		}
	}
}
