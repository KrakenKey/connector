package keyvault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/krakenkey/connector/pkg/plugin"
	"github.com/krakenkey/connector/plugins/azure-keyvault/internal/fakevault"
)

// targetConfig is target settings for certificate name in the fake vault.
func (e *env) targetConfig(name, extra string) json.RawMessage {
	c := `{"vault":"` + e.srv.URL + `","certificate_name":"` + name + `"`
	if extra != "" {
		c += "," + extra
	}
	return json.RawMessage(c + "}")
}

func (e *env) target(t *testing.T) *Target {
	t.Helper()
	tg := NewTarget(e.ks)
	if _, err := tg.Describe(plugin.WithCoreFeatures(e.ctx, plugin.FeatureRollbackMaterial, plugin.FeatureImplicitTarget)); err != nil {
		t.Fatal(err)
	}
	return tg
}

// issued is a certificate the key store issued, as the connector holds it.
type issued struct {
	ref, leafPEM, chainPEM string
	serial                 string
}

func (e *env) issued(t *testing.T, cfg json.RawMessage) issued {
	t.Helper()
	ref, leafPEM, chainPEM, _ := e.issue(t, cfg)
	b, _ := pem.Decode([]byte(leafPEM))
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return issued{ref: ref, leafPEM: leafPEM, chainPEM: chainPEM, serial: fmt.Sprintf("%x", leaf.SerialNumber)}
}

// vaultRef exports the key store's vault reference for a key.
func (e *env) vaultRef(t *testing.T, cfg json.RawMessage, ref string) plugin.KeyMaterial {
	t.Helper()
	km, err := e.ks.Export(e.ctx, plugin.ExportRequest{Config: cfg, KeyRef: ref, Format: plugin.KeyFormatVaultRef})
	if err != nil {
		t.Fatal(err)
	}
	return km
}

// deploy stages and activates c on the target with key km.
func (e *env) deploy(t *testing.T, tg *Target, cfg json.RawMessage, c issued, km plugin.KeyMaterial) (string, error) {
	t.Helper()
	staged, err := tg.Stage(e.ctx, plugin.StageRequest{Config: cfg, CertificateID: "7", Label: "kv",
		CertPEM: c.leafPEM, ChainPEM: c.chainPEM, FullChainPEM: c.leafPEM + c.chainPEM, Key: km, Serial: c.serial})
	if err != nil {
		return "", err
	}
	return tg.Activate(e.ctx, plugin.ActivateRequest{Config: cfg, StagedRef: staged, CertificateID: "7", Label: "kv"})
}

func (e *env) current(t *testing.T, tg *Target, cfg json.RawMessage) string {
	t.Helper()
	s, err := tg.Current(e.ctx, plugin.CurrentRequest{Config: cfg, CertificateID: "7"})
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	return s
}

func (e *env) calls(op string) int {
	n := 0
	for _, c := range e.srv.Calls() {
		if strings.HasPrefix(c, op+" ") {
			n++
		}
	}
	return n
}

func TestTargetDescribe(t *testing.T) {
	e := newEnv(t)
	tg := NewTarget(e.ks)
	if _, err := tg.Describe(e.ctx); !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "rollback_material") {
		t.Errorf("Describe without the core feature: %v", err)
	}
	if p, _ := tg.Validate(e.ctx, plugin.TargetValidateRequest{Config: e.targetConfig("web", "")}); len(p) != 1 || !strings.Contains(p[0], "upgrade the connector") {
		t.Errorf("Validate after a refused Describe = %q", p)
	}
	caps, err := tg.Describe(plugin.WithCoreFeatures(e.ctx, plugin.FeatureRollbackMaterial))
	if err != nil || !caps.RollbackNeedsMaterial || !caps.SupportsRollback || !caps.NeedsExportableKey || !caps.PropagatesAsync ||
		len(caps.Accepts) != 3 || len(caps.KeyTypes) != len(plugin.AllKeyTypes) {
		t.Errorf("caps = %+v, %v", caps, err)
	}
}

func TestParseTargetConfig(t *testing.T) {
	s, p := parseTargetConfig(json.RawMessage(`{"vault":"KV-Prod","certificate_name":"Web-1"}`))
	if len(p) != 0 || s.vaultURL != "https://kv-prod.vault.azure.net" || !s.exportable || s.adopt || s.id() != "https://kv-prod.vault.azure.net/certificates/web-1" {
		t.Errorf("defaults: %+v %q", s, p)
	}
	s, p = parseTargetConfig(json.RawMessage(`{"vault":"https://kv-prod.vault.azure.net/","certificate_name":"web-1","exportable":false,"adopt":true,"tags":{"env":"prod"}}`))
	if len(p) != 0 || s.exportable || !s.adopt || s.tags["env"] != "prod" || s.id() != "https://kv-prod.vault.azure.net/certificates/web-1" {
		t.Errorf("settings: %+v %q", s, p)
	}
	for raw, want := range map[string]string{
		`{}`:                  "vault is required",
		`{"vault":"kv-prod"}`: "certificate_name is required",
		`{"vault":"kv-prod","certificate_name":"a_b"}`:                                                 "not a valid Key Vault object name",
		`{"vault":"kv-prod","certificate_name":"a","content_type":"pem"}`:                              "unknown field",
		`{"vault":"kv-prod","certificate_name":"a","tags":{"krakenkey-connector-certificate-id":"1"}}`: "set by the connector",
		`{"vault":"kv-prod","certificate_name":"a","tags":{"":"1"}}`:                                   "must be 1-512 characters",
		`{"vault":"kv-prod","certificate_name":"a","tags":{"k":"` + strings.Repeat("v", 257) + `"}}`:   "longer than 256",
	} {
		if _, p := parseTargetConfig(json.RawMessage(raw)); !strings.Contains(strings.Join(p, "; "), want) {
			t.Errorf("%s: problems %q, want %q", raw, p, want)
		}
	}
	many := map[string]string{}
	for i := range 15 {
		many[fmt.Sprintf("t%d", i)] = "x"
	}
	b, _ := json.Marshal(TargetConfig{Vault: "kv-prod", CertificateName: "a", Tags: many})
	if _, p := parseTargetConfig(b); !strings.Contains(strings.Join(p, "; "), "at most 14 tags") {
		t.Errorf("15 tags: %q", p)
	}
}

func TestKeyStoreImplicitTarget(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct {
		extra      string
		exportable bool
	}{{"", true}, {`"exportable":false,"adopt":true`, false}} {
		v, err := e.ks.ValidateCapabilities(e.ctx, plugin.KeyStoreValidateRequest{Config: e.config(c.extra), CertificateID: "7"})
		if err != nil || len(v.Problems) != 0 || v.Capabilities == nil || v.Capabilities.ImplicitTarget == nil {
			t.Fatalf("ValidateCapabilities = %+v, %v", v, err)
		}
		if v.Capabilities.Exportable != c.exportable {
			t.Errorf("exportable = %t, want %t", v.Capabilities.Exportable, c.exportable)
		}
		it := v.Capabilities.ImplicitTarget
		if it.DeploymentID != e.srv.URL+"/certificates/web" {
			t.Errorf("deployment id = %q", it.DeploymentID)
		}
		s, p := parseTargetConfig(it.Config)
		if len(p) != 0 || s.id() != it.DeploymentID || s.exportable != c.exportable || s.adopt != !c.exportable {
			t.Errorf("implicit settings %s: %+v %q", it.Config, s, p)
		}
		// The target recognizes those settings as the key store's own.
		tv, err := e.target(t).ValidateDeployment(e.ctx, plugin.TargetValidateRequest{Config: it.Config, CertificateID: "7", KeyStoreDeploymentID: it.DeploymentID})
		if err != nil || tv.DeploymentID != it.DeploymentID || len(tv.Problems) != 0 {
			t.Errorf("target validate = %+v, %v", tv, err)
		}
	}

	// Bad settings: problems, no capabilities. A Key Vault error is a
	// problem, and the capabilities still arrive.
	if v, _ := e.ks.ValidateCapabilities(e.ctx, plugin.KeyStoreValidateRequest{Config: json.RawMessage(`{}`)}); v.Capabilities != nil || len(v.Problems) == 0 {
		t.Errorf("bad settings: %+v", v)
	}
	e.srv.Deny(fakevault.OpGetPolicy)
	v, err := e.ks.ValidateCapabilities(e.ctx, plugin.KeyStoreValidateRequest{Config: e.config(""), CertificateID: "7"})
	if err != nil || v.Capabilities == nil || len(v.Problems) != 1 || !strings.Contains(v.Problems[0], "certificates/read") {
		t.Errorf("denied: %+v, %v", v, err)
	}
}

func TestMatchWithTarget(t *testing.T) {
	e := newEnv(t)
	tcaps, _ := e.target(t).Describe(plugin.WithCoreFeatures(e.ctx, plugin.FeatureRollbackMaterial))
	locked, _ := e.ks.ValidateCapabilities(e.ctx, plugin.KeyStoreValidateRequest{Config: e.config(`"exportable":false`)})
	open, _ := e.ks.ValidateCapabilities(e.ctx, plugin.KeyStoreValidateRequest{Config: e.config("")})

	// Another vault needs the key: refused when the key cannot be exported.
	if _, err := plugin.Match(*locked.Capabilities, tcaps, plugin.KeyTypeRSA2048); err == nil ||
		!strings.Contains(err.Error(), "target needs the private key, but the key store does not allow export") {
		t.Errorf("locked key store with another vault: %v", err)
	}
	if f, err := plugin.Match(*open.Capabilities, tcaps, plugin.KeyTypeRSA2048); err != nil || f != plugin.KeyFormatVaultRef {
		t.Errorf("exportable key store with another vault: %s, %v", f, err)
	}
	// The key store's own certificate works either way; rollback needs export.
	f, err := plugin.MatchKeyStoreDeployment(*locked.Capabilities, tcaps, plugin.KeyTypeRSA2048)
	if err != nil || f != plugin.KeyFormatVaultRef {
		t.Fatalf("own certificate, locked: %s, %v", f, err)
	}
	if why := plugin.KeyStoreDeploymentRollbackUnavailable(*locked.Capabilities, tcaps, f); !strings.Contains(why, "does not allow export") {
		t.Errorf("rollback unavailable = %q", why)
	}
	if why := plugin.KeyStoreDeploymentRollbackUnavailable(*open.Capabilities, tcaps, f); why != "" {
		t.Errorf("rollback unavailable with export = %q", why)
	}
}

func TestTargetValidate(t *testing.T) {
	e := newEnv(t)
	tg := e.target(t)
	validate := func(cfg json.RawMessage, ksID string) plugin.TargetValidation {
		t.Helper()
		v, err := tg.ValidateDeployment(e.ctx, plugin.TargetValidateRequest{Config: cfg, CertificateID: "7", KeyStoreDeploymentID: ksID})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	// Missing certificate: fine, created on the first import.
	if v := validate(e.targetConfig("Web-DR", ""), ""); len(v.Problems) != 0 || v.DeploymentID != e.srv.URL+"/certificates/web-dr" {
		t.Errorf("missing = %+v", v)
	}
	// Somebody else's certificate.
	if err := e.srv.AddVersion("manual", nil); err != nil {
		t.Fatal(err)
	}
	if v := validate(e.targetConfig("manual", ""), ""); len(v.Problems) != 1 || !strings.Contains(v.Problems[0], "adopt: true") {
		t.Errorf("untagged = %+v", v)
	}
	if v := validate(e.targetConfig("manual", `"adopt":true`), ""); len(v.Problems) != 0 {
		t.Errorf("adopted = %+v", v)
	}
	// The key store's own certificate: no checks in Key Vault.
	if v := validate(e.targetConfig("manual", ""), e.srv.URL+"/certificates/MANUAL"); len(v.Problems) != 1 {
		t.Errorf("ids compare exactly; a different spelling is not the key store's = %+v", v)
	}
	before := len(e.srv.Calls())
	if v := validate(e.targetConfig("manual", ""), e.srv.URL+"/certificates/manual"); len(v.Problems) != 0 {
		t.Errorf("own certificate = %+v", v)
	}
	if len(e.srv.Calls()) != before {
		t.Error("validating the key store's own certificate called Key Vault")
	}
	// Soft-deleted name.
	e.srv.SoftDelete("manual")
	if v := validate(e.targetConfig("manual", ""), ""); len(v.Problems) != 1 || !strings.Contains(v.Problems[0], "soft-deleted") {
		t.Errorf("soft-deleted = %+v", v)
	}
	// A 403 is a problem naming the permission, with the id kept.
	e.srv.Deny(fakevault.OpGetCert)
	if v := validate(e.targetConfig("other", ""), ""); len(v.Problems) != 1 || !strings.Contains(v.Problems[0], "certificates/read") || v.DeploymentID == "" {
		t.Errorf("denied = %+v", v)
	}
	// Bad settings: problems, and no id without a vault and name.
	if v := validate(json.RawMessage(`{"vault":"kv-prod"}`), ""); len(v.Problems) == 0 || v.DeploymentID != "" {
		t.Errorf("bad = %+v", v)
	}
	if v := validate(json.RawMessage(`{"vault":"kv-prod","certificate_name":"a","tags":{"":"x"}}`), ""); len(v.Problems) == 0 || v.DeploymentID == "" {
		t.Errorf("bad tags keep the id = %+v", v)
	}
}

// TestOwnCertificateInPlace deploys to the key store's own certificate:
// nothing is imported and no secret is read.
func TestOwnCertificateInPlace(t *testing.T) {
	e := newEnv(t)
	ksCfg := e.config("")
	tCfg := e.targetConfig("web", "")
	tg := e.target(t)
	if got := e.current(t, tg, tCfg); got != "" {
		t.Errorf("Current before the first issuance = %q", got)
	}
	e.srv.Deny(fakevault.OpGetSecret)

	first := e.issued(t, ksCfg)
	prev, err := e.deploy(t, tg, tCfg, first, e.vaultRef(t, ksCfg, first.ref))
	if err != nil || prev != "" {
		t.Fatalf("first deployment = %q, %v", prev, err)
	}
	second := e.issued(t, ksCfg)
	prev, err = e.deploy(t, tg, tCfg, second, e.vaultRef(t, ksCfg, second.ref))
	if err != nil || prev != refPrefix+first.serial {
		t.Fatalf("second deployment = %q, %v; want previous %s", prev, err, first.serial)
	}
	if n := len(e.srv.Versions("web")); n != 2 || e.calls(fakevault.OpImport) != 0 || e.calls(fakevault.OpGetSecret) != 0 {
		t.Errorf("versions %d, imports %d, secret reads %d", n, e.calls(fakevault.OpImport), e.calls(fakevault.OpGetSecret))
	}
	if got := e.current(t, tg, tCfg); got != second.serial {
		t.Errorf("Current = %s, want %s", got, second.serial)
	}
	// Activating again finds it in place again (idempotent).
	prev, err = e.deploy(t, tg, tCfg, second, e.vaultRef(t, ksCfg, second.ref))
	if err != nil || prev != refPrefix+first.serial || len(e.srv.Versions("web")) != 2 {
		t.Errorf("re-activate = %q, %v", prev, err)
	}

	// A disabled latest version serves nobody: Current says nothing.
	e.srv.DisableVersion("web", "")
	if got := e.current(t, tg, tCfg); got != "" {
		t.Errorf("Current with a disabled latest version = %q", got)
	}
}

// TestPreviousVersionFromTag: versions the connector creates name the one
// they replaced, so creation times do not matter.
func TestPreviousVersionFromTag(t *testing.T) {
	e := newEnv(t)
	e.srv.SetClockStep(0) // every version in the same second
	ksCfg := e.config("")
	tCfg := e.targetConfig("web", "")
	tg := e.target(t)
	e.issued(t, ksCfg)
	b := e.issued(t, ksCfg)
	c := e.issued(t, ksCfg)
	versions := e.srv.Versions("web")
	if got := e.srv.Tags("web", "")[tagPreviousVersion]; got != versions[1] {
		t.Fatalf("merged version names %q as previous, want %q", got, versions[1])
	}
	prev, err := e.deploy(t, tg, tCfg, c, e.vaultRef(t, ksCfg, c.ref))
	if err != nil || prev != refPrefix+b.serial {
		t.Errorf("previous = %q, %v; want %s", prev, err, b.serial)
	}
	if e.calls(fakevault.OpListVersions) != 0 {
		t.Error("versions listed although the tag names the previous one")
	}
	// A disabled previous version served nobody: nothing to go back to.
	e.srv.DisableVersion("web", versions[1])
	if prev, err := e.deploy(t, tg, tCfg, c, e.vaultRef(t, ksCfg, c.ref)); err != nil || prev != "" {
		t.Errorf("previous with the replaced version disabled = %q, %v", prev, err)
	}
}

// TestPreviousVersionByTime covers versions created outside the connector,
// which carry no tag: creation times decide, and a tie in the deciding
// second gives no previous version rather than a guess.
func TestPreviousVersionByTime(t *testing.T) {
	cases := map[string]struct {
		steps []time.Duration // clock step before each of three versions
		deny  bool
		want  int // index of the expected previous version, -1 for none
	}{
		"latest before":          {[]time.Duration{time.Minute, time.Minute, time.Minute}, false, 1},
		"same second as current": {[]time.Duration{time.Minute, time.Minute, 0}, false, -1},
		"tie before":             {[]time.Duration{time.Minute, 0, time.Minute}, false, -1},
		"older tie is fine":      {[]time.Duration{time.Minute, 0, time.Minute, time.Minute}, false, 2},
		"cannot list":            {[]time.Duration{time.Minute, time.Minute, time.Minute}, true, -1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.srv.SetPageSize(1)
			for _, step := range tc.steps {
				e.srv.SetClockStep(step)
				if err := e.srv.AddVersion("ext", map[string]string{tagCertificateID: "7"}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.deny {
				e.srv.Deny(fakevault.OpListVersions)
			}
			s, _ := parseTargetConfig(e.targetConfig("ext", ""))
			c, err := e.ks.clientsFor(s.vaultURL)
			if err != nil {
				t.Fatal(err)
			}
			cur, _, err := getVersion(e.ctx, c, "ext", "")
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			if tc.want >= 0 {
				want = refPrefix + e.srv.Serial("ext", e.srv.Versions("ext")[tc.want])
			}
			if got := e.target(t).previousRef(e.ctx, c, "ext", cur); got != want {
				t.Errorf("previous = %q, want %q", got, want)
			}
		})
	}
}

// TestOwnCertificateRollback puts the previous certificate back as a new
// latest version, from the key the key store still holds.
func TestOwnCertificateRollback(t *testing.T) {
	e := newEnv(t)
	ksCfg := e.config("")
	tCfg := e.targetConfig("web", "")
	tg := e.target(t)
	first := e.issued(t, ksCfg)
	if _, err := e.deploy(t, tg, tCfg, first, e.vaultRef(t, ksCfg, first.ref)); err != nil {
		t.Fatal(err)
	}
	second := e.issued(t, ksCfg)
	prev, err := e.deploy(t, tg, tCfg, second, e.vaultRef(t, ksCfg, second.ref))
	if err != nil {
		t.Fatal(err)
	}
	rollback := func(req plugin.RollbackRequest) error {
		req.Config, req.CertificateID, req.Label = tCfg, "7", "kv"
		if req.PreviousRef == "" {
			req.PreviousRef = prev
		}
		return tg.Rollback(e.ctx, req)
	}
	material := plugin.RollbackRequest{
		PreviousCertPEM: first.leafPEM, PreviousChainPEM: first.chainPEM, PreviousFullChainPEM: first.leafPEM + first.chainPEM,
		PreviousKey: e.vaultRef(t, ksCfg, first.ref), PreviousSerial: first.serial,
	}

	// Without material, or with material for another certificate: refused.
	if err := rollback(plugin.RollbackRequest{}); !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "cannot reinstate an older version") {
		t.Errorf("without material: %v", err)
	}
	wrong := material
	wrong.PreviousSerial = second.serial
	if err := rollback(wrong); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("wrong serial: %v", err)
	}
	if err := rollback(plugin.RollbackRequest{PreviousRef: "bogus"}); !errors.Is(err, plugin.ErrInvalid) {
		t.Errorf("bad ref: %v", err)
	}
	if err := rollback(plugin.RollbackRequest{PreviousRef: ""}); err == nil {
		t.Error("rollback of the first version must fail")
	}
	if len(e.srv.Versions("web")) != 2 {
		t.Fatal("a refused rollback changed the vault")
	}

	if err := rollback(material); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	versions := e.srv.Versions("web")
	if len(versions) != 3 || e.srv.Serial("web", "") != first.serial || e.current(t, tg, tCfg) != first.serial {
		t.Fatalf("after rollback: %d versions, latest %s", len(versions), e.srv.Serial("web", ""))
	}
	if tags := e.srv.Tags("web", ""); tags[tagCertificateID] != "7" {
		t.Errorf("rolled back version tags = %v", tags)
	}
	if e.srv.Chain("web", "") != 2 || !e.srv.Exportable("web", "") {
		t.Errorf("rolled back version: chain %d, exportable %t", e.srv.Chain("web", ""), e.srv.Exportable("web", ""))
	}
	// The key store still owns the certificate and renews it.
	if _, err := e.ks.CreateCSR(e.ctx, plugin.CSRRequest{Config: ksCfg, CertificateID: "7", Names: []string{"www.example.com"}, KeyType: plugin.KeyTypeECDSAP256}); err != nil {
		t.Errorf("key store after rollback: %v", err)
	}
	// Rolling back again is a no-op.
	if err := rollback(material); err != nil || e.calls(fakevault.OpImport) != 1 {
		t.Errorf("second rollback: %v, imports %d", err, e.calls(fakevault.OpImport))
	}
}

func TestOwnCertificateRollbackNotExportable(t *testing.T) {
	e := newEnv(t)
	ksCfg := e.config(`"exportable":false`)
	tCfg := e.targetConfig("web", `"exportable":false`)
	tg := e.target(t)
	first := e.issued(t, ksCfg)
	second := e.issued(t, ksCfg)
	prev, err := e.deploy(t, tg, tCfg, second, e.vaultRef(t, ksCfg, second.ref))
	if err != nil || prev != refPrefix+first.serial {
		t.Fatalf("deploy = %q, %v", prev, err)
	}
	err = tg.Rollback(e.ctx, plugin.RollbackRequest{Config: tCfg, PreviousRef: prev, CertificateID: "7",
		PreviousCertPEM: first.leafPEM, PreviousChainPEM: first.chainPEM, PreviousKey: e.vaultRef(t, ksCfg, first.ref), PreviousSerial: first.serial})
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "not exportable") {
		t.Errorf("rollback = %v", err)
	}
	if e.srv.Serial("web", "") != second.serial || e.calls(fakevault.OpImport) != 0 {
		t.Error("a refused rollback changed the vault")
	}
}

// TestImportToAnotherVault deploys a Key Vault certificate to another
// certificate name by reading the source secret and importing it.
func TestImportToAnotherVault(t *testing.T) {
	e := newEnv(t)
	ksCfg := e.config("")
	tCfg := e.targetConfig("web-dr", `"tags":{"env":"dr"},"exportable":false`)
	tg := e.target(t)

	first := e.issued(t, ksCfg)
	prev, err := e.deploy(t, tg, tCfg, first, e.vaultRef(t, ksCfg, first.ref))
	if err != nil || prev != "" {
		t.Fatalf("first import = %q, %v", prev, err)
	}
	if e.srv.Serial("web-dr", "") != first.serial || e.current(t, tg, tCfg) != first.serial {
		t.Fatalf("imported serial = %s", e.srv.Serial("web-dr", ""))
	}
	tags := e.srv.Tags("web-dr", "")
	if tags[tagCertificateID] != "7" || tags["env"] != "dr" || e.srv.Exportable("web-dr", "") || e.srv.Chain("web-dr", "") != 2 {
		t.Errorf("imported version: tags %v, exportable %t, chain %d", tags, e.srv.Exportable("web-dr", ""), e.srv.Chain("web-dr", ""))
	}
	imp := e.srv.Imports()[0]
	if pol := imp.Policy; pol == nil || pol.SecretProperties == nil || *pol.SecretProperties.ContentType != contentTypePKCS12 ||
		pol.KeyProperties == nil || *pol.KeyProperties.KeyType != "EC" || *pol.KeyProperties.Curve != "P-256" {
		t.Errorf("import policy = %+v", imp.Policy)
	}

	second := e.issued(t, ksCfg)
	prev, err = e.deploy(t, tg, tCfg, second, e.vaultRef(t, ksCfg, second.ref))
	if err != nil || prev != refPrefix+first.serial || len(e.srv.Versions("web-dr")) != 2 {
		t.Fatalf("second import = %q, %v", prev, err)
	}
	// Activating the same certificate again imports nothing.
	prev, err = e.deploy(t, tg, tCfg, second, e.vaultRef(t, ksCfg, second.ref))
	if err != nil || prev != refPrefix+first.serial || e.calls(fakevault.OpImport) != 2 {
		t.Errorf("re-activate = %q, %v, imports %d", prev, err, e.calls(fakevault.OpImport))
	}
	// Rollback re-imports the first certificate.
	err = tg.Rollback(e.ctx, plugin.RollbackRequest{Config: tCfg, PreviousRef: prev, CertificateID: "7",
		PreviousCertPEM: first.leafPEM, PreviousChainPEM: first.chainPEM, PreviousKey: e.vaultRef(t, ksCfg, first.ref), PreviousSerial: first.serial})
	if err != nil || e.srv.Serial("web-dr", "") != first.serial {
		t.Errorf("rollback = %v, latest %s", err, e.srv.Serial("web-dr", ""))
	}
}

// localKey is a certificate with its key as PEM, as the local key store
// hands it over.
func localKey(t *testing.T) (issued, plugin.KeyMaterial, plugin.KeyMaterial) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, chainPEM, err := fakevault.SignPublicKey(key.Public(), "api.example.com", []string{"api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	b, _ := pem.Decode([]byte(leafPEM))
	leaf, _ := x509.ParseCertificate(b.Bytes)
	pfx, err := pkcs12.Modern.Encode(key, leaf, nil, "pw")
	if err != nil {
		t.Fatal(err)
	}
	return issued{leafPEM: leafPEM, chainPEM: chainPEM, serial: fmt.Sprintf("%x", leaf.SerialNumber)},
		plugin.KeyMaterial{Format: plugin.KeyFormatPEM, Data: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})},
		plugin.KeyMaterial{Format: plugin.KeyFormatPFX, Data: pfx, Password: "pw"}
}

func TestImportFromLocalKey(t *testing.T) {
	e := newEnv(t)
	tg := e.target(t)
	for i, pick := range []int{1, 2} {
		c, pemKey, pfxKey := localKey(t)
		km := []plugin.KeyMaterial{{}, pemKey, pfxKey}[pick]
		if _, err := e.deploy(t, tg, e.targetConfig("api", ""), c, km); err != nil {
			t.Fatalf("%s: %v", km.Format, err)
		}
		if e.srv.Serial("api", "") != c.serial || len(e.srv.Versions("api")) != i+1 {
			t.Errorf("%s: latest %s", km.Format, e.srv.Serial("api", ""))
		}
		if pol := e.srv.Imports()[i].Policy; *pol.KeyProperties.Curve != "P-384" {
			t.Errorf("curve = %s", *pol.KeyProperties.Curve)
		}
	}
}

func TestStageRefusals(t *testing.T) {
	e := newEnv(t)
	tg := e.target(t)
	c, pemKey, _ := localKey(t)
	other, otherKey, _ := localKey(t)
	cfg := e.targetConfig("api", "")
	stage := func(c issued, km plugin.KeyMaterial, serial string, cfg json.RawMessage) error {
		_, err := tg.Stage(e.ctx, plugin.StageRequest{Config: cfg, CertificateID: "7", CertPEM: c.leafPEM, ChainPEM: c.chainPEM, Key: km, Serial: serial})
		return err
	}
	if err := stage(c, otherKey, c.serial, cfg); !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("wrong key: %v", err)
	}
	if err := stage(c, pemKey, other.serial, cfg); !errors.Is(err, plugin.ErrInvalid) {
		t.Errorf("wrong serial: %v", err)
	}
	if err := stage(c, plugin.KeyMaterial{}, c.serial, cfg); !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "the key is needed") {
		t.Errorf("no key: %v", err)
	}
	if err := stage(c, plugin.KeyMaterial{Format: plugin.KeyFormatVaultRef, Ref: "arn:aws:secretsmanager:x"}, c.serial, cfg); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("foreign vault ref: %v", err)
	}
	if err := stage(c, pemKey, c.serial, json.RawMessage(`{}`)); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("bad settings: %v", err)
	}
	if err := stage(issued{leafPEM: "junk"}, pemKey, "", cfg); !errors.Is(err, plugin.ErrInvalid) {
		t.Errorf("bad certificate: %v", err)
	}
	for _, s := range e.srv.Calls() {
		if strings.Contains(s, "PRIVATE KEY") {
			t.Error("key material in a call record")
		}
	}

	// Ownership: an untagged certificate is refused unless adopt is set.
	if err := e.srv.AddVersion("manual", nil); err != nil {
		t.Fatal(err)
	}
	if err := stage(c, pemKey, c.serial, e.targetConfig("manual", "")); !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "adopt: true") {
		t.Errorf("untagged: %v", err)
	}
	if _, err := e.deploy(t, tg, e.targetConfig("manual", `"adopt":true`), c, pemKey); err != nil || e.srv.Serial("manual", "") != c.serial {
		t.Errorf("adopt: %v", err)
	}
	if tags := e.srv.Tags("manual", ""); tags[tagCertificateID] != "7" {
		t.Errorf("adopted version tags = %v", tags)
	}

	if _, err := tg.Activate(e.ctx, plugin.ActivateRequest{Config: cfg, StagedRef: "staged-unknown", CertificateID: "7"}); !errors.Is(err, plugin.ErrNotFound) {
		t.Errorf("unknown staged ref: %v", err)
	}
	if err := tg.Discard(e.ctx, plugin.DiscardRequest{StagedRef: "staged-unknown"}); err != nil {
		t.Errorf("Discard(unknown): %v", err)
	}
}

func TestActivateFailures(t *testing.T) {
	e := newEnv(t)
	tg := e.target(t)
	cfg := e.targetConfig("api", "")
	first, firstKey, _ := localKey(t)
	if _, err := e.deploy(t, tg, cfg, first, firstKey); err != nil {
		t.Fatal(err)
	}
	c, key, _ := localKey(t)

	// A failed import leaves the previous version current.
	e.srv.FailNext(fakevault.OpImport, http.StatusInternalServerError)
	if _, err := e.deploy(t, tg, cfg, c, key); !errors.Is(err, plugin.ErrUnavailable) {
		t.Errorf("500: %v", err)
	}
	if got := e.current(t, tg, cfg); got != first.serial {
		t.Errorf("Current after a failed import = %s, want %s", got, first.serial)
	}
	// A 403 names the permission.
	e.srv.Deny(fakevault.OpImport)
	if _, err := e.deploy(t, tg, cfg, c, key); !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "certificates/import/action") {
		t.Errorf("403: %v", err)
	}
	e.srv.Allow(fakevault.OpImport)
	// An import that went through although its answer was lost counts.
	e.srv.ApplyThenFail(fakevault.OpImport, http.StatusServiceUnavailable)
	prev, err := e.deploy(t, tg, cfg, c, key)
	if err != nil || prev != refPrefix+first.serial || e.current(t, tg, cfg) != c.serial {
		t.Errorf("lost answer: %q, %v", prev, err)
	}

	// Staged for one certificate, activated with settings for another.
	d, dKey, _ := localKey(t)
	staged, err := tg.Stage(e.ctx, plugin.StageRequest{Config: cfg, CertificateID: "7", CertPEM: d.leafPEM, ChainPEM: d.chainPEM, Key: dKey, Serial: d.serial})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tg.Activate(e.ctx, plugin.ActivateRequest{Config: e.targetConfig("other", ""), StagedRef: staged, CertificateID: "7"}); !errors.Is(err, plugin.ErrPermanent) {
		t.Errorf("moved target: %v", err)
	}
	// Discarded material is gone.
	staged, _ = tg.Stage(e.ctx, plugin.StageRequest{Config: cfg, CertificateID: "7", CertPEM: d.leafPEM, ChainPEM: d.chainPEM, Key: dKey, Serial: d.serial})
	if err := tg.Discard(e.ctx, plugin.DiscardRequest{StagedRef: staged}); err != nil {
		t.Fatal(err)
	}
	if _, err := tg.Activate(e.ctx, plugin.ActivateRequest{Config: cfg, StagedRef: staged, CertificateID: "7"}); !errors.Is(err, plugin.ErrNotFound) {
		t.Errorf("activate after discard: %v", err)
	}
}

func TestStagedMaterialExpires(t *testing.T) {
	e := newEnv(t)
	tg := e.target(t)
	tg.ttl = 0
	c, key, _ := localKey(t)
	cfg := e.targetConfig("api", "")
	staged, err := tg.Stage(e.ctx, plugin.StageRequest{Config: cfg, CertificateID: "7", CertPEM: c.leafPEM, ChainPEM: c.chainPEM, Key: key, Serial: c.serial})
	if err != nil {
		t.Fatal(err)
	}
	for range 100 {
		tg.mu.Lock()
		n := len(tg.staged)
		tg.mu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := tg.Activate(e.ctx, plugin.ActivateRequest{Config: cfg, StagedRef: staged, CertificateID: "7"}); !errors.Is(err, plugin.ErrNotFound) {
		t.Errorf("activate after the TTL: %v", err)
	}
}

// azureDenial is what Key Vault says when an access policy lacks a
// permission: it names the caller and its tenant.
const azureDenial = "The user, group or application 'appid=11111111-2222-3333-4444-555555555555;oid=66666666-7777-8888-9999-000000000000;iss=https://sts.windows.net/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/' does not have certificates create permission on key vault 'kv-b;location=westeurope'."

// azureRBACDenial is what Key Vault says when an RBAC role lacks a data
// action.
const azureRBACDenial = "Caller is not authorized to perform action on resource. If role assignments, deny assignments or role definitions were changed recently, please observe propagation time. Caller: appid=11111111-2222-3333-4444-555555555555;oid=66666666-7777-8888-9999-000000000000;iss=https://sts.windows.net/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/ Action: 'Microsoft.KeyVault/vaults/certificates/import/action' Resource: '/subscriptions/12345678-1234-1234-1234-123456789012/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv-b/certificates/kvt-copy' Assignment: (not found)"

func checkScrubbed(t *testing.T, err error) {
	t.Helper()
	for _, leak := range []string{"11111111-2222", "66666666-7777", "aaaaaaaa-bbbb", "12345678-1234", "sts.windows.net", "appid", "oid="} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error leaks %q: %v", leak, err)
		}
	}
}

// TestTargetNeverReadsPendingRequests: reading a pending request needs
// certificate permission Create in access policy vaults, which an import
// target does not have.
func TestTargetNeverReadsPendingRequests(t *testing.T) {
	e := newEnv(t)
	e.srv.Deny(fakevault.OpGetPending)
	tg := e.target(t)
	cfg := e.targetConfig("kvt-copy", "")
	if v, err := tg.ValidateDeployment(e.ctx, plugin.TargetValidateRequest{Config: cfg, CertificateID: "7"}); err != nil || len(v.Problems) != 0 {
		t.Fatalf("validate = %+v, %v", v, err)
	}
	c, key, _ := localKey(t)
	if _, err := e.deploy(t, tg, cfg, c, key); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if n := e.calls(fakevault.OpGetPending); n != 0 {
		t.Errorf("the target read pending requests %d times", n)
	}
}

// TestPermissionHintsAndScrubbing: a 403 names the permission Key Vault
// says is missing, and never the caller's ids or tenant.
func TestPermissionHintsAndScrubbing(t *testing.T) {
	e := newEnv(t)
	// Access policy vault: reading a pending request needs Create.
	e.srv.FailNextWith(fakevault.OpGetPending, http.StatusForbidden, azureDenial, "AccessDenied")
	_, err := e.ks.CreateCSR(e.ctx, plugin.CSRRequest{Config: e.config(""), CertificateID: "7", Names: []string{"a.example.com"}, KeyType: plugin.KeyTypeECDSAP256})
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "certificate permission Create in the vault access policy") ||
		!strings.Contains(err.Error(), "HTTP 403, Forbidden/AccessDenied") {
		t.Errorf("pending 403: %v", err)
	}
	checkScrubbed(t, err)

	// RBAC vault: the denied data action from Key Vault's answer.
	tg := e.target(t)
	c, key, _ := localKey(t)
	e.srv.FailNextWith(fakevault.OpImport, http.StatusForbidden, azureRBACDenial, "ForbiddenByRbac")
	_, err = e.deploy(t, tg, e.targetConfig("kvt-copy", ""), c, key)
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "grant the identity Microsoft.KeyVault/vaults/certificates/import/action") {
		t.Errorf("import 403: %v", err)
	}
	checkScrubbed(t, err)

	// Without a named permission, the operation's own hint.
	e.srv.Deny(fakevault.OpGetCert)
	_, err = tg.Current(e.ctx, plugin.CurrentRequest{Config: e.targetConfig("kvt-copy", "")})
	if !strings.Contains(err.Error(), "Microsoft.KeyVault/vaults/certificates/read") || !strings.Contains(err.Error(), "certificate permission Get") {
		t.Errorf("get 403: %v", err)
	}
	if got := scrub("token from https://sts.windows.net/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/ for 11111111-2222-3333-4444-555555555555"); got != "token from <issuer> for <id>" {
		t.Errorf("scrub = %q", got)
	}
}

func TestRollbackImportFailures(t *testing.T) {
	setup := func(t *testing.T) (*env, *Target, json.RawMessage, issued, plugin.KeyMaterial, string) {
		e := newEnv(t)
		tg := e.target(t)
		cfg := e.targetConfig("api", "")
		first, firstKey, _ := localKey(t)
		if _, err := e.deploy(t, tg, cfg, first, firstKey); err != nil {
			t.Fatal(err)
		}
		second, secondKey, _ := localKey(t)
		prev, err := e.deploy(t, tg, cfg, second, secondKey)
		if err != nil || prev != refPrefix+first.serial {
			t.Fatalf("deploy: %q, %v", prev, err)
		}
		return e, tg, cfg, first, firstKey, prev
	}
	rollback := func(e *env, tg *Target, cfg json.RawMessage, first issued, key plugin.KeyMaterial, prev string) error {
		return tg.Rollback(e.ctx, plugin.RollbackRequest{Config: cfg, PreviousRef: prev, CertificateID: "7",
			PreviousCertPEM: first.leafPEM, PreviousChainPEM: first.chainPEM, PreviousKey: key, PreviousSerial: first.serial})
	}
	t.Run("lost answer", func(t *testing.T) {
		e, tg, cfg, first, key, prev := setup(t)
		e.srv.ApplyThenFail(fakevault.OpImport, http.StatusServiceUnavailable)
		if err := rollback(e, tg, cfg, first, key, prev); err != nil || e.srv.Serial("api", "") != first.serial {
			t.Errorf("rollback = %v, latest %s", err, e.srv.Serial("api", ""))
		}
	})
	t.Run("forbidden", func(t *testing.T) {
		e, tg, cfg, first, key, prev := setup(t)
		e.srv.Deny(fakevault.OpImport)
		err := rollback(e, tg, cfg, first, key, prev)
		if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "certificates/import/action") || e.srv.Serial("api", "") == first.serial {
			t.Errorf("rollback = %v", err)
		}
	})
	t.Run("previous version named", func(t *testing.T) {
		e, tg, cfg, first, key, prev := setup(t)
		before := e.srv.Versions("api")
		if err := rollback(e, tg, cfg, first, key, prev); err != nil {
			t.Fatal(err)
		}
		if got := e.srv.Tags("api", "")[tagPreviousVersion]; got != before[len(before)-1] {
			t.Errorf("rollback version names %q as previous, want %q", got, before[len(before)-1])
		}
	})
}

func TestOwnershipChangesBetweenStageAndActivate(t *testing.T) {
	e := newEnv(t)
	tg := e.target(t)
	cfg := e.targetConfig("api", "")
	c, key, _ := localKey(t)
	staged, err := tg.Stage(e.ctx, plugin.StageRequest{Config: cfg, CertificateID: "7", CertPEM: c.leafPEM, ChainPEM: c.chainPEM, Key: key, Serial: c.serial})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.AddVersion("api", nil); err != nil {
		t.Fatal(err)
	}
	_, err = tg.Activate(e.ctx, plugin.ActivateRequest{Config: cfg, StagedRef: staged, CertificateID: "7"})
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "adopt: true") || e.calls(fakevault.OpImport) != 0 {
		t.Errorf("activate = %v, imports %d", err, e.calls(fakevault.OpImport))
	}
}

// TestOwnCertificateNotInPlaceNotExportable: when the key store's
// certificate is not the latest version any more and its key cannot be
// exported, it cannot be put back.
func TestOwnCertificateNotInPlaceNotExportable(t *testing.T) {
	e := newEnv(t)
	ksCfg := e.config(`"exportable":false`)
	tCfg := e.targetConfig("web", `"exportable":false`)
	tg := e.target(t)
	a := e.issued(t, ksCfg)
	e.issued(t, ksCfg)
	_, err := e.deploy(t, tg, tCfg, a, e.vaultRef(t, ksCfg, a.ref))
	if !errors.Is(err, plugin.ErrPermanent) || !strings.Contains(err.Error(), "not exportable") || e.calls(fakevault.OpImport) != 0 {
		t.Errorf("deploy = %v", err)
	}
}
