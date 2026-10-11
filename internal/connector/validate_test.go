package connector

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/pluginhost"
	"github.com/krakenkey/connector/pkg/plugin"
)

// checkerResolver is a capsResolver that also says where plugins were
// found.
type checkerResolver struct {
	capsResolver
	locs map[string]pluginhost.Location
	errs map[string]error
}

func (r checkerResolver) CheckPlugin(name string) (pluginhost.Location, error) {
	if err := r.errs[name]; err != nil {
		return pluginhost.Location{}, err
	}
	return r.locs[name], nil
}

func TestValidateShowsPlugins(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	cfg := &config.Config{
		PluginDir: "/usr/lib/krakenkey-connector/plugins",
		Plugins: map[string]config.PluginSpec{
			"azure-keyvault": {Version: "0.1.0"},
			"aws-acm":        {Version: "0.1.0", SHA256: sum},
			"custom":         {Path: "/opt/custom/plugin"},
			"broken":         {Version: "0.2.0"},
			"azure-appgw":    {},
			"unbundled":      {},
		},
		Certificates: []config.Certificate{{
			ID: 7, Names: []string{"api.example.com"},
			KeyStore: config.KeyStore{Plugin: "vault", KeyType: plugin.KeyTypeECDSAP256},
			Targets:  []config.Target{{Label: "lb", Plugin: "mat"}},
		}},
	}
	caps := capsResolver{
		ks:   plugin.KeyStoreCapabilities{Provides: []plugin.KeyFormat{plugin.KeyFormatPEM}, Exportable: true, KeyTypes: []plugin.KeyType{plugin.KeyTypeECDSAP256}},
		caps: plugin.TargetCapabilities{Accepts: []plugin.KeyFormat{plugin.KeyFormatPEM}, SupportsRollback: true},
	}
	r := checkerResolver{
		capsResolver: caps,
		locs: map[string]pluginhost.Location{
			"azure-keyvault": {Path: "/usr/lib/krakenkey-connector/plugins/azure-keyvault/0.1.0/krakenkey-connector-plugin-azure-keyvault",
				Source: pluginhost.SourcePluginDir, SHA256: sum, PinnedBy: []string{pluginhost.LockFile}},
			"aws-acm": {Path: "/var/lib/krakenkey-connector/plugins/aws-acm/0.1.0/krakenkey-connector-plugin-aws-acm",
				Source: pluginhost.SourceDataDir, SHA256: sum, PinnedBy: []string{pluginhost.PinConfig}},
			"custom": {Path: "/opt/custom/plugin", Source: pluginhost.SourcePath, SHA256: sum},
			"azure-appgw": {Path: "/usr/lib/krakenkey-connector/plugins/azure-appgw/0.3.0/krakenkey-connector-plugin-azure-appgw",
				Source: pluginhost.SourcePluginDir, Version: "0.3.0", Bundled: true, SHA256: sum, PinnedBy: []string{pluginhost.LockFile}},
		},
		errs: map[string]error{
			"broken":    errors.New("plugin broken: /usr/lib/krakenkey-connector/plugins/plugins.lock does not exist"),
			"unbundled": errors.New("plugin unbundled: no version is set and the system plugin directory has none installed"),
		},
	}

	var out bytes.Buffer
	n := Validate(context.Background(), cfg, r, nil, &out)
	report := out.String()
	for _, want := range []string{
		"Plugin dir: /usr/lib/krakenkey-connector/plugins\n",
		"  aws-acm 0.1.0: /var/lib/krakenkey-connector/plugins/aws-acm/0.1.0/krakenkey-connector-plugin-aws-acm (data dir)\n" +
			"    sha256 " + sum + ", matches the config's sha256\n",
		"  azure-keyvault 0.1.0: /usr/lib/krakenkey-connector/plugins/azure-keyvault/0.1.0/krakenkey-connector-plugin-azure-keyvault (system plugin dir)\n" +
			"    sha256 " + sum + ", matches plugins.lock\n",
		"  broken 0.2.0\n    PROBLEM: plugin broken: /usr/lib/krakenkey-connector/plugins/plugins.lock does not exist\n",
		"  custom: /opt/custom/plugin (path from the config)\n    sha256 " + sum + ", not pinned (set sha256 to pin it)\n",
		"  azure-appgw 0.3.0 (bundled, version not set): /usr/lib/krakenkey-connector/plugins/azure-appgw/0.3.0/krakenkey-connector-plugin-azure-appgw (system plugin dir)\n" +
			"    sha256 " + sum + ", matches plugins.lock\n",
		"  unbundled\n    PROBLEM: plugin unbundled: no version is set",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report does not contain %q", want)
		}
	}
	if n != 2 {
		t.Errorf("problems = %d\n%s", n, report)
	}
}
