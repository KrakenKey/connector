package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/krakenkey/connector/internal/api"
	"github.com/krakenkey/connector/internal/config"
	"github.com/krakenkey/connector/internal/pluginhost"
)

// ConfigSender is the API calls the config sharer uses.
type ConfigSender interface {
	PutConfigSummary(ctx context.Context, hash string, s api.ConfigSummary) error
	DeleteConfigSummary(ctx context.Context) error
}

// PluginLocator says where a plugin runs from (see pluginhost.Host.Locate).
type PluginLocator interface {
	Locate(name string) pluginhost.Location
}

// ConfigResend is how long an unchanged config summary goes without being
// sent again.
const ConfigResend = 24 * time.Hour

// summarySettings lists, by plugin name, the settings a config summary
// may include. Settings of other plugins are never sent. The file
// target's names under files are sent flattened (see fileSettings).
var summarySettings = map[string][]string{
	"azure-keyvault":   {"vault", "certificate_name", "exportable", "reuse_key", "adopt"},
	"azure-appgateway": {"resource_group", "gateway", "ssl_certificate", "replace_uploaded_certificate"},
	"aws-acm":          {"region"},
	config.BuiltinFile: {"dir"},
}

// fileNames are the keys under the file target's files setting.
var fileNames = []string{"cert", "chain", "fullchain", "key"}

// ConfigSharer sends KrakenKey a read-only summary of the config after
// passes, for the dashboard: the certificates, their key stores and
// targets (implicit ones included), and the plugins with their versions.
// Settings are taken from an allowlist (summarySettings), so commands,
// file owners and modes, tags, cloud account ids and secrets are never
// sent. With krakenkey.share_config off, it clears any summary KrakenKey
// has instead, once per process. It is used only for an enrolled
// connector, and it is not safe for concurrent use.
type ConfigSharer struct {
	API     ConfigSender
	Config  *config.Config
	Plugins PluginLocator
	Log     *slog.Logger
	// Version is the connector's version.
	Version string
	// Now defaults to time.Now.
	Now func() time.Time

	// effective holds the last certificate each pass resolved, with the
	// targets its key store added, by id.
	effective map[int]config.Certificate
	lastHash  string
	lastSent  time.Time
	cleared   bool
	// unsupported is set once KrakenKey answers 404 or 405: it does not
	// have the route, so nothing is sent until the connector restarts.
	unsupported bool
}

func (s *ConfigSharer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Remember keeps the certificates as a pass resolved them (see BuildJob),
// for this and later summaries. Certificates a pass did not process keep
// what an earlier pass resolved, or the configured targets.
func (s *ConfigSharer) Remember(certs map[int]config.Certificate) {
	if s.effective == nil {
		s.effective = map[int]config.Certificate{}
	}
	for id, c := range certs {
		s.effective[id] = c
	}
}

// Share sends the summary when it changed since the last one sent, or the
// last one is older than ConfigResend. With share_config off it clears
// the stored summary instead, once. Failures are logged, never returned:
// sharing must not fail a pass.
func (s *ConfigSharer) Share(ctx context.Context) {
	if s.unsupported {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ReportTimeout)
	defer cancel()

	if !s.Config.KrakenKey.SharesConfig() {
		if s.cleared {
			return
		}
		s.cleared = true
		err := s.API.DeleteConfigSummary(ctx)
		switch {
		case api.IsMissingRoute(err):
			s.unsupported = true
			s.Log.Debug("this KrakenKey version does not store config summaries")
		case err != nil:
			s.Log.Debug("could not clear the config summary in KrakenKey", "error", err)
		default:
			s.Log.Debug("config sharing is off; cleared the config summary in KrakenKey")
		}
		return
	}

	summary, cut := s.Build()
	hash, err := api.ConfigSummaryHash(summary)
	if err != nil {
		s.Log.Warn("could not build the config summary", "error", err)
		return
	}
	if hash == s.lastHash && s.now().Sub(s.lastSent) < ConfigResend {
		s.Log.Debug("config summary unchanged; not sent", "hash", hash)
		return
	}
	if len(cut) > 0 {
		s.Log.Warn("the config summary for KrakenKey is cut to the API's limits", "cut", strings.Join(cut, "; "))
	}
	err = s.API.PutConfigSummary(ctx, hash, summary)
	switch {
	case api.IsMissingRoute(err):
		s.unsupported = true
		s.Log.Debug("this KrakenKey version does not store config summaries; not sending them until the connector restarts")
		return
	case err != nil:
		s.Log.Warn("could not send the config summary to KrakenKey", "error", err)
		return
	}
	s.lastHash, s.lastSent = hash, s.now()
	s.Log.Debug("config summary sent", "hash", hash, "certificates", len(summary.Certificates))
}

// Build returns the summary, and what was cut from it to stay within the
// API's limits (summary.Truncated is set then).
func (s *ConfigSharer) Build() (api.ConfigSummary, []string) {
	var cut []string
	sum := api.ConfigSummary{
		Version:      s.Version,
		Plugins:      []api.ConfigPlugin{},
		Certificates: []api.ConfigCertificate{},
	}
	if secs := int(s.Config.CheckInterval / time.Second); secs >= 1 && secs <= api.MaxConfigCheckInterval {
		sum.CheckIntervalSeconds = &secs
	}

	plugins := s.pluginNames()
	if len(plugins) > api.MaxConfigPlugins {
		cut = append(cut, fmt.Sprintf("%d of %d plugins", api.MaxConfigPlugins, len(plugins)))
		plugins = plugins[:api.MaxConfigPlugins]
	}
	for _, name := range plugins {
		if p, ok := s.plugin(name); ok {
			sum.Plugins = append(sum.Plugins, p)
		}
	}

	certs := s.Config.Certificates
	if len(certs) > api.MaxReportCertificates {
		cut = append(cut, fmt.Sprintf("%d of %d certificates", api.MaxReportCertificates, len(certs)))
		certs = certs[:api.MaxReportCertificates]
	}
	for _, cert := range certs {
		if e, ok := s.effective[cert.ID]; ok {
			cert = e
		}
		sum.Certificates = append(sum.Certificates, certificateSummary(cert, &cut))
	}
	sum.Truncated = len(cut) > 0
	return sum, cut
}

// pluginNames returns the declared plugins and the built-in ones the
// certificates use, sorted.
func (s *ConfigSharer) pluginNames() []string {
	seen := map[string]bool{}
	for name := range s.Config.Plugins {
		seen[name] = true
	}
	for _, cert := range s.Config.Certificates {
		if slices.Contains(config.BuiltinKeyStores, cert.KeyStore.Plugin) {
			seen[cert.KeyStore.Plugin] = true
		}
		for _, t := range cert.Targets {
			if slices.Contains(config.BuiltinTargets, t.Plugin) {
				seen[t.Plugin] = true
			}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// plugin describes one plugin: built-in plugins have the connector's
// version; external ones the version they run, or would run, and where it
// comes from.
func (s *ConfigSharer) plugin(name string) (api.ConfigPlugin, bool) {
	var loc pluginhost.Location
	if s.Plugins != nil {
		loc = s.Plugins.Locate(name)
	}
	p := api.ConfigPlugin{Name: name}
	version := loc.Version
	switch loc.Source {
	case pluginhost.SourceBuiltin:
		p.Source, version = api.PluginSourceBuiltin, s.Version
	case pluginhost.SourcePluginDir:
		p.Source = api.PluginSourceBundled
	case pluginhost.SourceDataDir:
		p.Source = api.PluginSourceDataDir
	case pluginhost.SourcePath:
		p.Source = api.PluginSourcePath
	default:
		return p, false
	}
	if version != "" && printableASCII(version, api.MaxConfigVersion) {
		p.Version = &version
	}
	return p, true
}

func certificateSummary(cert config.Certificate, cut *[]string) api.ConfigCertificate {
	names := cert.Names
	if len(names) > api.MaxConfigNames {
		*cut = append(*cut, fmt.Sprintf("certificate %d: %d of %d names", cert.ID, api.MaxConfigNames, len(names)))
		names = names[:api.MaxConfigNames]
	}
	cc := api.ConfigCertificate{
		CertificateID: cert.ID,
		Names:         append([]string{}, names...),
		KeyStore: api.ConfigKeyStore{
			Plugin:   cert.KeyStore.Plugin,
			Settings: allowedSettings(cert.KeyStore.Plugin, cert.KeyStore.Settings, fmt.Sprintf("certificate %d: key store", cert.ID), cut),
		},
		Targets: []api.ConfigTarget{},
	}
	if kt := string(cert.KeyStore.KeyType); kt != "" && printableASCII(kt, api.MaxConfigKeyType) {
		cc.KeyStore.KeyType = &kt
	}
	targets := cert.Targets
	if len(targets) > api.MaxReportTargets {
		*cut = append(*cut, fmt.Sprintf("certificate %d: %d of %d targets", cert.ID, api.MaxReportTargets, len(targets)))
		targets = targets[:api.MaxReportTargets]
	}
	for _, t := range targets {
		ct := api.ConfigTarget{
			Label:       t.Label,
			Plugin:      t.Plugin,
			Implicit:    t.Implicit,
			RunsCommand: t.Then != nil || t.Plugin == config.BuiltinExec,
			Settings:    allowedSettings(t.Plugin, t.Settings, fmt.Sprintf("certificate %d: target %s", cert.ID, t.Label), cut),
		}
		if v := t.Verify; v != nil {
			cv := &api.ConfigVerify{SkipChainValidation: v.SkipChainValidation}
			if v.Host != "" {
				host := v.Host
				cv.Host = &host
			}
			// The port of an address setting is left out with the
			// address.
			if v.Address == "" && v.Port > 0 {
				port := v.Port
				cv.Port = &port
			}
			ct.Verify = cv
		}
		cc.Targets = append(cc.Targets, ct)
	}
	return cc
}

// allowedSettings returns the settings of plugin that summarySettings
// allows, with values the API takes (strings, booleans, finite numbers).
// Strings cut to the API's limit are noted in cut, prefixed with where.
func allowedSettings(plugin string, settings map[string]any, where string, cut *[]string) map[string]any {
	out := map[string]any{}
	add := func(key string, v any) {
		if str, ok := v.(string); ok {
			if utf16Len(str) > api.MaxConfigSettingValue {
				*cut = append(*cut, where+": setting "+key)
			}
			out[key] = cleanSetting(str)
			return
		}
		if v, ok := settingValue(v); ok {
			out[key] = v
		}
	}
	for _, key := range summarySettings[plugin] {
		if v, ok := settings[key]; ok {
			add(key, v)
		}
	}
	if plugin == config.BuiltinFile {
		if files, ok := settings["files"].(map[string]any); ok {
			for _, key := range fileNames {
				if v, ok := files[key].(string); ok {
					add(key, v)
				}
			}
		}
	}
	return out
}

// settingValue returns v if it is a boolean or a finite number.
func settingValue(v any) (any, bool) {
	switch x := v.(type) {
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return x, true
	case float32:
		return x, !math.IsInf(float64(x), 0) && !math.IsNaN(float64(x))
	case float64:
		return x, !math.IsInf(x, 0) && !math.IsNaN(x)
	case json.Number:
		f, err := x.Float64()
		return x, err == nil && !math.IsInf(f, 0) && !math.IsNaN(f)
	}
	return nil, false
}

func controlToSpace(r rune) rune {
	if unicode.IsControl(r) {
		return ' '
	}
	return r
}

// cleanSetting replaces control characters with spaces and keeps at most
// api.MaxConfigSettingValue UTF-16 code units, as the API counts them.
func cleanSetting(s string) string {
	s = strings.Map(controlToSpace, s)
	if utf16Len(s) <= api.MaxConfigSettingValue {
		return s
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		w := utf16.RuneLen(r)
		if w < 1 {
			w = 1
		}
		if n+w > api.MaxConfigSettingValue {
			break
		}
		b.WriteRune(r)
		n += w
	}
	return b.String()
}

// printableASCII reports whether s is at most max printable ASCII
// characters.
func printableASCII(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
