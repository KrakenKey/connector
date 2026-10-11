// Package config loads and checks the connector's YAML config file.
package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/krakenkey/connector/pkg/plugin"
)

// Defaults.
const (
	DefaultAPIURL        = "https://api.krakenkey.io"
	DefaultCheckInterval = 6 * time.Hour
	DefaultDataDir       = "/var/lib/krakenkey-connector"
	DefaultPluginDir     = "/usr/lib/krakenkey-connector/plugins"
	DefaultKeyType       = plugin.KeyTypeECDSAP256
	DefaultVerifyPort    = 443
	DefaultVerifyWindow  = 10 * time.Minute
	DefaultThenTimeout   = 2 * time.Minute
	DefaultCallTimeout   = 5 * time.Minute
	MinCheckInterval     = time.Minute
)

// Built-in plugin names. External plugins cannot use them.
const (
	BuiltinLocal = "local"
	BuiltinFile  = "file"
	BuiltinExec  = "exec"
)

// BuiltinKeyStores and BuiltinTargets list the built-in plugins by role.
var (
	BuiltinKeyStores = []string{BuiltinLocal}
	BuiltinTargets   = []string{BuiltinFile, BuiltinExec}
)

// Config is the whole config file.
type Config struct {
	KrakenKey     KrakenKey             `yaml:"krakenkey"`
	CheckInterval time.Duration         `yaml:"check_interval"`
	DataDir       string                `yaml:"data_dir"`
	PluginDir     string                `yaml:"plugin_dir"`
	AuditLog      string                `yaml:"audit_log"`
	Plugins       map[string]PluginSpec `yaml:"plugins"`
	Certificates  []Certificate         `yaml:"certificates"`
}

// KrakenKey holds API settings.
type KrakenKey struct {
	APIURL string `yaml:"api_url"`
}

// PluginSpec declares an external plugin.
type PluginSpec struct {
	// Version selects <data_dir>/plugins/<name>/<version>/krakenkey-connector-plugin-<name>,
	// or, when that does not exist, the same layout under plugin_dir.
	// Without Version and Path, the plugin is the only version of it in
	// plugin_dir (the bundled plugins), never one under data_dir.
	Version string `yaml:"version"`
	// Path overrides the binary location.
	Path string `yaml:"path"`
	// SHA256 is the expected checksum of the binary, hex encoded. Required
	// for plugins installed under data_dir; optional with path and for
	// plugins in plugin_dir, which plugin_dir/plugins.lock pins.
	SHA256 string `yaml:"sha256"`
	// CallTimeout bounds each call to the plugin. Default 5m.
	CallTimeout time.Duration `yaml:"call_timeout"`
}

// Certificate is one KrakenKey certificate the connector manages.
type Certificate struct {
	ID       int      `yaml:"id"`
	Names    []string `yaml:"names"`
	KeyStore KeyStore `yaml:"key_store"`
	Targets  []Target `yaml:"targets"`
}

// KeyStore selects the key store for a certificate. Fields other than
// plugin and key_type are passed to the plugin as its settings.
type KeyStore struct {
	Plugin   string         `yaml:"plugin"`
	KeyType  plugin.KeyType `yaml:"key_type"`
	Settings map[string]any `yaml:",inline"`
}

// Target is one place a certificate is deployed to. Fields other than the
// ones below are passed to the plugin as its settings.
type Target struct {
	// Label names the target in logs and the audit log.
	Label    string         `yaml:"label"`
	Plugin   string         `yaml:"plugin"`
	Then     *Then          `yaml:"then"`
	Verify   *Verify        `yaml:"verify"`
	Settings map[string]any `yaml:",inline"`
}

// Then is a command the core runs after a target is activated, and again
// after it is rolled back (for example to reload a web server).
type Then struct {
	Exec    []string      `yaml:"exec"`
	Timeout time.Duration `yaml:"timeout"`
}

// Verify says how the core checks that a target serves the new certificate.
type Verify struct {
	// Host is the TLS server name (SNI) and the name the certificate must
	// be valid for.
	Host string `yaml:"host"`
	// Address is the host:port to dial. Defaults to Host:Port.
	Address string `yaml:"address"`
	// Port is used when Address is empty.
	Port int `yaml:"port"`
	// Window is how long to keep trying. Defaults to the target's default,
	// then 10m.
	Window time.Duration `yaml:"window"`
	// CAFile holds the only roots trusted when validating the served chain.
	// Defaults to the system roots.
	CAFile string `yaml:"ca_file"`
	// SkipChainValidation turns off chain validation. The served leaf is
	// still compared to the issued certificate.
	SkipChainValidation bool `yaml:"skip_chain_validation"`
}

// DialAddress returns the host:port the verifier connects to.
func (v *Verify) DialAddress() string {
	if v.Address != "" {
		return v.Address
	}
	port := v.Port
	if port == 0 {
		port = DefaultVerifyPort
	}
	return net.JoinHostPort(v.Host, strconv.Itoa(port))
}

// SettingsJSON returns the key store's plugin settings as a JSON object.
func (k KeyStore) SettingsJSON() (json.RawMessage, error) { return settingsJSON(k.Settings) }

// SettingsJSON returns the target's plugin settings as a JSON object.
func (t Target) SettingsJSON() (json.RawMessage, error) { return settingsJSON(t.Settings) }

func settingsJSON(m map[string]any) (json.RawMessage, error) {
	if m == nil {
		m = map[string]any{}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("plugin settings: %w", err)
	}
	return b, nil
}

// Load reads, defaults and validates the config file at path. The
// KK_API_URL environment variable overrides krakenkey.api_url, and
// KK_PLUGIN_DIR overrides plugin_dir.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	cfg, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes, defaults and validates a config.
func Parse(r io.Reader) (*Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config is empty")
		}
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if v := os.Getenv("KK_API_URL"); v != "" {
		c.KrakenKey.APIURL = v
	}
	if c.KrakenKey.APIURL == "" {
		c.KrakenKey.APIURL = DefaultAPIURL
	}
	c.KrakenKey.APIURL = strings.TrimRight(c.KrakenKey.APIURL, "/")
	if c.CheckInterval == 0 {
		c.CheckInterval = DefaultCheckInterval
	}
	if c.DataDir == "" {
		c.DataDir = DefaultDataDir
	}
	if v := os.Getenv("KK_PLUGIN_DIR"); v != "" {
		c.PluginDir = v
	}
	if c.PluginDir == "" {
		c.PluginDir = DefaultPluginDir
	}
	if c.AuditLog == "" {
		c.AuditLog = filepath.Join(c.DataDir, "audit.jsonl")
	}
	for name, spec := range c.Plugins {
		if spec.CallTimeout == 0 {
			spec.CallTimeout = DefaultCallTimeout
			c.Plugins[name] = spec
		}
	}
	for i := range c.Certificates {
		cert := &c.Certificates[i]
		if cert.KeyStore.Plugin == "" {
			cert.KeyStore.Plugin = BuiltinLocal
		}
		if cert.KeyStore.KeyType == "" {
			cert.KeyStore.KeyType = DefaultKeyType
		}
		cert.KeyStore.KeyType = plugin.KeyType(strings.ToLower(string(cert.KeyStore.KeyType)))
		for j := range cert.Names {
			cert.Names[j] = strings.ToLower(strings.TrimSpace(cert.Names[j]))
		}
		for j := range cert.Targets {
			t := &cert.Targets[j]
			if t.Verify != nil && t.Verify.Address == "" && t.Verify.Port == 0 {
				t.Verify.Port = DefaultVerifyPort
			}
			if t.Then != nil && t.Then.Timeout == 0 {
				t.Then.Timeout = DefaultThenTimeout
			}
		}
	}
}

var (
	pluginNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	labelRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	dnsLabelRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Validate checks the config and returns every problem found, joined.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if u, err := url.Parse(c.KrakenKey.APIURL); err != nil || u.Host == "" {
		add("krakenkey.api_url %q is not a URL", c.KrakenKey.APIURL)
	} else if u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())) {
		add("krakenkey.api_url must use https (http is allowed only for localhost)")
	}
	if c.CheckInterval < MinCheckInterval {
		add("check_interval %s is shorter than the minimum of %s", c.CheckInterval, MinCheckInterval)
	}
	if !filepath.IsAbs(c.DataDir) {
		add("data_dir %q must be an absolute path", c.DataDir)
	}
	if !filepath.IsAbs(c.AuditLog) {
		add("audit_log %q must be an absolute path", c.AuditLog)
	}
	if !filepath.IsAbs(c.PluginDir) {
		add("plugin_dir %q must be an absolute path", c.PluginDir)
	}

	for name, spec := range c.Plugins {
		switch {
		case !pluginNameRe.MatchString(name):
			add("plugins.%s: name must be lowercase letters, digits and dashes", name)
		case slices.Contains(BuiltinKeyStores, name) || slices.Contains(BuiltinTargets, name):
			add("plugins.%s: %q is a built-in plugin and cannot be declared", name, name)
		}
		if strings.ContainsAny(spec.Version, `/\`) || spec.Version == ".." || spec.Version == "." {
			add("plugins.%s: version %q is not a version", name, spec.Version)
		}
		if spec.Path != "" && !filepath.IsAbs(spec.Path) {
			add("plugins.%s: path must be absolute", name)
		}
		// sha256 is required for plugins installed under data_dir, but
		// whether a plugin is there or in plugin_dir is only known when it
		// is started, so the plugin host checks that.
		if spec.SHA256 != "" {
			if b, err := hex.DecodeString(spec.SHA256); err != nil || len(b) != 32 {
				add("plugins.%s: sha256 must be 64 hex characters", name)
			}
		}
		if spec.CallTimeout < time.Second {
			add("plugins.%s: call_timeout must be at least 1s", name)
		}
	}

	if len(c.Certificates) == 0 {
		add("certificates: at least one certificate is required")
	}
	seenIDs := map[int]bool{}
	for i, cert := range c.Certificates {
		where := fmt.Sprintf("certificates[%d]", i)
		if cert.ID <= 0 {
			add("%s: id must be a positive KrakenKey certificate id", where)
		} else {
			where = fmt.Sprintf("certificate %d", cert.ID)
			if seenIDs[cert.ID] {
				add("%s: listed more than once", where)
			}
			seenIDs[cert.ID] = true
		}
		if len(cert.Names) == 0 {
			add("%s: names must list at least one DNS name", where)
		}
		seenNames := map[string]bool{}
		for _, n := range cert.Names {
			if !validDNSName(n) {
				add("%s: %q is not a valid DNS name", where, n)
			}
			if seenNames[n] {
				add("%s: name %q is listed twice", where, n)
			}
			seenNames[n] = true
		}

		ks := cert.KeyStore
		if !slices.Contains(BuiltinKeyStores, ks.Plugin) {
			if _, ok := c.Plugins[ks.Plugin]; !ok {
				add("%s: key_store plugin %q is not built in and not declared under plugins", where, ks.Plugin)
			}
		}
		if _, err := plugin.ParseKeyType(string(ks.KeyType)); err != nil {
			add("%s: key_store: %v", where, err)
		}

		if len(cert.Targets) == 0 {
			add("%s: targets must list at least one target", where)
		}
		seenLabels := map[string]bool{}
		for j, t := range cert.Targets {
			tw := fmt.Sprintf("%s: targets[%d]", where, j)
			if !labelRe.MatchString(t.Label) {
				add("%s: label %q must be 1-64 letters, digits, dots, dashes or underscores, starting with a letter or digit", tw, t.Label)
			} else {
				tw = fmt.Sprintf("%s: target %s", where, t.Label)
				if seenLabels[t.Label] {
					add("%s: label is used twice", tw)
				}
				seenLabels[t.Label] = true
			}
			if t.Plugin == "" {
				add("%s: plugin is required", tw)
			} else if !slices.Contains(BuiltinTargets, t.Plugin) {
				if _, ok := c.Plugins[t.Plugin]; !ok {
					add("%s: plugin %q is not built in and not declared under plugins", tw, t.Plugin)
				}
			}
			if t.Then != nil {
				if len(t.Then.Exec) == 0 || t.Then.Exec[0] == "" {
					add("%s: then.exec needs a command", tw)
				} else if prog := t.Then.Exec[0]; !filepath.IsAbs(prog) && strings.ContainsAny(prog, `/\`) {
					add("%s: then.exec %q is a relative path; use an absolute path or a name from PATH", tw, prog)
				}
				if t.Then.Timeout < 0 {
					add("%s: then.timeout must not be negative", tw)
				}
			}
			if v := t.Verify; v != nil {
				errs = append(errs, v.validate(tw)...)
				if v.Host != "" && len(cert.Names) > 0 && !coveredBy(strings.ToLower(v.Host), cert.Names) {
					add("%s: verify: host %q is not one of the certificate's names %v", tw, v.Host, cert.Names)
				}
			}
		}
	}
	return errors.Join(errs...)
}

func (v *Verify) validate(where string) []error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(where+": verify: "+format, args...)) }
	host := strings.ToLower(v.Host)
	if host == "" {
		add("host is required")
	} else if !validDNSName(host) && net.ParseIP(host) == nil {
		add("host %q is not a DNS name or IP address", v.Host)
	}
	if v.Address != "" {
		h, p, err := net.SplitHostPort(v.Address)
		if err != nil || h == "" {
			add("address %q must be host:port", v.Address)
		} else if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			add("address %q has an invalid port", v.Address)
		}
		if v.Port != 0 {
			add("set address or port, not both")
		}
	} else if v.Port < 1 || v.Port > 65535 {
		add("port %d is out of range", v.Port)
	}
	if v.Window < 0 {
		add("window must not be negative")
	}
	if v.CAFile != "" && !filepath.IsAbs(v.CAFile) {
		add("ca_file must be an absolute path")
	}
	if v.CAFile != "" && v.SkipChainValidation {
		add("ca_file and skip_chain_validation cannot both be set")
	}
	return errs
}

// Warnings returns things that are allowed but probably not intended.
func (c *Config) Warnings() []string {
	var w []string
	for _, cert := range c.Certificates {
		for _, t := range cert.Targets {
			switch {
			case t.Verify == nil:
				w = append(w, fmt.Sprintf("certificate %d: target %s has no verify block; deployments to it are not checked", cert.ID, t.Label))
			case t.Verify.SkipChainValidation:
				w = append(w, fmt.Sprintf("certificate %d: target %s skips chain validation; only the served leaf is checked", cert.ID, t.Label))
			}
		}
	}
	return w
}

// FindCertificate returns the certificate with the given id.
func (c *Config) FindCertificate(id int) (Certificate, bool) {
	for _, cert := range c.Certificates {
		if cert.ID == id {
			return cert, true
		}
	}
	return Certificate{}, false
}

// coveredBy reports whether host is one of names, or matches a wildcard
// name in them for exactly one label.
func coveredBy(host string, names []string) bool {
	for _, n := range names {
		if host == n {
			return true
		}
		if suffix, ok := strings.CutPrefix(n, "*."); ok {
			if label, rest, found := strings.Cut(host, "."); found && label != "" && rest == suffix {
				return true
			}
		}
	}
	return false
}

func validDNSName(n string) bool {
	if n == "" || len(n) > 253 {
		return false
	}
	n = strings.TrimPrefix(n, "*.")
	labels := strings.Split(n, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !dnsLabelRe.MatchString(l) {
			return false
		}
	}
	return true
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
