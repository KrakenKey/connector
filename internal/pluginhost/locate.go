package pluginhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/krakenkey/connector/internal/config"
)

// LockFile is the checksum list in the system plugin directory. Each line
// is "<sha256>  <name>/<version>/krakenkey-connector-plugin-<name>", the
// format sha256sum writes. Blank lines and lines starting with # are
// ignored.
const LockFile = "plugins.lock"

// maxLockSize bounds how much of plugins.lock is read.
const maxLockSize = 1 << 20

// Source says where a plugin's executable was found.
type Source string

// Plugin sources.
const (
	// SourcePath is the plugin's path setting.
	SourcePath Source = "path"
	// SourceDataDir is <data_dir>/plugins/<name>/<version>/.
	SourceDataDir Source = "data_dir"
	// SourcePluginDir is <plugin_dir>/<name>/<version>/, the system plugin
	// directory.
	SourcePluginDir Source = "plugin_dir"
	// SourceBuiltin is a plugin built into the connector.
	SourceBuiltin Source = "builtin"
)

// Location is where a plugin's executable was found and what its checksum
// was checked against.
type Location struct {
	Path   string
	Source Source
	// Version is the plugin version that was started: the configured one,
	// or for a plugin declared without version and path, the only version
	// in the system plugin directory. Empty for a path setting.
	Version string
	// Bundled says that Version was not configured but taken from the
	// system plugin directory.
	Bundled bool
	// SHA256 is the hex checksum of the executable that was started.
	SHA256 string
	// PinnedBy lists what SHA256 matched: "config" (the plugin's sha256
	// setting) and LockFile. Empty means the binary is not pinned.
	PinnedBy []string
}

// Locate says where the plugin called name runs from, without starting
// it: for a running plugin, the executable it was started from; for
// others, where the connector looks for it (Path and Version may be empty
// when that lookup fails). Built-in plugins have Source SourceBuiltin; a
// name that is neither built in nor declared gives an empty Location. It
// reads nothing but directory entries.
func (h *Host) Locate(name string) Location {
	if slices.Contains(config.BuiltinKeyStores, name) || slices.Contains(config.BuiltinTargets, name) {
		return Location{Source: SourceBuiltin}
	}
	h.mu.Lock()
	loc, running := h.locations[name]
	h.mu.Unlock()
	if running {
		return loc
	}
	spec, ok := h.specs[name]
	if !ok {
		return Location{}
	}
	loc, _, _ = h.find(name, spec)
	if loc.Source == "" {
		// Without version and path the plugin can only come from the
		// system plugin directory.
		loc.Source = SourcePluginDir
	}
	return loc
}

// PinConfig is the PinnedBy entry for the plugin's sha256 setting.
const PinConfig = "config"

// open finds the plugin's executable, checks it, and returns it open, with
// its checksum checked against the config and, for the system plugin
// directory, against plugins.lock.
func (h *Host) open(name string) (*os.File, Location, error) {
	spec, ok := h.specs[name]
	if !ok {
		return nil, Location{}, fmt.Errorf("plugin %q is not declared under plugins", name)
	}
	loc, stop, err := h.find(name, spec)
	if err != nil {
		return nil, loc, err
	}
	system := loc.Source == SourcePluginDir

	var lock map[string][]byte
	if system {
		if lock, err = readLock(h.pluginDir); err != nil {
			if loc.Bundled {
				return nil, loc, fmt.Errorf("plugins in the system plugin directory are refused: %w", err)
			}
			return nil, loc, fmt.Errorf("version %s is not installed under %s, and plugins in the system plugin directory are refused: %w",
				spec.Version, filepath.Join(h.dataDir, "plugins"), err)
		}
	}

	f, err := openChecked(loc.Path, stop, system, true)
	if err != nil {
		return nil, loc, err
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		_ = f.Close()
		return nil, loc, fmt.Errorf("hash %s: %w", loc.Path, err)
	}
	got := sum.Sum(nil)
	loc.SHA256 = hex.EncodeToString(got)

	if want := spec.SHA256; want != "" {
		wantBytes, _ := hex.DecodeString(want)
		if !bytes.Equal(got, wantBytes) {
			_ = f.Close()
			return nil, loc, fmt.Errorf("checksum mismatch for %s: sha256 is %x, config says %s", loc.Path, got, want)
		}
		loc.PinnedBy = append(loc.PinnedBy, PinConfig)
	}
	if system {
		key := lockKey(name, loc.Version)
		want, ok := lock[key]
		if !ok {
			_ = f.Close()
			return nil, loc, fmt.Errorf("%s has no entry for %s, so %s is not started",
				filepath.Join(h.pluginDir, LockFile), key, loc.Path)
		}
		if !bytes.Equal(got, want) {
			_ = f.Close()
			return nil, loc, fmt.Errorf("checksum mismatch for %s: sha256 is %x, %s says %x", loc.Path, got, LockFile, want)
		}
		loc.PinnedBy = append(loc.PinnedBy, LockFile)
	}
	return f, loc, nil
}

// find says where the plugin's executable is and up to which directory
// its parents are checked: its path setting; or, by version, under
// <data_dir>/plugins, which needs a sha256 setting; or, when nothing is
// installed there, under the system plugin directory. Without version and
// path, it is the only version in the system plugin directory.
func (h *Host) find(name string, spec config.PluginSpec) (Location, string, error) {
	if spec.Path != "" {
		return Location{Path: spec.Path, Source: SourcePath}, string(filepath.Separator), nil
	}
	if spec.Version == "" {
		return h.findBundled(name)
	}
	data := filepath.Join(h.dataDir, "plugins", name, spec.Version, BinaryName(name))
	_, err := os.Lstat(data)
	switch {
	case err == nil:
		loc := Location{Path: data, Source: SourceDataDir, Version: spec.Version}
		if spec.SHA256 == "" {
			return loc, "", fmt.Errorf("%s is installed under the data directory, which needs sha256 set for the plugin", data)
		}
		return loc, h.dataDir, nil
	case !errors.Is(err, fs.ErrNotExist):
		return Location{Path: data, Source: SourceDataDir, Version: spec.Version}, "", err
	}
	if h.pluginDir == "" {
		return Location{Path: data, Source: SourceDataDir, Version: spec.Version}, "", fmt.Errorf("version %s is not installed: %s does not exist", spec.Version, data)
	}
	system := filepath.Join(h.pluginDir, name, spec.Version, BinaryName(name))
	if _, err := os.Lstat(system); errors.Is(err, fs.ErrNotExist) {
		msg := fmt.Sprintf("version %s is not installed: neither %s nor %s exists", spec.Version, data, system)
		if have := installedVersions(filepath.Join(h.pluginDir, name)); len(have) > 0 {
			msg += fmt.Sprintf(" (the system plugin directory has %s; plugins there have the connector's version)", strings.Join(have, ", "))
		}
		return Location{Path: data, Source: SourceDataDir, Version: spec.Version}, "", errors.New(msg)
	}
	return Location{Path: system, Source: SourcePluginDir, Version: spec.Version}, string(filepath.Separator), nil
}

// findBundled finds a plugin declared without version and path: the only
// version of it in the system plugin directory. Plugins under
// <data_dir>/plugins are never picked this way; they need a version and a
// sha256. The binary is then checked like any other in the system plugin
// directory, plugins.lock included.
func (h *Host) findBundled(name string) (Location, string, error) {
	if h.pluginDir == "" {
		return Location{}, "", errors.New("no version is set and there is no system plugin directory; set version")
	}
	dir := filepath.Join(h.pluginDir, name)
	if _, err := os.ReadDir(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Location{}, "", fmt.Errorf("no version is set and the system plugin directory cannot be read: %w", err)
	}
	versions := installedVersions(dir)
	switch len(versions) {
	case 0:
		return Location{}, "", fmt.Errorf("no version is set and the system plugin directory has none installed (%s); "+
			"install the krakenkey-connector package or use the container image, which include it, "+
			"or set version and sha256 and install the plugin under %s",
			dir, filepath.Join(h.dataDir, "plugins", name, "<version>"))
	case 1:
	default:
		return Location{}, "", fmt.Errorf("no version is set and the system plugin directory has several (%s in %s); set version to the one to use",
			strings.Join(versions, ", "), dir)
	}
	v := versions[0]
	loc := Location{Path: filepath.Join(dir, v, BinaryName(name)), Source: SourcePluginDir, Version: v, Bundled: true}
	return loc, string(filepath.Separator), nil
}

// installedVersions lists the version directories under dir, for error
// messages.
func installedVersions(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

func lockKey(name, version string) string {
	return name + "/" + version + "/" + BinaryName(name)
}

// readLock reads and parses dir/plugins.lock, which must pass the same
// checks as the system plugins themselves.
func readLock(dir string) (map[string][]byte, error) {
	path := filepath.Join(dir, LockFile)
	f, err := openChecked(path, string(filepath.Separator), true, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s does not exist", path)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxLockSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxLockSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxLockSize)
	}
	lock, err := parseLock(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return lock, nil
}

// parseLock parses plugins.lock. Any line it does not understand makes
// the whole file invalid.
func parseLock(data []byte) (map[string][]byte, error) {
	lock := map[string][]byte{}
	for i, line := range strings.Split(string(data), "\n") {
		n := i + 1
		line = strings.TrimRight(line, " \t\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sumHex, rest, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("line %d: want \"<sha256>  <name>/<version>/<binary>\"", n)
		}
		sum, err := hex.DecodeString(sumHex)
		if err != nil || len(sum) != sha256.Size {
			return nil, fmt.Errorf("line %d: %q is not a sha256 checksum", n, sumHex)
		}
		// sha256sum separates the checksum and the name with two spaces,
		// or a space and * in binary mode.
		if !strings.HasPrefix(rest, " ") && !strings.HasPrefix(rest, "*") {
			return nil, fmt.Errorf("line %d: want two spaces between the checksum and the name", n)
		}
		key := rest[1:]
		parts := strings.Split(key, "/")
		if len(parts) != 3 {
			return nil, fmt.Errorf("line %d: %q is not <name>/<version>/<binary>", n, key)
		}
		for _, p := range parts {
			if p == "" || p == "." || p == ".." || strings.ContainsAny(p, `\ `) {
				return nil, fmt.Errorf("line %d: %q is not <name>/<version>/<binary>", n, key)
			}
		}
		if parts[2] != BinaryName(parts[0]) {
			return nil, fmt.Errorf("line %d: the binary in %s must be %s", n, key, BinaryName(parts[0]))
		}
		if _, dup := lock[key]; dup {
			return nil, fmt.Errorf("line %d: %s is listed twice", n, key)
		}
		lock[key] = sum
	}
	return lock, nil
}
