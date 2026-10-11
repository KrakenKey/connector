package pluginhost

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/krakenkey/connector/internal/config"
)

// systemDir lays out a system plugin directory holding the test binary as
// plugin "mem" version 1.0.0, with a plugins.lock that also lists a plugin
// that is not installed. It lets the test's own user stand in for root.
func systemDir(t *testing.T) (dir, bin, sum string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("permission bits")
	}
	systemDirOwnUser = true
	t.Cleanup(func() { systemDirOwnUser = false })

	exe, sum := selfBinary(t)
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(t.TempDir(), "plugins")
	bin = filepath.Join(dir, "mem", "1.0.0", BinaryName("mem"))
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, data, 0o755); err != nil {
		t.Fatal(err)
	}
	writeLock(t, dir, sum+"  "+lockKey("mem", "1.0.0")+"\n"+
		strings.Repeat("ab", 32)+"  "+lockKey("other", "1.0.0")+"\n")
	return dir, bin, sum
}

func writeLock(t *testing.T, dir, content string) {
	t.Helper()
	path := filepath.Join(dir, LockFile)
	_ = os.Remove(path)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func systemHost(t *testing.T, pluginDir string, spec config.PluginSpec) *Host {
	t.Helper()
	h := New(&config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		PluginDir: pluginDir,
		Plugins:   map[string]config.PluginSpec{"mem": spec},
	}, quiet())
	t.Cleanup(h.Close)
	return h
}

func TestSystemPluginDir(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a subprocess")
	}
	t.Setenv(servePluginEnv, "1")
	dir, bin, sum := systemDir(t)

	h := systemHost(t, dir, config.PluginSpec{Version: "1.0.0"})
	loc, err := h.CheckPlugin("mem")
	if err != nil {
		t.Fatalf("CheckPlugin: %v", err)
	}
	if loc.Path != bin || loc.Source != SourcePluginDir || loc.SHA256 != sum || !slices.Equal(loc.PinnedBy, []string{LockFile}) {
		t.Errorf("location = %+v", loc)
	}
	tg, err := h.Target("mem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tg.Describe(context.Background()); err != nil {
		t.Fatalf("Describe: %v", err)
	}

	// A sha256 in the config is checked as well.
	h = systemHost(t, dir, config.PluginSpec{Version: "1.0.0", SHA256: sum})
	if loc, err := h.CheckPlugin("mem"); err != nil || !slices.Equal(loc.PinnedBy, []string{PinConfig, LockFile}) {
		t.Errorf("CheckPlugin = %+v, %v", loc, err)
	}
}

func TestDataDirBeforeSystemPluginDir(t *testing.T) {
	dir, _, sum := systemDir(t)
	h := systemHost(t, dir, config.PluginSpec{Version: "1.0.0"})
	exe, _ := selfBinary(t)
	data, _ := os.ReadFile(exe)
	local := filepath.Join(h.dataDir, "plugins", "mem", "1.0.0", BinaryName("mem"))
	if err := os.MkdirAll(filepath.Dir(local), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, data, 0o755); err != nil {
		t.Fatal(err)
	}

	// Installed under data_dir, the plugin needs its own sha256, even
	// though the system plugin directory has the same version.
	_, _, err := h.open("mem")
	if err == nil || !strings.Contains(err.Error(), "needs sha256 set") {
		t.Fatalf("data_dir plugin without sha256: %v", err)
	}

	h = New(&config.Config{DataDir: h.dataDir, PluginDir: dir, Plugins: map[string]config.PluginSpec{"mem": {Version: "1.0.0", SHA256: sum}}}, quiet())
	f, loc, err := h.open("mem")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if loc.Path != local || loc.Source != SourceDataDir || !slices.Equal(loc.PinnedBy, []string{PinConfig}) {
		t.Errorf("location = %+v", loc)
	}
}

func TestSystemPluginDirRefusals(t *testing.T) {
	dir, bin, sum := systemDir(t)
	goodLock, err := os.ReadFile(filepath.Join(dir, LockFile))
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, LockFile)

	tests := []struct {
		name  string
		spec  config.PluginSpec
		setup func(t *testing.T)
		want  string
	}{
		{"lock missing", config.PluginSpec{Version: "1.0.0"}, func(t *testing.T) { _ = os.Remove(lockPath) },
			LockFile + " does not exist"},
		{"lock malformed", config.PluginSpec{Version: "1.0.0"}, func(t *testing.T) {
			writeLock(t, dir, sum+"  "+lockKey("mem", "1.0.0")+"\nnot a checksum line\n")
		}, "line 2"},
		{"lock writable by group", config.PluginSpec{Version: "1.0.0"}, func(t *testing.T) { _ = os.Chmod(lockPath, 0o664) },
			"writable by group or others"},
		{"lock is a symlink", config.PluginSpec{Version: "1.0.0"}, func(t *testing.T) {
			real := filepath.Join(t.TempDir(), "real.lock")
			_ = os.WriteFile(real, goodLock, 0o644)
			_ = os.Remove(lockPath)
			_ = os.Symlink(real, lockPath)
		}, "is a symlink"},
		{"no lock entry", config.PluginSpec{Version: "1.0.0"}, func(t *testing.T) {
			writeLock(t, dir, strings.Repeat("ab", 32)+"  "+lockKey("other", "1.0.0")+"\n")
		}, "has no entry for mem/1.0.0/" + BinaryName("mem")},
		{"lock checksum differs", config.PluginSpec{Version: "1.0.0"}, func(t *testing.T) {
			writeLock(t, dir, strings.Repeat("0", 64)+"  "+lockKey("mem", "1.0.0")+"\n")
		}, "plugins.lock says 0000"},
		{"config checksum differs", config.PluginSpec{Version: "1.0.0", SHA256: strings.Repeat("0", 64)}, nil,
			"config says 0000"},
		{"binary writable by group", config.PluginSpec{Version: "1.0.0"}, func(t *testing.T) { _ = os.Chmod(bin, 0o775) },
			"writable by group or others"},
		{"version dir writable by others", config.PluginSpec{Version: "1.0.0"}, func(t *testing.T) { _ = os.Chmod(filepath.Dir(bin), 0o757) },
			"writable by group or others"},
		{"binary is a symlink", config.PluginSpec{Version: "1.0.0"}, func(t *testing.T) {
			_ = os.Rename(bin, bin+".real")
			_ = os.Symlink(bin+".real", bin)
		}, "is a symlink"},
		{"not installed anywhere", config.PluginSpec{Version: "2.0.0"}, nil, "neither "},
		{"other versions are listed", config.PluginSpec{Version: "2.0.0"}, nil, "the system plugin directory has 1.0.0;"},
		{"owned by the connector's user, not root", config.PluginSpec{Version: "1.0.0"}, func(t *testing.T) {
			systemDirOwnUser = false
			if os.Geteuid() == 0 {
				_ = os.Chown(bin, 4242, 4242)
			}
		}, "not root; everything in the system plugin directory must be owned by root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Each case starts from the layout systemDir made.
			writeLock(t, dir, string(goodLock))
			if tt.setup != nil {
				tt.setup(t)
			}
			t.Cleanup(func() {
				systemDirOwnUser = true
				if fi, err := os.Lstat(bin); err == nil && fi.Mode()&os.ModeSymlink != 0 {
					_ = os.Remove(bin)
					_ = os.Rename(bin+".real", bin)
				}
				_ = os.Chmod(bin, 0o755)
				_ = os.Chmod(filepath.Dir(bin), 0o755)
				if os.Geteuid() == 0 {
					_ = os.Chown(bin, 0, 0)
				}
			})
			h := systemHost(t, dir, tt.spec)
			if _, err := h.Target("mem"); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestNoSystemPluginDir(t *testing.T) {
	h := systemHost(t, "", config.PluginSpec{Version: "1.0.0"})
	want := filepath.Join(h.dataDir, "plugins", "mem", "1.0.0", BinaryName("mem")) + " does not exist"
	if _, err := h.Target("mem"); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("err = %v, want %q", err, want)
	}
}

func TestParseLock(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	good := "# made by sha256sum\n\n" +
		sum + "  aws-acm/0.1.0/" + BinaryName("aws-acm") + "\n" +
		strings.ToUpper(sum) + " *azure-keyvault/0.1.0/" + BinaryName("azure-keyvault") + "\n"
	lock, err := parseLock([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString(sum)
	if len(lock) != 2 || string(lock["aws-acm/0.1.0/"+BinaryName("aws-acm")]) != string(want) {
		t.Errorf("lock = %x", lock)
	}

	for name, line := range map[string]string{
		"no name":            sum,
		"short checksum":     sum[:62] + "  aws-acm/0.1.0/" + BinaryName("aws-acm"),
		"not hex":            strings.Repeat("zz", 32) + "  aws-acm/0.1.0/" + BinaryName("aws-acm"),
		"one space":          sum + " aws-acm/0.1.0/" + BinaryName("aws-acm"),
		"two parts":          sum + "  aws-acm/" + BinaryName("aws-acm"),
		"four parts":         sum + "  x/aws-acm/0.1.0/" + BinaryName("aws-acm"),
		"absolute":           sum + "  /aws-acm/0.1.0/" + BinaryName("aws-acm"),
		"dot dot":            sum + "  aws-acm/../" + BinaryName("aws-acm"),
		"binary of another":  sum + "  aws-acm/0.1.0/" + BinaryName("azure-keyvault"),
		"listed twice":       sum + "  aws-acm/0.1.0/" + BinaryName("aws-acm") + "\n" + sum + "  aws-acm/0.1.0/" + BinaryName("aws-acm"),
		"space in the name":  sum + "  aws acm/0.1.0/" + BinaryName("aws acm"),
		"leading whitespace": " " + sum + "  aws-acm/0.1.0/" + BinaryName("aws-acm"),
	} {
		if _, err := parseLock([]byte(line + "\n")); err == nil {
			t.Errorf("%s: parsed %q", name, line)
		}
	}
}

func TestBundledPlugin(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a subprocess")
	}
	t.Setenv(servePluginEnv, "1")
	dir, bin, sum := systemDir(t)

	h := systemHost(t, dir, config.PluginSpec{})
	loc, err := h.CheckPlugin("mem")
	if err != nil {
		t.Fatalf("CheckPlugin: %v", err)
	}
	want := Location{Path: bin, Source: SourcePluginDir, Version: "1.0.0", Bundled: true, SHA256: sum, PinnedBy: []string{LockFile}}
	if loc.Path != want.Path || loc.Source != want.Source || loc.Version != want.Version || !loc.Bundled ||
		loc.SHA256 != want.SHA256 || !slices.Equal(loc.PinnedBy, want.PinnedBy) {
		t.Errorf("location = %+v, want %+v", loc, want)
	}
	tg, err := h.Target("mem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tg.Describe(context.Background()); err != nil {
		t.Fatalf("Describe: %v", err)
	}

	// A sha256 in the config is checked as well.
	h = systemHost(t, dir, config.PluginSpec{SHA256: sum})
	if loc, err := h.CheckPlugin("mem"); err != nil || !slices.Equal(loc.PinnedBy, []string{PinConfig, LockFile}) {
		t.Errorf("CheckPlugin = %+v, %v", loc, err)
	}

	// An explicit version is not marked as bundled.
	h = systemHost(t, dir, config.PluginSpec{Version: "1.0.0"})
	if loc, err := h.CheckPlugin("mem"); err != nil || loc.Bundled || loc.Version != "1.0.0" {
		t.Errorf("CheckPlugin = %+v, %v", loc, err)
	}
}

// A plugin without a version is only ever taken from the system plugin
// directory, never from <data_dir>/plugins.
func TestBundledPluginIgnoresDataDir(t *testing.T) {
	dir, bin, _ := systemDir(t)
	h := systemHost(t, dir, config.PluginSpec{})
	exe, _ := selfBinary(t)
	data, _ := os.ReadFile(exe)
	local := filepath.Join(h.dataDir, "plugins", "mem", "1.0.0", BinaryName("mem"))
	if err := os.MkdirAll(filepath.Dir(local), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, data, 0o755); err != nil {
		t.Fatal(err)
	}

	f, loc, err := h.open("mem")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if loc.Path != bin || loc.Source != SourcePluginDir || !loc.Bundled {
		t.Errorf("location = %+v, want the system plugin directory", loc)
	}

	// With nothing in the system plugin directory, the copy under
	// data_dir is still not used.
	if err := os.RemoveAll(filepath.Join(dir, "mem")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.open("mem"); err == nil || !strings.Contains(err.Error(), "has none installed") {
		t.Errorf("err = %v, want none installed", err)
	}
}

func TestBundledPluginRefusals(t *testing.T) {
	dir, bin, sum := systemDir(t)
	lockPath := filepath.Join(dir, LockFile)
	goodLock, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(dir, "mem", "2.0.0")

	tests := []struct {
		name  string
		noDir bool
		setup func(t *testing.T)
		want  []string
	}{
		{name: "not installed", setup: func(t *testing.T) {
			_ = os.Rename(filepath.Join(dir, "mem"), filepath.Join(dir, "mem.away"))
		}, want: []string{"no version is set", "has none installed (" + filepath.Join(dir, "mem") + ")", "install the krakenkey-connector package"}},
		{name: "several versions", setup: func(t *testing.T) { _ = os.MkdirAll(second, 0o755) },
			want: []string{"has several (1.0.0, 2.0.0 in " + filepath.Join(dir, "mem") + ")", "set version"}},
		{name: "no system plugin directory", noDir: true,
			want: []string{"no version is set and there is no system plugin directory; set version"}},
		{name: "lock missing", setup: func(t *testing.T) { _ = os.Remove(lockPath) },
			want: []string{"plugins in the system plugin directory are refused", LockFile + " does not exist"}},
		{name: "lock checksum differs", setup: func(t *testing.T) {
			writeLock(t, dir, strings.Repeat("0", 64)+"  "+lockKey("mem", "1.0.0")+"\n")
		}, want: []string{"checksum mismatch", "plugins.lock says 0000"}},
		{name: "no lock entry", setup: func(t *testing.T) {
			writeLock(t, dir, sum+"  "+lockKey("mem", "0.9.0")+"\n")
		}, want: []string{"has no entry for mem/1.0.0/" + BinaryName("mem")}},
		{name: "binary writable by group", setup: func(t *testing.T) { _ = os.Chmod(bin, 0o775) },
			want: []string{"writable by group or others"}},
		{name: "owned by the connector's user, not root", setup: func(t *testing.T) {
			systemDirOwnUser = false
			if os.Geteuid() == 0 {
				_ = os.Chown(bin, 4242, 4242)
			}
		}, want: []string{"not root; everything in the system plugin directory must be owned by root"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeLock(t, dir, string(goodLock))
			if tt.setup != nil {
				tt.setup(t)
			}
			t.Cleanup(func() {
				systemDirOwnUser = true
				_ = os.Rename(filepath.Join(dir, "mem.away"), filepath.Join(dir, "mem"))
				_ = os.RemoveAll(second)
				_ = os.Chmod(bin, 0o755)
				if os.Geteuid() == 0 {
					_ = os.Chown(bin, 0, 0)
				}
			})
			pluginDir := dir
			if tt.noDir {
				pluginDir = ""
			}
			h := systemHost(t, pluginDir, config.PluginSpec{})
			_, err := h.Target("mem")
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("err = %v, want %q", err, w)
				}
			}
		})
	}
}

// TestLocate checks where plugins are reported to come from without
// starting them.
func TestLocate(t *testing.T) {
	dir, bin, _ := systemDir(t)
	h := New(&config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		PluginDir: dir,
		Plugins: map[string]config.PluginSpec{
			"mem":       {},
			"not-installed":    {Version: "1.0.0"},
			"local-bin": {Version: "2.0.0", SHA256: strings.Repeat("ab", 32)},
			"by-path":   {Path: "/opt/plugin"},
			"missing":   {},
		},
	}, quiet())
	t.Cleanup(h.Close)
	data := filepath.Join(h.dataDir, "plugins", "local-bin", "2.0.0", BinaryName("local-bin"))
	if err := os.MkdirAll(filepath.Dir(data), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(data, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	for name, want := range map[string]Location{
		"file":      {Source: SourceBuiltin},
		"exec":      {Source: SourceBuiltin},
		"local":     {Source: SourceBuiltin},
		"unknown":   {},
		"mem":       {Path: bin, Source: SourcePluginDir, Version: "1.0.0", Bundled: true},
		"not-installed":    {Path: filepath.Join(h.dataDir, "plugins", "not-installed", "1.0.0", BinaryName("not-installed")), Source: SourceDataDir, Version: "1.0.0"},
		"local-bin": {Path: data, Source: SourceDataDir, Version: "2.0.0"},
		"by-path":   {Path: "/opt/plugin", Source: SourcePath},
		// Not installed: it would come from the system plugin directory.
		"missing": {Source: SourcePluginDir},
	} {
		got := h.Locate(name)
		if got.Path != want.Path || got.Source != want.Source || got.Version != want.Version || got.Bundled != want.Bundled {
			t.Errorf("%s: %+v, want %+v", name, got, want)
		}
	}
}
