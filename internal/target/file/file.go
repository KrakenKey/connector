// Package file is the built-in target that writes PEM files into a
// directory, for servers such as nginx, HAProxy or Caddy.
//
// Each file is replaced atomically: the new content is written to a temp
// file in the same directory and renamed over the old one. Before that, the
// old files are hard-linked (or copied) into
// <dir>/.krakenkey-previous/<stage id>/ so Rollback can put them back. The
// two most recent backups are kept.
package file

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/krakenkey/connector/internal/certutil"
	"github.com/krakenkey/connector/pkg/plugin"
)

// BackupDir is the directory, inside the target dir, that holds previous
// files.
const BackupDir = ".krakenkey-previous"

// keepBackups is how many backup sets Activate keeps.
const keepBackups = 2

// Default file modes.
const (
	DefaultKeyMode  fs.FileMode = 0o600
	DefaultCertMode fs.FileMode = 0o644
)

// Config is the file target's settings.
type Config struct {
	// Dir is the directory the files go in. It must exist.
	Dir   string `json:"dir"`
	Files Files  `json:"files"`
	// Owner is "user", "user:group" or ":group"; names or numeric ids.
	Owner string `json:"owner,omitempty"`
	// Mode is the key file's mode as an octal string, such as "0640".
	Mode string `json:"mode,omitempty"`
}

// Files names the files to write. Empty names are skipped; key is required,
// and so is at least one of cert and fullchain.
type Files struct {
	Cert      string `json:"cert,omitempty"`
	Chain     string `json:"chain,omitempty"`
	FullChain string `json:"fullchain,omitempty"`
	Key       string `json:"key,omitempty"`
}

type entry struct {
	kind string // cert, chain, fullchain, key
	name string
}

func (f Files) entries() []entry {
	var out []entry
	for _, e := range []entry{{"cert", f.Cert}, {"chain", f.Chain}, {"fullchain", f.FullChain}, {"key", f.Key}} {
		if e.name != "" {
			out = append(out, e)
		}
	}
	return out
}

// Target is the file target.
type Target struct{}

var _ plugin.Target = Target{}

// New returns the file target.
func New() Target { return Target{} }

// Describe reports a PEM target with rollback.
func (Target) Describe(context.Context) (plugin.TargetCapabilities, error) {
	return plugin.TargetCapabilities{
		Accepts:            []plugin.KeyFormat{plugin.KeyFormatPEM},
		NeedsExportableKey: true,
		SupportsRollback:   true,
	}, nil
}

// Validate checks the settings and that the directory exists.
func (Target) Validate(_ context.Context, raw json.RawMessage) ([]string, error) {
	_, problems := parse(raw)
	return problems, nil
}

type parsed struct {
	Config
	uid, gid int // -1 when unchanged
	keyMode  fs.FileMode
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func parse(raw json.RawMessage) (*parsed, []string) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, []string{"settings: " + err.Error()}
	}
	p := &parsed{Config: c, uid: -1, gid: -1, keyMode: DefaultKeyMode}
	var problems []string

	if c.Dir == "" {
		problems = append(problems, "dir is required")
	} else if !filepath.IsAbs(c.Dir) {
		problems = append(problems, fmt.Sprintf("dir %q must be an absolute path", c.Dir))
	} else if info, err := os.Stat(c.Dir); err != nil {
		problems = append(problems, fmt.Sprintf("dir %s: %v", c.Dir, err))
	} else if !info.IsDir() {
		problems = append(problems, fmt.Sprintf("dir %s is not a directory", c.Dir))
	}

	if c.Files.Key == "" {
		problems = append(problems, "files.key is required")
	}
	if c.Files.Cert == "" && c.Files.FullChain == "" {
		problems = append(problems, "files needs cert or fullchain")
	}
	var seen []string
	for _, e := range c.Files.entries() {
		if !safeName.MatchString(e.name) {
			problems = append(problems, fmt.Sprintf("files.%s %q must be a plain file name in dir", e.kind, e.name))
		}
		if slices.Contains(seen, e.name) {
			problems = append(problems, fmt.Sprintf("files.%s %q is used for two files", e.kind, e.name))
		}
		seen = append(seen, e.name)
	}

	if c.Mode != "" {
		m, err := strconv.ParseUint(c.Mode, 8, 32)
		switch {
		case err != nil || m > 0o777:
			problems = append(problems, fmt.Sprintf("mode %q must be an octal file mode such as \"0640\"", c.Mode))
		case m&0o007 != 0:
			problems = append(problems, fmt.Sprintf("mode %s gives other users access to the private key", c.Mode))
		case m&0o400 == 0:
			problems = append(problems, fmt.Sprintf("mode %s does not let the owner read the key", c.Mode))
		default:
			p.keyMode = fs.FileMode(m)
		}
	}

	if c.Owner != "" {
		uid, gid, err := lookupOwner(c.Owner)
		if err != nil {
			problems = append(problems, "owner: "+err.Error())
		}
		p.uid, p.gid = uid, gid
	}
	return p, problems
}

func lookupOwner(owner string) (int, int, error) {
	if runtime.GOOS == "windows" {
		return -1, -1, errors.New("not supported on Windows")
	}
	u, g, _ := strings.Cut(owner, ":")
	uid, gid := -1, -1
	if u != "" {
		if n, err := strconv.Atoi(u); err == nil {
			uid = n
		} else if usr, err := user.Lookup(u); err == nil {
			uid, _ = strconv.Atoi(usr.Uid)
		} else {
			return -1, -1, fmt.Errorf("unknown user %q", u)
		}
	}
	if g != "" {
		if n, err := strconv.Atoi(g); err == nil {
			gid = n
		} else if grp, err := user.LookupGroup(g); err == nil {
			gid, _ = strconv.Atoi(grp.Gid)
		} else {
			return -1, -1, fmt.Errorf("unknown group %q", g)
		}
	}
	return uid, gid, nil
}

func mustParse(raw json.RawMessage) (*parsed, error) {
	p, problems := parse(raw)
	if len(problems) > 0 {
		return nil, errors.New("file target: " + strings.Join(problems, "; "))
	}
	return p, nil
}

// Current returns the serial of the certificate in the cert (or fullchain)
// file, or "" when there is none.
func (Target) Current(_ context.Context, raw json.RawMessage) (string, error) {
	p, err := mustParse(raw)
	if err != nil {
		return "", err
	}
	name := p.Files.Cert
	if name == "" {
		name = p.Files.FullChain
	}
	data, err := os.ReadFile(filepath.Join(p.Dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	leaf, err := certutil.ParseLeaf(string(data))
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return certutil.SerialHex(leaf.SerialNumber), nil
}

type stagedRef struct {
	ID string `json:"id"`
}

type previousRef struct {
	ID string `json:"id"`
	// Present lists the file names that existed before Activate. Files not
	// listed were created by Activate and are removed on rollback.
	Present []string `json:"present"`
}

func stagedName(name, id string) string { return "." + name + ".kk-staged-" + id }

// Stage writes the new files next to the live ones under temporary names,
// with their final mode and owner.
func (Target) Stage(_ context.Context, req plugin.StageRequest) (string, error) {
	p, err := mustParse(req.Config)
	if err != nil {
		return "", err
	}
	if req.Key.Format != plugin.KeyFormatPEM || len(req.Key.Data) == 0 {
		return "", errors.New("file target needs the private key as PEM")
	}
	id := time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + randomHex(3)
	contents := map[string][]byte{
		"cert":      []byte(req.CertPEM),
		"chain":     []byte(req.ChainPEM),
		"fullchain": []byte(req.FullChainPEM),
		"key":       req.Key.Data,
	}
	var written []string
	cleanup := func() {
		for _, w := range written {
			_ = os.Remove(w)
		}
	}
	for _, e := range p.Files.entries() {
		mode := DefaultCertMode
		if e.kind == "key" {
			mode = p.keyMode
		}
		path := filepath.Join(p.Dir, stagedName(e.name, id))
		if err := writeNew(path, contents[e.kind], mode, p.uid, p.gid); err != nil {
			cleanup()
			return "", fmt.Errorf("stage %s: %w", e.name, err)
		}
		written = append(written, path)
	}
	ref, _ := json.Marshal(stagedRef{ID: id})
	return string(ref), nil
}

// Activate backs up the live files and renames the staged files over them.
func (Target) Activate(_ context.Context, raw json.RawMessage, stagedRefJSON string) (string, error) {
	p, err := mustParse(raw)
	if err != nil {
		return "", err
	}
	var sr stagedRef
	if err := json.Unmarshal([]byte(stagedRefJSON), &sr); err != nil || !safeName.MatchString(sr.ID) {
		return "", fmt.Errorf("invalid staged ref %q", stagedRefJSON)
	}

	backup := filepath.Join(p.Dir, BackupDir, sr.ID)
	if err := os.MkdirAll(backup, 0o700); err != nil {
		return "", fmt.Errorf("create backup dir: %w", err)
	}
	prev := previousRef{ID: sr.ID}
	for _, e := range p.Files.entries() {
		live := filepath.Join(p.Dir, e.name)
		if _, err := os.Lstat(live); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return "", err
		}
		if err := preserve(live, filepath.Join(backup, e.name)); err != nil {
			return "", fmt.Errorf("back up %s: %w", e.name, err)
		}
		prev.Present = append(prev.Present, e.name)
	}
	prevJSON, _ := json.Marshal(prev)

	var done []entry
	for _, e := range p.Files.entries() {
		if err := os.Rename(filepath.Join(p.Dir, stagedName(e.name, sr.ID)), filepath.Join(p.Dir, e.name)); err != nil {
			// Put back whatever was already swapped, so the directory is
			// never left with a mix of old and new files.
			restoreErr := restore(p, prev, done)
			for _, rest := range p.Files.entries() {
				_ = os.Remove(filepath.Join(p.Dir, stagedName(rest.name, sr.ID)))
			}
			return "", errors.Join(fmt.Errorf("activate %s: %w", e.name, err), restoreErr)
		}
		done = append(done, e)
	}
	syncDir(p.Dir)
	pruneBackups(filepath.Join(p.Dir, BackupDir), keepBackups)
	return string(prevJSON), nil
}

// Rollback puts back the files that were live before Activate.
func (Target) Rollback(_ context.Context, raw json.RawMessage, previousRefJSON string) error {
	p, err := mustParse(raw)
	if err != nil {
		return err
	}
	var prev previousRef
	if err := json.Unmarshal([]byte(previousRefJSON), &prev); err != nil || !safeName.MatchString(prev.ID) {
		return fmt.Errorf("invalid previous ref %q", previousRefJSON)
	}
	return restore(p, prev, p.Files.entries())
}

func restore(p *parsed, prev previousRef, entries []entry) error {
	backup := filepath.Join(p.Dir, BackupDir, prev.ID)
	var errs []error
	for _, e := range entries {
		live := filepath.Join(p.Dir, e.name)
		if !slices.Contains(prev.Present, e.name) {
			if err := os.Remove(live); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		tmp := filepath.Join(p.Dir, "."+e.name+".kk-restore-"+randomHex(3))
		if err := preserve(filepath.Join(backup, e.name), tmp); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", e.name, err))
			continue
		}
		if err := os.Rename(tmp, live); err != nil {
			_ = os.Remove(tmp)
			errs = append(errs, fmt.Errorf("restore %s: %w", e.name, err))
		}
	}
	syncDir(p.Dir)
	return errors.Join(errs...)
}

// preserve makes dst a copy of src with the same mode and owner, using a
// hard link when possible.
func preserve(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	uid, gid := fileOwner(info)
	return writeNew(dst, data, info.Mode().Perm(), uid, gid)
}

// writeNew creates path (which must not exist) with exactly mode, sets the
// owner, and syncs it.
func writeNew(path string, data []byte, mode fs.FileMode, uid, gid int) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if uid != -1 || gid != -1 {
		if err := os.Lchown(path, uid, gid); err != nil {
			return err
		}
	}
	// Set the mode after chown, which can clear setuid/setgid bits, and
	// after writing, so the content is never readable more widely than the
	// final mode allows.
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	ok = true
	return nil
}

func pruneBackups(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names) // ids start with a UTC timestamp
	for len(names) > keep {
		_ = os.RemoveAll(filepath.Join(dir, names[0]))
		names = names[1:]
	}
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
