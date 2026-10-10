// Package file is the built-in target that writes PEM files into a
// directory, for servers such as nginx, HAProxy or Caddy.
//
// Every file system operation goes through an os.Root opened on the target
// directory, so symlinks cannot make the target read, write or delete
// anything outside it. Files are created with O_EXCL and their owner and
// mode are set on the open file descriptor before it is closed.
//
// Each file is replaced atomically: the new content is written to a temp
// file in the same directory and renamed over the old one. Before that, the
// old files are copied into
// <dir>/.krakenkey-previous/<stage id>/ so Rollback can put them back.
//
// Retention: the two most recent backup sets are kept, and each holds a
// copy of the private key that was live before. The backup directory must
// be a real directory owned by the connector's user with mode 0700.
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
	"github.com/krakenkey/connector/internal/securefs"
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
func (Target) Validate(_ context.Context, req plugin.TargetValidateRequest) ([]string, error) {
	_, problems := parse(req.Config)
	return problems, nil
}

type parsed struct {
	Config
	uid, gid int // -1 when unchanged
	keyMode  fs.FileMode
}

var (
	safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	// idRe matches stage ids, which name staged files and backup sets.
	idRe = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{9}Z-[0-9a-f]{6}$`)
	// tempRe matches the temp files this target leaves while working.
	tempRe = regexp.MustCompile(`^\..+\.kk-(staged|restore)-[0-9A-Za-z.\-]+$`)
)

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
		return nil, fmt.Errorf("%w: file target: %s", plugin.ErrPermanent, strings.Join(problems, "; "))
	}
	return p, nil
}

// open parses the settings and opens the target directory as a Root.
func open(raw json.RawMessage) (*parsed, *os.Root, error) {
	p, err := mustParse(raw)
	if err != nil {
		return nil, nil, err
	}
	root, err := os.OpenRoot(p.Dir)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", p.Dir, err)
	}
	return p, root, nil
}

// Current returns the serial of the certificate in the cert (or fullchain)
// file, or "" when there is none.
func (Target) Current(_ context.Context, req plugin.CurrentRequest) (string, error) {
	p, root, err := open(req.Config)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	name := p.Files.Cert
	if name == "" {
		name = p.Files.FullChain
	}
	data, err := root.ReadFile(name)
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

func newID() string {
	return time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + randomHex(3)
}

// Stage writes the new files next to the live ones under temporary names,
// with their final mode and owner. Leftover temp files from an earlier,
// interrupted run are removed first.
func (Target) Stage(_ context.Context, req plugin.StageRequest) (string, error) {
	p, root, err := open(req.Config)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	if req.Key.Format != plugin.KeyFormatPEM || len(req.Key.Data) == 0 {
		return "", fmt.Errorf("%w: file target needs the private key as PEM", plugin.ErrPermanent)
	}
	sweepTemps(root)

	id := newID()
	contents := map[string][]byte{
		"cert":      []byte(req.CertPEM),
		"chain":     []byte(req.ChainPEM),
		"fullchain": []byte(req.FullChainPEM),
		"key":       req.Key.Data,
	}
	for _, e := range p.Files.entries() {
		mode := DefaultCertMode
		if e.kind == "key" {
			mode = p.keyMode
		}
		if err := writeNew(root, stagedName(e.name, id), contents[e.kind], mode, p.uid, p.gid); err != nil {
			removeStaged(root, p, id)
			return "", fmt.Errorf("stage %s: %w", e.name, err)
		}
	}
	ref, _ := json.Marshal(stagedRef{ID: id})
	return string(ref), nil
}

// Discard removes staged files. Unknown ids are ignored.
func (Target) Discard(_ context.Context, req plugin.DiscardRequest) error {
	p, root, err := open(req.Config)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	var sr stagedRef
	if err := json.Unmarshal([]byte(req.StagedRef), &sr); err != nil || !idRe.MatchString(sr.ID) {
		return fmt.Errorf("%w: staged ref %q", plugin.ErrInvalid, req.StagedRef)
	}
	removeStaged(root, p, sr.ID)
	return nil
}

func removeStaged(root *os.Root, p *parsed, id string) {
	for _, e := range p.Files.entries() {
		_ = root.Remove(stagedName(e.name, id))
	}
}

// sweepTemps removes staged and restore temp files left by an interrupted
// run. Only one connector process uses a data directory at a time, and
// each target is staged and then activated or discarded before the next,
// so any such file found here is stale.
func sweepTemps(root *os.Root) {
	d, err := root.Open(".")
	if err != nil {
		return
	}
	names, _ := d.Readdirnames(-1)
	_ = d.Close()
	for _, n := range names {
		if tempRe.MatchString(n) {
			if info, err := root.Lstat(n); err == nil && info.Mode().IsRegular() {
				_ = root.Remove(n)
			}
		}
	}
}

// backupRoot returns a Root for the backup directory, creating it if
// needed. It must be a real directory, owned by the connector's user, with
// no group or other access.
func backupRoot(root *os.Root) (*os.Root, error) {
	if err := root.Mkdir(BackupDir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("create %s: %w", BackupDir, err)
	}
	if err := checkPrivateDir(root, BackupDir); err != nil {
		return nil, err
	}
	return root.OpenRoot(BackupDir)
}

func checkPrivateDir(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	switch {
	case info.Mode()&fs.ModeSymlink != 0 || !info.IsDir():
		return fmt.Errorf("%w: %s must be a directory, not a symlink or file", plugin.ErrPermanent, name)
	case !securefs.OwnedByMe(info):
		return fmt.Errorf("%w: %s is not owned by the user running the connector", plugin.ErrPermanent, name)
	case runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("%w: %s has mode %04o, want 0700", plugin.ErrPermanent, name, info.Mode().Perm())
	}
	return nil
}

// Activate backs up the live files and renames the staged files over them.
// On failure it restores what it already swapped and removes the staged
// files, so the directory is never left with a mix of old and new files.
func (Target) Activate(_ context.Context, req plugin.ActivateRequest) (prevJSON string, err error) {
	p, root, err := open(req.Config)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	var sr stagedRef
	if err := json.Unmarshal([]byte(req.StagedRef), &sr); err != nil || !idRe.MatchString(sr.ID) {
		return "", fmt.Errorf("%w: staged ref %q", plugin.ErrInvalid, req.StagedRef)
	}
	defer func() {
		if err != nil {
			removeStaged(root, p, sr.ID)
		}
	}()
	for _, e := range p.Files.entries() {
		if _, err := root.Lstat(stagedName(e.name, sr.ID)); err != nil {
			return "", fmt.Errorf("%w: staged file for %s: %v", plugin.ErrNotFound, e.name, err)
		}
	}

	backups, err := backupRoot(root)
	if err != nil {
		return "", err
	}
	defer func() { _ = backups.Close() }()
	if err := backups.Mkdir(sr.ID, 0o700); err != nil {
		return "", fmt.Errorf("create backup set: %w", err)
	}
	set, err := backups.OpenRoot(sr.ID)
	if err != nil {
		return "", err
	}
	defer func() { _ = set.Close() }()

	prev := previousRef{ID: sr.ID}
	for _, e := range p.Files.entries() {
		if _, err := root.Lstat(e.name); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return "", err
		}
		if err := preserve(root, e.name, set, e.name); err != nil {
			return "", fmt.Errorf("back up %s: %w", e.name, err)
		}
		prev.Present = append(prev.Present, e.name)
	}
	_ = syncRoot(set)
	out, _ := json.Marshal(prev)

	var done []entry
	for _, e := range p.Files.entries() {
		if err := root.Rename(stagedName(e.name, sr.ID), e.name); err != nil {
			restoreErr := restore(root, set, prev, done)
			return "", errors.Join(fmt.Errorf("activate %s: %w", e.name, err), restoreErr)
		}
		done = append(done, e)
	}
	_ = syncRoot(root)
	pruneBackups(backups, sr.ID, keepBackups)
	return string(out), nil
}

// Rollback puts back the files that were live before Activate, and removes
// files that did not exist then.
func (Target) Rollback(_ context.Context, req plugin.RollbackRequest) error {
	p, root, err := open(req.Config)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	var prev previousRef
	if err := json.Unmarshal([]byte(req.PreviousRef), &prev); err != nil || !idRe.MatchString(prev.ID) {
		return fmt.Errorf("%w: previous ref %q", plugin.ErrInvalid, req.PreviousRef)
	}
	backups, err := backupRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = backups.Close() }()
	if err := checkPrivateDir(backups, prev.ID); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: backup set %s", plugin.ErrNotFound, prev.ID)
		}
		return err
	}
	set, err := backups.OpenRoot(prev.ID)
	if err != nil {
		return err
	}
	defer func() { _ = set.Close() }()
	return restore(root, set, prev, p.Files.entries())
}

func restore(root, set *os.Root, prev previousRef, entries []entry) error {
	var errs []error
	for _, e := range entries {
		if !slices.Contains(prev.Present, e.name) {
			if err := root.Remove(e.name); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		tmp := "." + e.name + ".kk-restore-" + randomHex(3)
		if err := preserve(set, e.name, root, tmp); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", e.name, err))
			continue
		}
		if err := root.Rename(tmp, e.name); err != nil {
			_ = root.Remove(tmp)
			errs = append(errs, fmt.Errorf("restore %s: %w", e.name, err))
		}
	}
	_ = syncRoot(root)
	return errors.Join(errs...)
}

// preserve makes dstName in dst a copy of srcName in src, with the same
// mode and owner. Both names are resolved inside their roots.
func preserve(src *os.Root, srcName string, dst *os.Root, dstName string) error {
	in, err := src.OpenFile(srcName, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", srcName)
	}
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	uid, gid := securefs.Owner(info)
	return writeNew(dst, dstName, data, info.Mode().Perm(), uid, gid)
}

// writeNew creates name in root (it must not exist), writes data, and sets
// owner and mode on the open descriptor before closing it.
func writeNew(root *os.Root, name string, data []byte, mode fs.FileMode, uid, gid int) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = root.Remove(name)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if uid != -1 || gid != -1 {
		if err := f.Chown(uid, gid); err != nil {
			_ = f.Close()
			return err
		}
	}
	// After chown, which can clear setuid/setgid bits, and after writing,
	// so the content is never readable more widely than the final mode.
	if err := f.Chmod(mode); err != nil {
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
	ok = true
	return nil
}

// pruneBackups keeps the newest keep backup sets, never removing current,
// and only touches directories whose names are stage ids.
func pruneBackups(backups *os.Root, current string, keep int) {
	d, err := backups.Open(".")
	if err != nil {
		return
	}
	names, _ := d.Readdirnames(-1)
	_ = d.Close()
	var sets []string
	for _, n := range names {
		if !idRe.MatchString(n) {
			continue
		}
		if info, err := backups.Lstat(n); err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
			continue
		}
		sets = append(sets, n)
	}
	slices.Sort(sets) // ids start with a UTC timestamp
	for len(sets) > keep {
		if sets[0] != current {
			_ = backups.RemoveAll(sets[0])
		}
		sets = sets[1:]
	}
}

func syncRoot(r *os.Root) error {
	d, err := r.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
