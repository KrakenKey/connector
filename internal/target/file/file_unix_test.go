//go:build unix

package file

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/krakenkey/connector/internal/testca"
)

func TestOwner(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	cfg := settings(t, dir, fmt.Sprintf(`,"owner":%q`, u.Username+":"+g.Name))
	if problems, _ := New().Validate(context.Background(), cfg); len(problems) > 0 {
		t.Fatalf("problems: %q", problems)
	}
	deploy(t, New(), newBundle(t, testca.New(t), cfg))
	info, _ := os.Stat(filepath.Join(dir, "key.pem"))
	st := info.Sys().(*syscall.Stat_t)
	if fmt.Sprint(st.Uid) != u.Uid || fmt.Sprint(st.Gid) != u.Gid {
		t.Errorf("owner %d:%d, want %s:%s", st.Uid, st.Gid, u.Uid, u.Gid)
	}
}
