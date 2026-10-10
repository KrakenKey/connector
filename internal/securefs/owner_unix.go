//go:build unix

package securefs

import (
	"io/fs"
	"os"
	"syscall"
)

// OwnedByMe reports whether info belongs to the effective user.
func OwnedByMe(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// Owner returns the uid and gid of info, or -1, -1.
func Owner(info fs.FileInfo) (int, int) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}
