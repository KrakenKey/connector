//go:build unix

package file

import (
	"io/fs"
	"syscall"
)

func fileOwner(info fs.FileInfo) (int, int) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}
