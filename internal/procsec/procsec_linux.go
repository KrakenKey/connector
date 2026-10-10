//go:build linux

package procsec

import "golang.org/x/sys/unix"

func harden() error { return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }

// Dumpable reports the current PR_GET_DUMPABLE value.
func Dumpable() (bool, error) {
	v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	return v != 0, err
}
