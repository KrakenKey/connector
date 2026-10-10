//go:build !linux

package procsec

func harden() error { return nil }

// Dumpable is always true where it cannot be changed.
func Dumpable() (bool, error) { return true, nil }
