// Package procsec hardens the connector process.
package procsec

// Harden makes the process non-dumpable where the platform supports it. On
// Linux this stops other processes running as the same user, including
// plugins and deployment commands started by the connector, from reading
// its memory or its original environment through /proc. Root can still
// read both.
func Harden() error { return harden() }
