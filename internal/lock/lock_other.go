//go:build !unix

package lock

import "os"

// On platforms without flock the lock file only marks the directory; it
// does not exclude other processes.
func tryLock(*os.File) error { return nil }

func unlock(*os.File) {}
