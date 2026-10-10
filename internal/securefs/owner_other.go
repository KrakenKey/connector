//go:build !unix

package securefs

import "io/fs"

// OwnedByMe always reports true where ownership is not checked.
func OwnedByMe(fs.FileInfo) bool { return true }

// Owner returns -1, -1 where ownership is not available.
func Owner(fs.FileInfo) (int, int) { return -1, -1 }
