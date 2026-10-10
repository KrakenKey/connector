//go:build !unix

package file

import "io/fs"

func fileOwner(fs.FileInfo) (int, int) { return -1, -1 }
