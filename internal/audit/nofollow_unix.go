//go:build unix

package audit

import "syscall"

const syscallNoFollow = syscall.O_NOFOLLOW
