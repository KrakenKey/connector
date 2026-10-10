// Package execx runs deployment commands (the exec target and then.exec
// hooks).
package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// SecretEnv lists environment variables never passed to child processes.
var SecretEnv = []string{"KK_API_KEY"}

// Env returns the current environment without SecretEnv, plus extra.
func Env(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		secret := false
		for _, s := range SecretEnv {
			if name == s {
				secret = true
				break
			}
		}
		if !secret {
			env = append(env, kv)
		}
	}
	return append(env, extra...)
}

// maxOutput caps how much command output is kept for error messages.
const maxOutput = 2048

// Run runs argv with env and timeout. A non-zero exit is an error that
// includes the end of the command's combined output.
func Run(ctx context.Context, argv []string, env []string, timeout time.Duration) error {
	if len(argv) == 0 || argv[0] == "" {
		return errors.New("no command")
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	var out tailBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	if err == nil {
		return nil
	}
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("timed out after %s", timeout)
	}
	if o := strings.TrimSpace(out.String()); o != "" {
		return fmt.Errorf("%s: %w: %s", argv[0], err, o)
	}
	return fmt.Errorf("%s: %w", argv[0], err)
}

// tailBuffer keeps the last maxOutput bytes written to it.
type tailBuffer struct{ b bytes.Buffer }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b.Write(p)
	if extra := t.b.Len() - maxOutput; extra > 0 {
		t.b.Next(extra)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return t.b.String() }
