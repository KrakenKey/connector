//go:build unix

package execx

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestEnvDropsSecrets(t *testing.T) {
	t.Setenv("KK_API_KEY", "kk_secret")
	t.Setenv("KEEP_ME", "1")
	env := Env("EXTRA=2")
	for _, kv := range env {
		if strings.HasPrefix(kv, "KK_API_KEY=") {
			t.Fatal("KK_API_KEY passed to child processes")
		}
	}
	if !slices.Contains(env, "KEEP_ME=1") || !slices.Contains(env, "EXTRA=2") {
		t.Error("environment not passed through")
	}
}

func TestRun(t *testing.T) {
	ctx := context.Background()
	if err := Run(ctx, []string{"sh", "-c", "exit 0"}, Env(), time.Minute); err != nil {
		t.Fatalf("success: %v", err)
	}
	err := Run(ctx, []string{"sh", "-c", "printf '%05000d' 0; echo tail-marker >&2; exit 4"}, Env(), time.Minute)
	if err == nil || !strings.Contains(err.Error(), "exit status 4") || !strings.Contains(err.Error(), "tail-marker") {
		t.Fatalf("failure: %v", err)
	}
	if len(err.Error()) > maxOutput+200 {
		t.Errorf("error message not truncated: %d bytes", len(err.Error()))
	}
	err = Run(ctx, []string{"sleep", "5"}, Env(), 50*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout: %v", err)
	}
	if err := Run(ctx, nil, Env(), 0); err == nil {
		t.Error("empty command accepted")
	}
}
