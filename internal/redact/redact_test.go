package redact

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	in := "before -----BEGIN EC PRIVATE KEY-----\nMHcCAQEE\n-----END EC PRIVATE KEY----- after kk_abcdef123456 and " +
		"-----BEGIN PRIVATE KEY-----\ntruncated"
	out := String(in)
	for _, leak := range []string{"MHcCAQEE", "abcdef123456", "truncated"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q survived: %s", leak, out)
		}
	}
	if !strings.Contains(out, "before") || !strings.Contains(out, "after") {
		t.Errorf("too much removed: %s", out)
	}
	if out := String("token kkce_Zm9vYmFyYmF6cXV4 used"); strings.Contains(out, "Zm9vYmFy") || !strings.Contains(out, "kkce_[removed]") {
		t.Errorf("enrollment token survived: %s", out)
	}
	if got := Limit("abcdef", 3); got != "abc... (truncated)" {
		t.Errorf("Limit = %q", got)
	}
}
