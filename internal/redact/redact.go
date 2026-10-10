// Package redact removes secrets from text that ends up in logs, errors
// and the audit log, such as the output of deployment commands.
package redact

import "regexp"

var (
	privateKeyRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)
	apiKeyRe     = regexp.MustCompile(`kk_[A-Za-z0-9_\-]{8,}`)
)

// String replaces PEM private keys and KrakenKey API keys in s.
func String(s string) string {
	s = privateKeyRe.ReplaceAllString(s, "[private key removed]")
	return apiKeyRe.ReplaceAllString(s, "kk_[removed]")
}

// Limit caps s at n bytes.
func Limit(s string, n int) string {
	if len(s) > n {
		return s[:n] + "... (truncated)"
	}
	return s
}
