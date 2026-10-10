package plugin

import (
	"fmt"
	"slices"
	"strings"
)

// IncompatibleError lists every reason a key store and target cannot work
// together.
type IncompatibleError struct {
	Reasons []string
}

func (e *IncompatibleError) Error() string {
	return "key store and target are incompatible: " + strings.Join(e.Reasons, "; ")
}

// Match checks whether a key store and a target can be used together for
// keys of type keyType, and returns the key format the core should use to
// hand the key to the target. An empty keyType checks only that the two
// share at least one key type.
//
// When they cannot work together the error is an *IncompatibleError listing
// every problem found, not only the first.
func Match(ks KeyStoreCapabilities, t TargetCapabilities, keyType KeyType) (KeyFormat, error) {
	var reasons []string

	if keyType != "" {
		if !slices.Contains(ks.KeyTypes, keyType) {
			reasons = append(reasons, fmt.Sprintf("key store cannot create %s keys (supports %s)",
				keyType, orNone(joinKeyTypes(ks.KeyTypes))))
		}
		if len(t.KeyTypes) > 0 && !slices.Contains(t.KeyTypes, keyType) {
			reasons = append(reasons, fmt.Sprintf("target cannot serve %s keys (accepts %s)",
				keyType, joinKeyTypes(t.KeyTypes)))
		}
	} else if len(t.KeyTypes) > 0 && !slices.ContainsFunc(ks.KeyTypes, func(k KeyType) bool {
		return slices.Contains(t.KeyTypes, k)
	}) {
		reasons = append(reasons, fmt.Sprintf("no key type in common: key store creates %s, target accepts %s",
			orNone(joinKeyTypes(ks.KeyTypes)), joinKeyTypes(t.KeyTypes)))
	}

	if t.NeedsExportableKey && !ks.Exportable {
		reasons = append(reasons, "target needs the private key, but the key store does not allow export")
	}

	format, formatReason := pickFormat(ks, t)
	if formatReason != "" {
		reasons = append(reasons, formatReason)
	}

	if len(reasons) > 0 {
		return "", &IncompatibleError{Reasons: reasons}
	}
	return format, nil
}

// pickFormat returns the preferred format both sides support. Formats other
// than a vault reference carry the key itself, so they need an exportable
// key store.
func pickFormat(ks KeyStoreCapabilities, t TargetCapabilities) (KeyFormat, string) {
	sharedButLocked := false
	for _, f := range formatPreference {
		if !slices.Contains(ks.Provides, f) || !slices.Contains(t.Accepts, f) {
			continue
		}
		if f != KeyFormatVaultRef && !ks.Exportable {
			sharedButLocked = true
			continue
		}
		return f, ""
	}
	if sharedButLocked {
		return "", fmt.Sprintf("target accepts only %s, which carries the private key, and the key store does not allow export",
			joinFormats(t.Accepts))
	}
	return "", fmt.Sprintf("no key format in common: key store provides %s, target accepts %s",
		joinFormats(ks.Provides), joinFormats(t.Accepts))
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// RollbackUnavailable returns why the core cannot roll back target t when
// its keys come from key store ks, or "" when it can. Unlike Match, this
// does not make the pair unusable: deployments still work, but a failed
// one keeps the new certificate.
func RollbackUnavailable(ks KeyStoreCapabilities, t TargetCapabilities) string {
	switch {
	case !t.SupportsRollback:
		return "target does not support rollback"
	case t.RollbackNeedsMaterial && !ks.Exportable:
		return "target needs the previous private key to roll back, and the key store does not allow export"
	}
	return ""
}
