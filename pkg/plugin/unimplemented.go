package plugin

import (
	"context"
	"fmt"
)

func unsupported(call string) error { return fmt.Errorf("%w: %s", ErrUnsupported, call) }

// UnimplementedKeyStore answers every KeyStore call with ErrUnsupported.
// Embed it in a key store so it keeps compiling when calls are added to
// the interface, and override the calls you support.
type UnimplementedKeyStore struct{}

// Describe is not supported.
func (UnimplementedKeyStore) Describe(context.Context) (KeyStoreCapabilities, error) {
	return KeyStoreCapabilities{}, unsupported("Describe")
}

// Validate is not supported, which the core treats as "nothing to check".
func (UnimplementedKeyStore) Validate(context.Context, KeyStoreValidateRequest) ([]string, error) {
	return nil, unsupported("Validate")
}

// CreateCSR is not supported.
func (UnimplementedKeyStore) CreateCSR(context.Context, CSRRequest) (CSR, error) {
	return CSR{}, unsupported("CreateCSR")
}

// PublicKey is not supported.
func (UnimplementedKeyStore) PublicKey(context.Context, PublicKeyRequest) ([]byte, error) {
	return nil, unsupported("PublicKey")
}

// Complete is not supported.
func (UnimplementedKeyStore) Complete(context.Context, CompleteRequest) (string, error) {
	return "", unsupported("Complete")
}

// Export is not supported.
func (UnimplementedKeyStore) Export(context.Context, ExportRequest) (KeyMaterial, error) {
	return KeyMaterial{}, unsupported("Export")
}

// Release is not supported.
func (UnimplementedKeyStore) Release(context.Context, ReleaseRequest) error {
	return unsupported("Release")
}

// UnimplementedTarget answers every Target call with ErrUnsupported. Embed
// it in a target so it keeps compiling when calls are added to the
// interface, and override the calls you support.
type UnimplementedTarget struct{}

// Describe is not supported.
func (UnimplementedTarget) Describe(context.Context) (TargetCapabilities, error) {
	return TargetCapabilities{}, unsupported("Describe")
}

// Validate is not supported.
func (UnimplementedTarget) Validate(context.Context, TargetValidateRequest) ([]string, error) {
	return nil, unsupported("Validate")
}

// Current is not supported, which the core treats as "cannot tell".
func (UnimplementedTarget) Current(context.Context, CurrentRequest) (string, error) {
	return "", unsupported("Current")
}

// Stage is not supported.
func (UnimplementedTarget) Stage(context.Context, StageRequest) (string, error) {
	return "", unsupported("Stage")
}

// Activate is not supported.
func (UnimplementedTarget) Activate(context.Context, ActivateRequest) (string, error) {
	return "", unsupported("Activate")
}

// Rollback is not supported.
func (UnimplementedTarget) Rollback(context.Context, RollbackRequest) error {
	return unsupported("Rollback")
}

// Discard is not supported, which the core ignores.
func (UnimplementedTarget) Discard(context.Context, DiscardRequest) error {
	return unsupported("Discard")
}

var (
	_ KeyStore = UnimplementedKeyStore{}
	_ Target   = UnimplementedTarget{}
)
