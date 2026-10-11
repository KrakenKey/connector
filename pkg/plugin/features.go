package plugin

import (
	"context"
	"slices"
)

// Optional protocol features. The connector sends the ones it supports
// with every Describe call, so a plugin can refuse to run with a connector
// that lacks one it depends on.
const (
	// FeatureRollbackMaterial means the connector fills the Previous*
	// fields of RollbackRequest for targets with RollbackNeedsMaterial.
	FeatureRollbackMaterial = "rollback_material"
	// FeatureKeyStoreValidateCapabilities means the connector uses the
	// capabilities a key store returns from ValidateCapabilities.
	FeatureKeyStoreValidateCapabilities = "keystore_validate_capabilities"
	// FeatureImplicitTarget means the connector adds the ImplicitTarget a
	// key store reports from ValidateCapabilities, sends
	// TargetValidateRequest.KeyStoreDeploymentID and reads
	// TargetValidation.DeploymentID.
	FeatureImplicitTarget = "implicit_target"
)

// CoreFeatures are the features the host side of this SDK supports. The
// connector built with it sends them in Describe requests.
var CoreFeatures = []string{FeatureRollbackMaterial, FeatureKeyStoreValidateCapabilities, FeatureImplicitTarget}

type coreFeaturesKey struct{}

// WithCoreFeatures returns a context carrying the connector's features.
// The gRPC server side of the SDK sets it for Describe calls; tests and
// in-process callers can set it themselves.
func WithCoreFeatures(ctx context.Context, features ...string) context.Context {
	return context.WithValue(ctx, coreFeaturesKey{}, slices.Clone(features))
}

// CoreFeaturesFrom returns the connector's features passed to Describe.
// Outside a Describe call, or with a connector that predates features, it
// returns nil.
func CoreFeaturesFrom(ctx context.Context) []string {
	f, _ := ctx.Value(coreFeaturesKey{}).([]string)
	return f
}

// HasCoreFeature reports whether the connector calling Describe supports
// feature.
func HasCoreFeature(ctx context.Context, feature string) bool {
	return slices.Contains(CoreFeaturesFrom(ctx), feature)
}

type installIDKey struct{}

// WithInstallID returns a context carrying the connector's install id. The
// connector sets it once for a run; the SDK sends it with every request
// that has an install_id field, and the plugin side puts it back into the
// context of the call.
func WithInstallID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, installIDKey{}, id)
}

// InstallIDFrom returns the install id of the connector making the call:
// an opaque, stable identifier of the installation (the connector's id in
// KrakenKey once it is enrolled, before that a random id kept in its data
// directory). Plugins may use it to tag resources they create. It is ""
// for connectors that predate it, and for calls that do not carry it
// (PublicKey, Export, Current).
func InstallIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(installIDKey{}).(string)
	return id
}
