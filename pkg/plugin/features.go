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
)

// CoreFeatures are the features the host side of this SDK supports. The
// connector built with it sends them in Describe requests.
var CoreFeatures = []string{FeatureRollbackMaterial, FeatureKeyStoreValidateCapabilities}

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
