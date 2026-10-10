// Package plugin is the SDK for KrakenKey connector plugins.
//
// A plugin is a separate executable that the connector starts and talks to
// over gRPC, using hashicorp/go-plugin. A plugin implements KeyStore,
// Target, or both, and calls Serve from main:
//
//	func main() {
//		plugin.Serve(plugin.ServeOpts{Target: &myTarget{}})
//	}
//
// The connector core uses Launch (or ClientConfig) to start a plugin and
// DispenseKeyStore or DispenseTarget to get an implementation that forwards
// calls over gRPC. Built-in key stores and targets implement the same
// interfaces in process.
//
// Errors: wrap ErrPermanent, ErrNotFound, ErrUnavailable, ErrInvalid or
// ErrUnsupported (see errors.go) so the core knows whether to retry. Embed
// UnimplementedKeyStore or UnimplementedTarget for calls you do not support.
//
// Secrets: KeyMaterial and StageRequest redact the private key when
// formatted, logged or JSON encoded. The generated protobuf messages do
// not, so never log them.
package plugin

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	pb "github.com/krakenkey/connector/proto/krakenkey/connector/plugin/v1"
)

// ProtocolVersion is the plugin protocol version this SDK speaks. It
// changes only on breaking changes to the gRPC services. Plugins and the
// connector negotiate it through go-plugin's versioned plugin sets, so a
// later connector can serve more than one version.
const ProtocolVersion = 1

// Plugin names used when dispensing.
const (
	KeyStorePluginName = "keystore"
	TargetPluginName   = "target"
)

// Handshake is shared by the connector and its plugins. The magic cookie is
// not a security measure; it stops a plugin binary from doing anything
// surprising when someone runs it by hand.
var Handshake = goplugin.HandshakeConfig{
	ProtocolVersion:  ProtocolVersion,
	MagicCookieKey:   "KRAKENKEY_CONNECTOR_PLUGIN",
	MagicCookieValue: "b6c1d9e4-connector-plugin",
}

// KeyStorePlugin is the go-plugin GRPCPlugin for key stores. Impl is set on
// the plugin side and left nil on the host side.
type KeyStorePlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	Impl KeyStore
}

// GRPCServer registers the key store service.
func (p *KeyStorePlugin) GRPCServer(_ *goplugin.GRPCBroker, s *grpc.Server) error {
	if p.Impl == nil {
		return errors.New("key store plugin has no implementation")
	}
	pb.RegisterKeyStoreServiceServer(s, &keyStoreGRPCServer{impl: p.Impl})
	return nil
}

// GRPCClient returns a KeyStore that calls the plugin.
func (p *KeyStorePlugin) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return &keyStoreGRPCClient{client: pb.NewKeyStoreServiceClient(c)}, nil
}

// TargetPlugin is the go-plugin GRPCPlugin for targets. Impl is set on the
// plugin side and left nil on the host side.
type TargetPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	Impl Target
}

// GRPCServer registers the target service.
func (p *TargetPlugin) GRPCServer(_ *goplugin.GRPCBroker, s *grpc.Server) error {
	if p.Impl == nil {
		return errors.New("target plugin has no implementation")
	}
	pb.RegisterTargetServiceServer(s, &targetGRPCServer{impl: p.Impl})
	return nil
}

// GRPCClient returns a Target that calls the plugin.
func (p *TargetPlugin) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return &targetGRPCClient{client: pb.NewTargetServiceClient(c)}, nil
}

var (
	_ goplugin.GRPCPlugin = (*KeyStorePlugin)(nil)
	_ goplugin.GRPCPlugin = (*TargetPlugin)(nil)
)

// ServeOpts says what a plugin binary provides. At least one of KeyStore
// and Target must be set.
type ServeOpts struct {
	KeyStore KeyStore
	Target   Target
	// Logger is optional. Plugin logs go to stderr, which the connector
	// collects into its own log.
	Logger hclog.Logger
}

// PluginSet returns the go-plugin set for the given implementations. Most
// plugin authors call Serve instead.
func (o ServeOpts) PluginSet() goplugin.PluginSet {
	set := goplugin.PluginSet{}
	if o.KeyStore != nil {
		set[KeyStorePluginName] = &KeyStorePlugin{Impl: o.KeyStore}
	}
	if o.Target != nil {
		set[TargetPluginName] = &TargetPlugin{Impl: o.Target}
	}
	return set
}

// Serve runs the plugin until the connector stops it. Call it from main.
// It panics if opts provides neither a key store nor a target.
func Serve(opts ServeOpts) {
	set := opts.PluginSet()
	if len(set) == 0 {
		panic("plugin.Serve: ServeOpts needs a KeyStore, a Target, or both")
	}
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig:  Handshake,
		VersionedPlugins: map[int]goplugin.PluginSet{ProtocolVersion: set},
		GRPCServer:       goplugin.DefaultGRPCServer,
		Logger:           opts.Logger,
	})
}

// HostPluginSet is the plugin set the connector uses when dispensing.
func HostPluginSet() goplugin.PluginSet {
	return goplugin.PluginSet{
		KeyStorePluginName: &KeyStorePlugin{},
		TargetPluginName:   &TargetPlugin{},
	}
}

// ClientConfig returns the go-plugin client config for starting the plugin
// in cmd. The connection is gRPC only, with mutual TLS negotiated
// automatically. Callers may adjust the result (for example to set
// SecureConfig) before passing it to goplugin.NewClient.
func ClientConfig(cmd *exec.Cmd, logger hclog.Logger) *goplugin.ClientConfig {
	return &goplugin.ClientConfig{
		HandshakeConfig:  Handshake,
		VersionedPlugins: map[int]goplugin.PluginSet{ProtocolVersion: HostPluginSet()},
		Cmd:              cmd,
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
		AutoMTLS:         true,
		Logger:           logger,
	}
}

// DispenseKeyStore returns the key store served by a started plugin.
func DispenseKeyStore(c goplugin.ClientProtocol) (KeyStore, error) {
	raw, err := c.Dispense(KeyStorePluginName)
	if err != nil {
		return nil, fmt.Errorf("plugin does not serve a key store: %w", err)
	}
	ks, ok := raw.(KeyStore)
	if !ok {
		return nil, fmt.Errorf("plugin returned %T, not a key store", raw)
	}
	return ks, nil
}

// DispenseTarget returns the target served by a started plugin.
func DispenseTarget(c goplugin.ClientProtocol) (Target, error) {
	raw, err := c.Dispense(TargetPluginName)
	if err != nil {
		return nil, fmt.Errorf("plugin does not serve a target: %w", err)
	}
	t, ok := raw.(Target)
	if !ok {
		return nil, fmt.Errorf("plugin returned %T, not a target", raw)
	}
	return t, nil
}
