package plugin

import (
	"context"

	pb "github.com/krakenkey/connector/proto/krakenkey/connector/plugin/v1"
)

// keyStoreGRPCServer adapts a KeyStore to the generated gRPC server.
type keyStoreGRPCServer struct {
	pb.UnimplementedKeyStoreServiceServer
	impl KeyStore
}

func (s *keyStoreGRPCServer) Describe(ctx context.Context, req *pb.KeyStoreServiceDescribeRequest) (*pb.KeyStoreServiceDescribeResponse, error) {
	ctx = WithInstallID(ctx, req.GetInstallId())
	caps, err := s.impl.Describe(WithCoreFeatures(ctx, req.GetCoreFeatures()...))
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.KeyStoreServiceDescribeResponse{Capabilities: pbKeyStoreCaps(caps)}, nil
}

func (s *keyStoreGRPCServer) Validate(ctx context.Context, req *pb.KeyStoreServiceValidateRequest) (*pb.KeyStoreServiceValidateResponse, error) {
	ctx = WithInstallID(ctx, req.GetInstallId())
	v, err := ValidateKeyStore(ctx, s.impl, KeyStoreValidateRequest{Config: req.GetConfigJson(), CertificateID: req.GetCertificateId()})
	if err != nil {
		return nil, toStatus(err)
	}
	resp := &pb.KeyStoreServiceValidateResponse{Problems: v.Problems}
	if v.Capabilities != nil {
		resp.Capabilities = pbKeyStoreCaps(*v.Capabilities)
	}
	return resp, nil
}

func (s *keyStoreGRPCServer) CreateCSR(ctx context.Context, req *pb.CreateCSRRequest) (*pb.CreateCSRResponse, error) {
	ctx = WithInstallID(ctx, req.GetInstallId())
	csr, err := s.impl.CreateCSR(ctx, CSRRequest{
		Config:        req.GetConfigJson(),
		CertificateID: req.GetCertificateId(),
		Names:         req.GetNames(),
		KeyType:       goKeyType(req.GetKeyType()),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.CreateCSRResponse{CsrPem: csr.PEM, KeyRef: csr.KeyRef}, nil
}

func (s *keyStoreGRPCServer) PublicKey(ctx context.Context, req *pb.PublicKeyRequest) (*pb.PublicKeyResponse, error) {
	der, err := s.impl.PublicKey(ctx, PublicKeyRequest{Config: req.GetConfigJson(), KeyRef: req.GetKeyRef()})
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.PublicKeyResponse{SpkiDer: der}, nil
}

func (s *keyStoreGRPCServer) Complete(ctx context.Context, req *pb.CompleteRequest) (*pb.CompleteResponse, error) {
	ctx = WithInstallID(ctx, req.GetInstallId())
	ref, err := s.impl.Complete(ctx, CompleteRequest{
		Config:   req.GetConfigJson(),
		KeyRef:   req.GetKeyRef(),
		CertPEM:  req.GetCertPem(),
		ChainPEM: req.GetChainPem(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.CompleteResponse{KeyRef: ref}, nil
}

func (s *keyStoreGRPCServer) Export(ctx context.Context, req *pb.ExportRequest) (*pb.ExportResponse, error) {
	key, err := s.impl.Export(ctx, ExportRequest{
		Config: req.GetConfigJson(),
		KeyRef: req.GetKeyRef(),
		Format: goFormat(req.GetFormat()),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.ExportResponse{Key: pbKeyMaterial(key)}, nil
}

func (s *keyStoreGRPCServer) Release(ctx context.Context, req *pb.ReleaseRequest) (*pb.ReleaseResponse, error) {
	ctx = WithInstallID(ctx, req.GetInstallId())
	if err := s.impl.Release(ctx, ReleaseRequest{Config: req.GetConfigJson(), KeyRef: req.GetKeyRef()}); err != nil {
		return nil, toStatus(err)
	}
	return &pb.ReleaseResponse{}, nil
}

// keyStoreGRPCClient implements KeyStore over a gRPC connection.
type keyStoreGRPCClient struct {
	client pb.KeyStoreServiceClient
}

var _ KeyStore = (*keyStoreGRPCClient)(nil)

func (c *keyStoreGRPCClient) Describe(ctx context.Context) (KeyStoreCapabilities, error) {
	resp, err := c.client.Describe(ctx, &pb.KeyStoreServiceDescribeRequest{InstallId: InstallIDFrom(ctx), CoreFeatures: CoreFeatures})
	if err != nil {
		return KeyStoreCapabilities{}, fromStatus("key store describe", err)
	}
	return goKeyStoreCaps(resp.GetCapabilities()), nil
}

func (c *keyStoreGRPCClient) Validate(ctx context.Context, req KeyStoreValidateRequest) ([]string, error) {
	v, err := c.ValidateCapabilities(ctx, req)
	return v.Problems, err
}

// ValidateCapabilities returns the problems and, if the key store sent
// them, the capabilities for these settings.
func (c *keyStoreGRPCClient) ValidateCapabilities(ctx context.Context, req KeyStoreValidateRequest) (KeyStoreValidation, error) {
	resp, err := c.client.Validate(ctx, &pb.KeyStoreServiceValidateRequest{InstallId: InstallIDFrom(ctx), ConfigJson: req.Config, CertificateId: req.CertificateID})
	if err != nil {
		return KeyStoreValidation{}, fromStatus("key store validate", err)
	}
	v := KeyStoreValidation{Problems: resp.GetProblems()}
	if resp.Capabilities != nil {
		caps := goKeyStoreCaps(resp.GetCapabilities())
		v.Capabilities = &caps
	}
	return v, nil
}

func (c *keyStoreGRPCClient) CreateCSR(ctx context.Context, req CSRRequest) (CSR, error) {
	resp, err := c.client.CreateCSR(ctx, &pb.CreateCSRRequest{InstallId: InstallIDFrom(ctx),
		ConfigJson:    req.Config,
		CertificateId: req.CertificateID,
		Names:         req.Names,
		KeyType:       pbKeyType(req.KeyType),
	})
	if err != nil {
		return CSR{}, fromStatus("key store create CSR", err)
	}
	return CSR{PEM: resp.GetCsrPem(), KeyRef: resp.GetKeyRef()}, nil
}

func (c *keyStoreGRPCClient) PublicKey(ctx context.Context, req PublicKeyRequest) ([]byte, error) {
	resp, err := c.client.PublicKey(ctx, &pb.PublicKeyRequest{ConfigJson: req.Config, KeyRef: req.KeyRef})
	if err != nil {
		return nil, fromStatus("key store public key", err)
	}
	return resp.GetSpkiDer(), nil
}

func (c *keyStoreGRPCClient) Complete(ctx context.Context, req CompleteRequest) (string, error) {
	resp, err := c.client.Complete(ctx, &pb.CompleteRequest{InstallId: InstallIDFrom(ctx),
		ConfigJson: req.Config,
		KeyRef:     req.KeyRef,
		CertPem:    req.CertPEM,
		ChainPem:   req.ChainPEM,
	})
	if err != nil {
		return "", fromStatus("key store complete", err)
	}
	return resp.GetKeyRef(), nil
}

func (c *keyStoreGRPCClient) Export(ctx context.Context, req ExportRequest) (KeyMaterial, error) {
	resp, err := c.client.Export(ctx, &pb.ExportRequest{
		ConfigJson: req.Config,
		KeyRef:     req.KeyRef,
		Format:     pbFormat(req.Format),
	})
	if err != nil {
		return KeyMaterial{}, fromStatus("key store export", err)
	}
	return goKeyMaterial(resp.GetKey()), nil
}

func (c *keyStoreGRPCClient) Release(ctx context.Context, req ReleaseRequest) error {
	_, err := c.client.Release(ctx, &pb.ReleaseRequest{InstallId: InstallIDFrom(ctx), ConfigJson: req.Config, KeyRef: req.KeyRef})
	return fromStatus("key store release", err)
}
