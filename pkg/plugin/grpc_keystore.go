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

func (s *keyStoreGRPCServer) Describe(ctx context.Context, _ *pb.KeyStoreServiceDescribeRequest) (*pb.KeyStoreServiceDescribeResponse, error) {
	caps, err := s.impl.Describe(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.KeyStoreServiceDescribeResponse{Capabilities: pbKeyStoreCaps(caps)}, nil
}

func (s *keyStoreGRPCServer) CreateCSR(ctx context.Context, req *pb.CreateCSRRequest) (*pb.CreateCSRResponse, error) {
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

func (s *keyStoreGRPCServer) Complete(ctx context.Context, req *pb.CompleteRequest) (*pb.CompleteResponse, error) {
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
	resp, err := c.client.Describe(ctx, &pb.KeyStoreServiceDescribeRequest{})
	if err != nil {
		return KeyStoreCapabilities{}, fromStatus("key store describe", err)
	}
	return goKeyStoreCaps(resp.GetCapabilities()), nil
}

func (c *keyStoreGRPCClient) CreateCSR(ctx context.Context, req CSRRequest) (CSR, error) {
	resp, err := c.client.CreateCSR(ctx, &pb.CreateCSRRequest{
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

func (c *keyStoreGRPCClient) Complete(ctx context.Context, req CompleteRequest) (string, error) {
	resp, err := c.client.Complete(ctx, &pb.CompleteRequest{
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
	_, err := c.client.Release(ctx, &pb.ReleaseRequest{ConfigJson: req.Config, KeyRef: req.KeyRef})
	return fromStatus("key store release", err)
}
