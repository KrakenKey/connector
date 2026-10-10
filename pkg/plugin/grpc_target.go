package plugin

import (
	"context"

	pb "github.com/krakenkey/connector/proto/krakenkey/connector/plugin/v1"
)

// targetGRPCServer adapts a Target to the generated gRPC server.
type targetGRPCServer struct {
	pb.UnimplementedTargetServiceServer
	impl Target
}

func (s *targetGRPCServer) Describe(ctx context.Context, req *pb.TargetServiceDescribeRequest) (*pb.TargetServiceDescribeResponse, error) {
	ctx = WithInstallID(ctx, req.GetInstallId())
	caps, err := s.impl.Describe(WithCoreFeatures(ctx, req.GetCoreFeatures()...))
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.TargetServiceDescribeResponse{Capabilities: pbTargetCaps(caps)}, nil
}

func (s *targetGRPCServer) Validate(ctx context.Context, req *pb.TargetServiceValidateRequest) (*pb.TargetServiceValidateResponse, error) {
	ctx = WithInstallID(ctx, req.GetInstallId())
	problems, err := s.impl.Validate(ctx, TargetValidateRequest{
		Config: req.GetConfigJson(), CertificateID: req.GetCertificateId(), Label: req.GetLabel(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.TargetServiceValidateResponse{Problems: problems}, nil
}

func (s *targetGRPCServer) Current(ctx context.Context, req *pb.CurrentRequest) (*pb.CurrentResponse, error) {
	serial, err := s.impl.Current(ctx, CurrentRequest{
		Config: req.GetConfigJson(), CertificateID: req.GetCertificateId(), Label: req.GetLabel(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.CurrentResponse{Serial: serial}, nil
}

func (s *targetGRPCServer) Stage(ctx context.Context, req *pb.StageRequest) (*pb.StageResponse, error) {
	ctx = WithInstallID(ctx, req.GetInstallId())
	ref, err := s.impl.Stage(ctx, StageRequest{
		Config:        req.GetConfigJson(),
		CertificateID: req.GetCertificateId(),
		Label:         req.GetLabel(),
		CertPEM:       req.GetCertPem(),
		ChainPEM:      req.GetChainPem(),
		FullChainPEM:  req.GetFullchainPem(),
		Key:           goKeyMaterial(req.GetKey()),
		Serial:        req.GetSerial(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.StageResponse{StagedRef: ref}, nil
}

func (s *targetGRPCServer) Activate(ctx context.Context, req *pb.ActivateRequest) (*pb.ActivateResponse, error) {
	ctx = WithInstallID(ctx, req.GetInstallId())
	prev, err := s.impl.Activate(ctx, ActivateRequest{
		Config: req.GetConfigJson(), StagedRef: req.GetStagedRef(),
		CertificateID: req.GetCertificateId(), Label: req.GetLabel(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.ActivateResponse{PreviousRef: prev}, nil
}

func (s *targetGRPCServer) Rollback(ctx context.Context, req *pb.RollbackRequest) (*pb.RollbackResponse, error) {
	ctx = WithInstallID(ctx, req.GetInstallId())
	err := s.impl.Rollback(ctx, RollbackRequest{
		Config: req.GetConfigJson(), PreviousRef: req.GetPreviousRef(),
		CertificateID: req.GetCertificateId(), Label: req.GetLabel(),
		PreviousCertPEM:      req.GetPreviousCertPem(),
		PreviousChainPEM:     req.GetPreviousChainPem(),
		PreviousFullChainPEM: req.GetPreviousFullchainPem(),
		PreviousKey:          goKeyMaterial(req.GetPreviousKey()),
		PreviousSerial:       req.GetPreviousSerial(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.RollbackResponse{}, nil
}

func (s *targetGRPCServer) Discard(ctx context.Context, req *pb.DiscardRequest) (*pb.DiscardResponse, error) {
	ctx = WithInstallID(ctx, req.GetInstallId())
	err := s.impl.Discard(ctx, DiscardRequest{
		Config: req.GetConfigJson(), StagedRef: req.GetStagedRef(),
		CertificateID: req.GetCertificateId(), Label: req.GetLabel(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.DiscardResponse{}, nil
}

// targetGRPCClient implements Target over a gRPC connection.
type targetGRPCClient struct {
	client pb.TargetServiceClient
}

var _ Target = (*targetGRPCClient)(nil)

func (c *targetGRPCClient) Describe(ctx context.Context) (TargetCapabilities, error) {
	resp, err := c.client.Describe(ctx, &pb.TargetServiceDescribeRequest{InstallId: InstallIDFrom(ctx), CoreFeatures: CoreFeatures})
	if err != nil {
		return TargetCapabilities{}, fromStatus("target describe", err)
	}
	return goTargetCaps(resp.GetCapabilities()), nil
}

func (c *targetGRPCClient) Validate(ctx context.Context, req TargetValidateRequest) ([]string, error) {
	resp, err := c.client.Validate(ctx, &pb.TargetServiceValidateRequest{InstallId: InstallIDFrom(ctx),
		ConfigJson: req.Config, CertificateId: req.CertificateID, Label: req.Label,
	})
	if err != nil {
		return nil, fromStatus("target validate", err)
	}
	return resp.GetProblems(), nil
}

func (c *targetGRPCClient) Current(ctx context.Context, req CurrentRequest) (string, error) {
	resp, err := c.client.Current(ctx, &pb.CurrentRequest{
		ConfigJson: req.Config, CertificateId: req.CertificateID, Label: req.Label,
	})
	if err != nil {
		return "", fromStatus("target current", err)
	}
	return resp.GetSerial(), nil
}

func (c *targetGRPCClient) Stage(ctx context.Context, req StageRequest) (string, error) {
	resp, err := c.client.Stage(ctx, &pb.StageRequest{InstallId: InstallIDFrom(ctx),
		ConfigJson:    req.Config,
		CertificateId: req.CertificateID,
		Label:         req.Label,
		CertPem:       req.CertPEM,
		ChainPem:      req.ChainPEM,
		FullchainPem:  req.FullChainPEM,
		Key:           pbKeyMaterial(req.Key),
		Serial:        req.Serial,
	})
	if err != nil {
		return "", fromStatus("target stage", err)
	}
	return resp.GetStagedRef(), nil
}

func (c *targetGRPCClient) Activate(ctx context.Context, req ActivateRequest) (string, error) {
	resp, err := c.client.Activate(ctx, &pb.ActivateRequest{InstallId: InstallIDFrom(ctx),
		ConfigJson: req.Config, StagedRef: req.StagedRef, CertificateId: req.CertificateID, Label: req.Label,
	})
	if err != nil {
		return "", fromStatus("target activate", err)
	}
	return resp.GetPreviousRef(), nil
}

func (c *targetGRPCClient) Rollback(ctx context.Context, req RollbackRequest) error {
	_, err := c.client.Rollback(ctx, &pb.RollbackRequest{InstallId: InstallIDFrom(ctx),
		ConfigJson: req.Config, PreviousRef: req.PreviousRef, CertificateId: req.CertificateID, Label: req.Label,
		PreviousCertPem:      req.PreviousCertPEM,
		PreviousChainPem:     req.PreviousChainPEM,
		PreviousFullchainPem: req.PreviousFullChainPEM,
		PreviousKey:          pbKeyMaterial(req.PreviousKey),
		PreviousSerial:       req.PreviousSerial,
	})
	return fromStatus("target rollback", err)
}

func (c *targetGRPCClient) Discard(ctx context.Context, req DiscardRequest) error {
	_, err := c.client.Discard(ctx, &pb.DiscardRequest{InstallId: InstallIDFrom(ctx),
		ConfigJson: req.Config, StagedRef: req.StagedRef, CertificateId: req.CertificateID, Label: req.Label,
	})
	return fromStatus("target discard", err)
}
