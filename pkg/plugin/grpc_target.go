package plugin

import (
	"context"
	"encoding/json"

	pb "github.com/krakenkey/connector/proto/krakenkey/connector/plugin/v1"
)

// targetGRPCServer adapts a Target to the generated gRPC server.
type targetGRPCServer struct {
	pb.UnimplementedTargetServiceServer
	impl Target
}

func (s *targetGRPCServer) Describe(ctx context.Context, _ *pb.TargetServiceDescribeRequest) (*pb.TargetServiceDescribeResponse, error) {
	caps, err := s.impl.Describe(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.TargetServiceDescribeResponse{Capabilities: pbTargetCaps(caps)}, nil
}

func (s *targetGRPCServer) Validate(ctx context.Context, req *pb.ValidateRequest) (*pb.ValidateResponse, error) {
	problems, err := s.impl.Validate(ctx, req.GetConfigJson())
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.ValidateResponse{Problems: problems}, nil
}

func (s *targetGRPCServer) Current(ctx context.Context, req *pb.CurrentRequest) (*pb.CurrentResponse, error) {
	serial, err := s.impl.Current(ctx, req.GetConfigJson())
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.CurrentResponse{Serial: serial}, nil
}

func (s *targetGRPCServer) Stage(ctx context.Context, req *pb.StageRequest) (*pb.StageResponse, error) {
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
	prev, err := s.impl.Activate(ctx, req.GetConfigJson(), req.GetStagedRef())
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.ActivateResponse{PreviousRef: prev}, nil
}

func (s *targetGRPCServer) Rollback(ctx context.Context, req *pb.RollbackRequest) (*pb.RollbackResponse, error) {
	if err := s.impl.Rollback(ctx, req.GetConfigJson(), req.GetPreviousRef()); err != nil {
		return nil, toStatus(err)
	}
	return &pb.RollbackResponse{}, nil
}

// targetGRPCClient implements Target over a gRPC connection.
type targetGRPCClient struct {
	client pb.TargetServiceClient
}

var _ Target = (*targetGRPCClient)(nil)

func (c *targetGRPCClient) Describe(ctx context.Context) (TargetCapabilities, error) {
	resp, err := c.client.Describe(ctx, &pb.TargetServiceDescribeRequest{})
	if err != nil {
		return TargetCapabilities{}, fromStatus("target describe", err)
	}
	return goTargetCaps(resp.GetCapabilities()), nil
}

func (c *targetGRPCClient) Validate(ctx context.Context, config json.RawMessage) ([]string, error) {
	resp, err := c.client.Validate(ctx, &pb.ValidateRequest{ConfigJson: config})
	if err != nil {
		return nil, fromStatus("target validate", err)
	}
	return resp.GetProblems(), nil
}

func (c *targetGRPCClient) Current(ctx context.Context, config json.RawMessage) (string, error) {
	resp, err := c.client.Current(ctx, &pb.CurrentRequest{ConfigJson: config})
	if err != nil {
		return "", fromStatus("target current", err)
	}
	return resp.GetSerial(), nil
}

func (c *targetGRPCClient) Stage(ctx context.Context, req StageRequest) (string, error) {
	resp, err := c.client.Stage(ctx, &pb.StageRequest{
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

func (c *targetGRPCClient) Activate(ctx context.Context, config json.RawMessage, stagedRef string) (string, error) {
	resp, err := c.client.Activate(ctx, &pb.ActivateRequest{ConfigJson: config, StagedRef: stagedRef})
	if err != nil {
		return "", fromStatus("target activate", err)
	}
	return resp.GetPreviousRef(), nil
}

func (c *targetGRPCClient) Rollback(ctx context.Context, config json.RawMessage, previousRef string) error {
	_, err := c.client.Rollback(ctx, &pb.RollbackRequest{ConfigJson: config, PreviousRef: previousRef})
	return fromStatus("target rollback", err)
}
