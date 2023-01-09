package rpcstream

import (
	"context"
	"fmt"

	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/security-rd/go-pkg/logging"
)

type MessageStreamClient interface {
	CreateHoneySpot(ctx context.Context, nodeKey string, honeySpot *pb.HoneySpotReq) (*pb.HoneySpotResp, error)
	DeleteHoneySpot(ctx context.Context, nodeKey, namespace, name string) error
	PublishHoneySpot(ctx context.Context, nodeKeys []string, msgType pb.MessageType, honeySpot *pb.HoneySpotReq) error
	CreateCluster(ctx context.Context, nodeKey string, honeySpot *pb.ClusterRegister) (*pb.CommonReponse, error)
}

func (s *messageStream) CreateHoneySpot(ctx context.Context, nodeKey string, honeySpot *pb.HoneySpotReq) (*pb.HoneySpotResp, error) {
	resp, err := s.Request(ctx, nodeKey, pb.MessageType_CREATE, honeySpot, true)

	if err != nil {
		logging.Get().Err(err).Msg("request err")
		return nil, err
	}
	r, ok := resp.(*pb.HoneySpotResp)
	if !ok {
		return nil, fmt.Errorf("invalid message type: %s", resp.ProtoReflect().Descriptor().FullName())
	}
	logging.Get().Info().Msgf("response: %s", r.String())
	return r, nil
}

// PublishHoneySpot publish message to all nodes
func (s *messageStream) PublishHoneySpot(ctx context.Context, nodeKeys []string, msgType pb.MessageType, honeySpot *pb.HoneySpotReq) error {
	err := s.Publish(ctx, nodeKeys, msgType, honeySpot, false)
	if err != nil {
		return err
	}
	return nil
}

func (s *messageStream) DeleteHoneySpot(ctx context.Context, nodeKey, namespace, name string) error {
	resp, err := s.Request(ctx, nodeKey, pb.MessageType_DELETE, &pb.HoneySpotReq{
		Namespace: namespace,
		Name:      name,
	}, true)

	if err != nil {
		logging.Get().Err(err).Msg("request err")
		return err
	}
	r, ok := resp.(*pb.HoneySpotResp)
	if !ok {
		return fmt.Errorf("invalid message type: %s", resp.ProtoReflect().Descriptor().FullName())
	}
	logging.Get().Info().Msgf("response: %s", r.String())
	return nil
}

func (s *messageStream) CreateCluster(ctx context.Context, nodeKey string, cluster *pb.ClusterRegister) (*pb.CommonReponse, error) {
	resp, err := s.Request(ctx, nodeKey, pb.MessageType_CREATE, cluster, true)

	if err != nil {
		logging.Get().Err(err).Msg("request err")
		return nil, err
	}
	r, ok := resp.(*pb.CommonReponse)
	if !ok {
		return nil, fmt.Errorf("invalid message type: %s", resp.ProtoReflect().Descriptor().FullName())
	}
	logging.Get().Info().Msgf("response: %s", r.String())
	return r, nil
}
