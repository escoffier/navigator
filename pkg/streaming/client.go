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
	UpdateVulnDB(ctx context.Context, nodeKey string, vulnReq *pb.ImageSecReq) (*pb.ImageSecResp, error)
	DeliverImageSecMsg(ctx context.Context, nodeKey string, imageSecReq *pb.ImageSecReq) (*pb.ImageSecResp, error)

	PublishImageSecMsgByClusterKey(ctx context.Context, clusterKey string, imageSecReq *pb.ImageSecReq) (*pb.ImageSecResp, error)

	PublishImageSecMsgByNode(ctx context.Context, nodeKey string, msgType pb.MessageType, imageSecReq *pb.ImageSecReq) (*pb.ImageSecResp, error)

	PublishImageSecMsgToScanner(ctx context.Context, scannerKey string, imageSecReq *pb.ImageSecReq) (*pb.ImageSecResp, error)

	// ScannerPushImageSecMsg scanner push msg to console
	ScannerPushImageSecMsg(ctx context.Context, imageSecReq *pb.ImageSecReq) (*pb.ImageSecResp, error)
}

func (s *messageStream) UpdateVulnDB(ctx context.Context, nodeKey string, vulnReq *pb.ImageSecReq) (*pb.ImageSecResp, error) {
	logging.Get().Info().Msgf("stream push DB nodekey:%v", nodeKey)
	resp, err := s.Request(ctx, nodeKey, pb.MessageType_UPDATE, vulnReq, true)
	if err != nil {
		logging.Get().Err(err).Msg("request err")
		return nil, err
	}
	if resp != nil {
		r, ok := resp.(*pb.ImageSecResp)
		if !ok {
			return nil, fmt.Errorf("invalid message type: %s", resp.ProtoReflect().Descriptor().FullName())
		}
		logging.Get().Info().Msgf("response: %s", r.String())
		return r, nil
	}
	return nil, nil
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
	if r.Status == 1 {
		return r, fmt.Errorf("%s", r.StatusMessage)
	}
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
	if r.Status == 1 {
		return fmt.Errorf("%s", r.StatusMessage)
	}
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

func (s *messageStream) DeliverImageSecMsg(ctx context.Context, nodeKey string, imageSecReq *pb.ImageSecReq) (*pb.ImageSecResp, error) {
	resp, err := s.Request(ctx, nodeKey, pb.MessageType_CREATE, imageSecReq, true)

	if err != nil {
		logging.Get().Err(err).Msg("request err")
		return nil, err
	}
	r, ok := resp.(*pb.ImageSecResp)
	if !ok {
		return nil, fmt.Errorf("invalid message type: %s", resp.ProtoReflect().Descriptor().FullName())
	}
	logging.Get().Info().Msgf("response: %s", r.String())
	return r, nil
}

// PublishImageSecMsgByClusterKey cluster manager of master cluster forward msg to slave cluster
func (s *messageStream) PublishImageSecMsgByClusterKey(ctx context.Context, clusterKey string, imageSecReq *pb.ImageSecReq) (*pb.ImageSecResp, error) {
	resp, err := s.Request(ctx, clusterKey, pb.MessageType_CREATE, imageSecReq, true)
	if err != nil {
		logging.Get().Err(err).Msg("request err")
		return nil, err
	}
	r, ok := resp.(*pb.ImageSecResp)
	if !ok {
		return nil, fmt.Errorf("invalid message type: %s", resp.ProtoReflect().Descriptor().FullName())
	}
	logging.Get().Info().Msgf("response: %s", r.String())
	return r, nil
}
func (s *messageStream) PublishImageSecMsgByNode(ctx context.Context, nodeKey string, msgType pb.MessageType, imageSecReq *pb.ImageSecReq) (*pb.ImageSecResp, error) {
	resp, err := s.Request(ctx, nodeKey, msgType, imageSecReq, true)
	if err != nil {
		logging.Get().Err(err).Msg("request err")
		return nil, err
	}
	r, ok := resp.(*pb.ImageSecResp)
	if !ok {
		return nil, fmt.Errorf("invalid message type: %s", resp.ProtoReflect().Descriptor().FullName())
	}
	logging.Get().Info().Msgf("response: %s", r.String())
	return r, nil
}

func (s *messageStream) PublishImageSecMsgToScanner(ctx context.Context, scannerKey string, imageSecReq *pb.ImageSecReq) (*pb.ImageSecResp, error) {
	resp, err := s.Request(ctx, scannerKey, pb.MessageType_CREATE, imageSecReq, true)
	if err != nil {
		logging.Get().Err(err).Msg("request err")
		return nil, err
	}
	r, ok := resp.(*pb.ImageSecResp)
	if !ok {
		return nil, fmt.Errorf("invalid message type: %s", resp.ProtoReflect().Descriptor().FullName())
	}
	logging.Get().Info().Msgf("response: %s", r.String())
	return r, nil
}
func (s *messageStream) ScannerPushImageSecMsg(ctx context.Context, imageSecReq *pb.ImageSecReq) (*pb.ImageSecResp, error) {
	// used for scanner as grpc client.
	// client only contain one stream with name defaultNodeKey
	resp, err := s.Request(ctx, defaultNodeKey, pb.MessageType_CREATE, imageSecReq, true)
	if err != nil {
		logging.Get().Err(err).Msg("failed to publish image sec msg")
		return nil, err
	}
	r, ok := resp.(*pb.ImageSecResp)
	if !ok {
		logging.Get().Error().Msg("recv invalid rsp msg")
		return nil, err
	}
	logging.Get().Debug().Str("rsp", r.String()).Msg("recv image sec rsp end")

	return r, nil
}
