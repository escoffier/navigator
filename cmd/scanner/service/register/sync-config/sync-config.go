package syncConfig

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"gitlab.com/security-rd/go-pkg/logging"

	imagesecStream "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/stream"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

const (
	serviceName        = "sync-config"
	syncInterval       = 30
	defaultGrpcTimeout = 60
)

type Syncer struct {
	streamClient rpcstream.MessageStream
}

func (s *Syncer) Start(_ context.Context) error {
	isHostCluster := os.Getenv("IS_MAIN_CLUSTER")
	if isHostCluster != "true" {
		logging.Get().Info().Msg("test publish msg not  started in slave cluster")
		return nil
	}

	logging.Get().Info().Msg("test publish msg started")

	// get grpc client
	s.streamClient = imagesecStream.MustGetGrpcStream()
	logging.Get().Debug().Msg("get grpc client ok")

	for {
		time.Sleep(syncInterval * time.Second)
		//
		// // mock config
		// mockConfig := imagesec.NodeImageConfig{
		// 	DeepScan:     true,
		// 	SyncInterval: 300,
		// 	ScanTimeout:  300,
		// }
		// clusterKey := "076f5418-9d9b-4708-a268-9b21ba32724e"
		clusterKey := "f815c6f8-8264-46a0-a273-c039de27492d" // local cluster02
		// dstNodes := make([]string, 0)
		// dstNodes = append(dstNodes, "cluster01-node01-192.168.3.11-centos")

		data, err := json.Marshal(nil)
		if err != nil {
			logging.Get().Err(err).Msg("failed to marshal task")
			return err
		}
		reqId := uuid.New().String()
		req := &pb.ImageSecReq{
			ImageSecReqType: pb.ImageSecReqType_RegistryHealthyCheck,
			ClusterKey:      clusterKey,
			MsgID:           reqId,
			// NodeName:        dstNodes,
			Payload: data,
		}
		publishFunc := func() error {
			logging.Get().Info().Str("msgID", reqId).Msg("ready to publish health check msg")

			ctx, cancel := context.WithTimeout(context.Background(), defaultGrpcTimeout*time.Second)
			defer cancel()
			rsp, err := s.streamClient.ScannerPushImageSecMsg(ctx, req)
			if err != nil {
				logging.Get().Err(err).Str("msgID", reqId).Msg("failed to publish health check by grpc stream")
				return err
			}
			if rsp.Status != 0 {
				err = fmt.Errorf("publish health check response err code:%v", rsp.Status)
				logging.Get().Err(err).Int32("rspStatus", rsp.Status).Str("msgID", reqId).Msg("failed to publish health check msg,rsp err code")
				return err
			}
			logging.Get().Info().Str("msgID", reqId).Msg("publish health check msg ok")
			return nil
		}
		_ = publishFunc()

		logging.Get().Info().Msg("publish health check msg end")
	}

}

func (s *Syncer) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.Get().Err(err).Str("serviceName", serviceName).Msg("failed to register service")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	d := &Syncer{}
	return d, nil
}
