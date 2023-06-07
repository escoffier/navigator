// Package sync_vulndb for test
package sync_vulndb

import (
	"context"
	"fmt"
	"os"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/stream"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	serviceName        = "sync-vulndb"
	syncInterval       = 300
	defaultGrpcTimeout = 600
)

type Syncer struct {
	streamClient rpcstream.MessageStream
}

func (s *Syncer) Start(_ context.Context) error {
	logging.Get().Info().Msg("sync vulndb started")

	// get grpc client
	s.streamClient = stream.MustGetGrpcClient()
	logging.Get().Debug().Msg("get grpc client ok")

	for {
		time.Sleep(syncInterval * time.Second)

		// mock
		clusterKey := "494c5054-4b9b-4944-8452-84b8893c21b7"
		dstNodes := make([]string, 0)
		dstNodes = append(dstNodes, "cluster01-node01-192.168.3.11-centos")

		// read vulndb tar file
		data, err := os.ReadFile("/root/alldb/db.zip")
		if err != nil {
			logging.Get().Err(err).Msg("open vulndb tar err")
			continue
		}

		req := &pb.ImageSecReq{
			ImageSecReqType: pb.ImageSecReqType_TiDBUpdate,
			ClusterKey:      clusterKey,
			NodeName:        dstNodes,
			Payload:         data,
		}
		publishFunc := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), defaultGrpcTimeout*time.Second)
			defer cancel()
			rsp, err := s.streamClient.ScannerPushImageSecMsg(ctx, req)
			if err != nil {
				logging.Get().Err(err).Msg("failed to publish vulndb by grpc stream")
				return err
			}
			if rsp.Status != 0 {
				err = fmt.Errorf("publish config response err code:%v", rsp.Status)
				logging.Get().Err(err).Msg("failed to publish vulndb,rsp err code")
				return err
			}
			return nil
		}
		_ = publishFunc()

		logging.Get().Info().Msg("publish node image vulndb end")
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
