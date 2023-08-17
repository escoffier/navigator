// Package stream 使用多集群通信框架接收下发的扫描任务，漏洞库数据等
package stream

import (
	"fmt"
	"os"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"k8s.io/apimachinery/pkg/util/wait"

	"gitlab.com/piccolo_su/vegeta/cmd/node-image/config"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services"
	"gitlab.com/piccolo_su/vegeta/cmd/node-image/services/helper"
	imagesec2 "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type RpcStream struct {
	broadcastServer *util.BroadcastServer
}

func init() {
	err := services.RegisterService(&RpcStream{})
	if err != nil {
		logging.Get().Err(err).Msg("failed to register rpc stream service")
	} else {
		logging.Get().Info().Msg("register rpc stream service ok")
	}
}

func (r *RpcStream) Type() consts.ServiceType {
	return consts.TypeServiceStream
}

func (r *RpcStream) PreRun(_ config.Config, _ imagesec2.NodeImageConfig, bs *util.BroadcastServer) error {
	r.broadcastServer = bs
	return nil
}

func (r *RpcStream) Run() error {
	// connect to grpc server
	clusterGrpcAddr := os.Getenv("CLUSTER_MANAGER_GRPC_ADDR")
	if clusterGrpcAddr == "" {
		logging.Get().Error().Msg("failed to get env CLUSTER_MANAGER_GRPC_ADDR value")
		return fmt.Errorf("failed to get cluster grpc address failed")
	}
	logging.Get().Debug().Str("grpcServer", clusterGrpcAddr).Msg("get grpc server addr")

	rpcStream := rpcstream.NewStreamFactory(rpcstream.WithClusterKey(GenerateCustomKey())).Client(clusterGrpcAddr)
	err := rpcStream.AddHandler(&pb.ImageSecReq{}, &Handler{
		taskQueue:       helper.TaskQueue,
		broadcastServer: r.broadcastServer,
	})
	if err != nil {
		logging.Get().Err(err).Msg("failed to add rpc stream handler")
		return err
	}

	// cluster manager's grpc server may delay,so we wait
	stopChan := make(chan struct{}, 1)
	wait.Until(func() {
		err := rpcStream.Start()
		if err != nil {
			logging.Get().Warn().Msgf("failed to connect grpc server, will try again.%v", err)
		} else {
			logging.Get().Info().Msg("connect to grpc server ok")
			stopChan <- struct{}{}
		}
	}, 5*time.Second, stopChan)

	return nil
}

func GenerateCustomKey() string {
	hostName := os.Getenv("MY_NODE_NAME")
	if hostName == "" {
		hostName = "Unknown"
	}
	return fmt.Sprintf("%s-node-image", hostName)
}
