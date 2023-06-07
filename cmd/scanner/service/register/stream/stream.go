package stream

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/security-rd/go-pkg/logging"
)

const (
	serviceName   = "scanner-grpc-handler"
	GrpcStreamKey = "scanner-grpc"
	GrpcFmt       = "%s@%s"
)

var (
	streamInstance *GrpcStream
	once           sync.Once
)

type GrpcStream struct {
	connected      bool // true: connect to grpc server ok
	grpcServerAddr string
	clientStream   rpcstream.MessageStream
}

type GrpcStreamWrapper struct {
}

// GetGrpcClient used for task dispatcher to publish image tasks. e.g. GetGrpcClient().DeliverImageSecMsg(...)
func GetGrpcClient() (rpcstream.MessageStream, error) {
	if !streamInstance.connected {
		return nil, fmt.Errorf("client stream not connected")
	}
	return streamInstance.clientStream, nil
}

// MustGetGrpcClient wait grpc connected ok,then return.Maybe cost a lot of time
func MustGetGrpcClient() rpcstream.MessageStream {
	for {
		s, err := GetGrpcClient()
		if err != nil {
			logging.Get().Warn().Msg("grpc client not connect,wait and try")
			time.Sleep(2 * time.Second)
			continue
		}
		return s
	}
}

func (g *GrpcStreamWrapper) PreStart() error {
	isHostCluster := os.Getenv("IS_MAIN_CLUSTER")
	if isHostCluster == "true" {
		// connect to console in main cluster
		streamInstance.grpcServerAddr = os.Getenv("CONSOLE_INTERNAL_GRPC_ADDR")
	} else {
		// connect to cluster manager in slave cluster
		streamInstance.grpcServerAddr = os.Getenv("CLUSTER_MANAGER_GRPC_ADDR")
	}
	return nil
}

func (g *GrpcStreamWrapper) Start(ctx context.Context) error {
	_ = g.PreStart()
	logging.Get().Info().
		Str("grpcServerAddr", streamInstance.grpcServerAddr).
		Str("clusterKey", fmt.Sprintf(GrpcFmt, global.ClusterKey, GrpcStreamKey)).
		Msg("grpc server")

	fac := rpcstream.NewStreamFactory(
		rpcstream.WithClusterKey(fmt.Sprintf(GrpcFmt, global.ClusterKey, GrpcStreamKey)))

	streamInstance.clientStream = fac.Client(streamInstance.grpcServerAddr)
	_ = streamInstance.clientStream.AddHandler(&pb.ImageSecReq{}, &GrpcHandler{DB: store.GetScannerWrapperDb()})

	for {
		// try until succeed
		err := streamInstance.clientStream.Start()
		if err == nil {
			streamInstance.connected = true
			break
		}
		logging.Get().Warn().Str("errMsg", err.Error()).Msg("failed to connect grpc server,will try again")
		time.Sleep(5 * time.Second)
	}
	logging.Get().Info().Msg("scanner grpc client connect ok")
	return nil
}

func (g *GrpcStreamWrapper) Stop(ctx context.Context) error {
	return nil
}

func init() {
	once.Do(func() {
		streamInstance = &GrpcStream{
			connected: false,
		}
	})
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.Get().Err(err).Str("serviceName", serviceName).Msg("register service err")
		return
	}
	logging.Get().Info().Str("serviceName", serviceName).Msg("register service")
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	g := &GrpcStreamWrapper{}

	return g, nil
}
