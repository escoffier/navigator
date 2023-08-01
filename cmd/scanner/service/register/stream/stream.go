package stream

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	"gitlab.com/piccolo_su/vegeta/pkg/util"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

const (
	serviceName = "scanner-grpc-handler"
)

var (
	consoleStreamInstance        *GrpcStream // grpc stream to console
	clusterManagerStreamInstance *GrpcStream // grpc stream to cluster manager,not available for outside caller
	once                         sync.Once
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
	if !consoleStreamInstance.connected {
		return nil, fmt.Errorf("client stream not connected")
	}
	return consoleStreamInstance.clientStream, nil
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

func (g *GrpcStreamWrapper) connectToConsole() error {
	isHostCluster := os.Getenv("IS_MAIN_CLUSTER")
	if isHostCluster == "true" {
		// connect to console in main cluster
		consoleStreamInstance.grpcServerAddr = os.Getenv("CONSOLE_INTERNAL_GRPC_ADDR")
	} else {
		// not connect to console when in slave cluster
		logging.Get().Info().Msg("scanner not connect to console grpc when in slave cluster")
		return nil
	}

	streamKey := util.ScannerConsoleGrpcStreamKey()
	logging.Get().Info().
		Str("grpcServerAddr", consoleStreamInstance.grpcServerAddr).
		Str("clusterKey", streamKey).
		Msg("console grpc server")

	fac := rpcstream.NewStreamFactory(rpcstream.WithClusterKey(streamKey))

	consoleStreamInstance.clientStream = fac.Client(consoleStreamInstance.grpcServerAddr)
	_ = consoleStreamInstance.clientStream.AddHandler(&pb.ImageSecReq{}, &GrpcHandler{DB: store.GetRDBInstance()})

	stopChan := make(chan struct{}, 1)
	wait.Until(func() {
		logging.Get().Debug().Msg("scanner grpc client try connecting to console")

		err := consoleStreamInstance.clientStream.Start()
		if err != nil {
			logging.Get().Warn().Str("errMsg", err.Error()).Msg("failed to connect console grpc server,will try again")
		} else {
			logging.Get().Info().Msg("scanner grpc client connect console ok")
			consoleStreamInstance.connected = true
			stopChan <- struct{}{}
		}
	}, 3*time.Second, stopChan)

	logging.Get().Info().Msg("scanner grpc client connect console end")
	return nil
}

// connectToClusterManager scanner connect to cluster manager in master and slave cluster
func (g *GrpcStreamWrapper) connectToClusterManager() error {
	clusterManagerStreamInstance.grpcServerAddr = os.Getenv("CLUSTER_MANAGER_GRPC_ADDR")

	streamKey := util.ScannerClusterManagerGrpcStreamKey(global.ClusterKey)
	logging.Get().Info().
		Str("grpcServerAddr", clusterManagerStreamInstance.grpcServerAddr).
		Str("clusterKey", streamKey).
		Msg("cluster manager grpc server")

	fac := rpcstream.NewStreamFactory(rpcstream.WithClusterKey(streamKey))

	clusterManagerStreamInstance.clientStream = fac.Client(clusterManagerStreamInstance.grpcServerAddr)
	_ = clusterManagerStreamInstance.clientStream.AddHandler(&pb.ImageSecReq{}, &GrpcHandler{})

	stopChan := make(chan struct{}, 1)
	wait.Until(func() {
		err := clusterManagerStreamInstance.clientStream.Start()
		if err == nil {
			logging.Get().Info().Msg("scanner grpc client connect cluster manager ok")
			clusterManagerStreamInstance.connected = true
			stopChan <- struct{}{}
			return
		}
		logging.Get().Warn().Str("errMsg", err.Error()).Msg("failed to connect cluster manager grpc server,will try again")
	}, 3*time.Second, stopChan)

	logging.Get().Info().Msg("scanner grpc client connect cluster manager end")
	return nil
}

func (g *GrpcStreamWrapper) Start(ctx context.Context) error {

	stopChan := make(chan struct{})

	// connect to console grpc server
	_ = g.connectToConsole()

	// connect to cluster manager grpc server
	_ = g.connectToClusterManager()

	<-stopChan
	return nil
}

func (g *GrpcStreamWrapper) Stop(ctx context.Context) error {
	return nil
}

func init() {
	once.Do(func() {
		consoleStreamInstance = &GrpcStream{
			connected: false,
		}
		clusterManagerStreamInstance = &GrpcStream{
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
