package imagesecStream

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type RpcStream struct {
	Handler rpcstream.MessageHandler
	Log     *scannerUtils.LogEvent
}

func NewRpcStream(handler rpcstream.MessageHandler) *RpcStream {
	return &RpcStream{Handler: handler,
		Log: scannerUtils.NewLogEvent(
			scannerUtils.WithSubModule("Stream"),
			scannerUtils.WithModule(consts.ModuleRpcStream),
		),
	}
}

func MustGetGrpcStream() rpcstream.MessageStream {
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

var (
	consoleStreamInstance        *GrpcStream // grpc stream to console
	clusterManagerStreamInstance *GrpcStream // grpc stream to cluster manager,not available for outside caller
	once                         sync.Once
)

func init() {
	once.Do(func() {
		consoleStreamInstance = &GrpcStream{
			connected: false,
		}
		clusterManagerStreamInstance = &GrpcStream{
			connected: false,
		}
	})
}

type GrpcStream struct {
	connected      bool // true: connect to grpc server ok
	grpcServerAddr string
	clientStream   rpcstream.MessageStream
}

// GetGrpcClient used for task dispatcher to publish image tasks. e.g. GetGrpcClient().DeliverImageSecMsg(...)
func GetGrpcClient() (rpcstream.MessageStream, error) {
	if !consoleStreamInstance.connected {
		return nil, fmt.Errorf("client stream not connected")
	}
	return consoleStreamInstance.clientStream, nil
}

func (vi *RpcStream) connectToConsole() error {
	if scannerUtils.MainCluster() {
		// connect to console in main cluster
		consoleStreamInstance.grpcServerAddr = os.Getenv("CONSOLE_INTERNAL_GRPC_ADDR")
	} else {
		// not connect to console when in slave cluster
		vi.Log.Info().Msg("scanner not connect to console grpc when in slave cluster")
		return nil
	}

	streamKey := util.ScannerConsoleGrpcStreamKey()
	vi.Log.Info().
		Str("grpcServerAddr", consoleStreamInstance.grpcServerAddr).
		Str("clusterKey", streamKey).
		Msg("console grpc server")

	fac := rpcstream.NewStreamFactory(rpcstream.WithClusterKey(streamKey))

	consoleStreamInstance.clientStream = fac.Client(consoleStreamInstance.grpcServerAddr)
	_ = consoleStreamInstance.clientStream.AddHandler(&pb.ImageSecReq{}, vi.Handler)

	for {
		vi.Log.Debug().Msg("scanner grpc client try connecting to console")

		err := consoleStreamInstance.clientStream.Start()
		if err == nil {
			vi.Log.Info().Msg("scanner grpc client connect console ok")
			consoleStreamInstance.connected = true
			break
		}

		logging.Get().Warn().Str("errMsg", err.Error()).Msg("failed to connect console grpc server,will try again")
		time.Sleep(time.Second * 5)
	}

	vi.Log.Info().Msg("scanner grpc client connect console end")
	return nil
}

// connectToClusterManager scanner connect to cluster manager in master and slave cluster
func (vi *RpcStream) connectToClusterManager() error {
	clusterManagerStreamInstance.grpcServerAddr = os.Getenv("CLUSTER_MANAGER_GRPC_ADDR")

	streamKey := util.ScannerClusterManagerGrpcStreamKey(global.ClusterKey)

	vi.Log.Info().
		Str("grpcServerAddr", clusterManagerStreamInstance.grpcServerAddr).
		Str("clusterKey", streamKey).
		Msg("cluster manager grpc server")

	fac := rpcstream.NewStreamFactory(rpcstream.WithClusterKey(streamKey))

	clusterManagerStreamInstance.clientStream = fac.Client(clusterManagerStreamInstance.grpcServerAddr)
	_ = clusterManagerStreamInstance.clientStream.AddHandler(&pb.ImageSecReq{}, vi.Handler)

	for {
		err := clusterManagerStreamInstance.clientStream.Start()
		if err == nil {
			vi.Log.Info().Msg("scanner grpc client connect cluster manager ok")
			clusterManagerStreamInstance.connected = true
			break
		}
		time.Sleep(time.Second * 5)
		logging.Get().Warn().Str("errMsg", err.Error()).Msg("failed to connect cluster manager grpc server,will try again")
	}
	vi.Log.Info().Msg("scanner grpc client connect cluster manager end")
	return nil
}

func (vi *RpcStream) Start(ctx context.Context) error {
	// connect to console grpc server
	_ = vi.connectToConsole()

	// connect to cluster manager grpc server
	_ = vi.connectToClusterManager()

	return nil
}
