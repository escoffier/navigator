package subscanner

import (
	"context"
	"fmt"
	"os"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"
	"k8s.io/apimachinery/pkg/util/wait"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	rpcstream "gitlab.com/piccolo_su/vegeta/pkg/streaming"
	"gitlab.com/piccolo_su/vegeta/pkg/streaming/pb"
)

type DBUpdateSrv struct {
	AviraUpdate  types.UpdateDEngin
	ClamavUpdate types.UpdateDEngin
}

func NewDBUpdateSrv(
	aviraUpdateSrv types.UpdateDEngin,
	clamavUpdateSrv types.UpdateDEngin,
) *DBUpdateSrv {
	srv := &DBUpdateSrv{
		AviraUpdate:  aviraUpdateSrv,
		ClamavUpdate: clamavUpdateSrv,
	}
	return srv
}

type SubScanner struct {
	AviraUpdate  types.UpdateDEngin
	ClamavUpdate types.UpdateDEngin
}

func NewSubScanner(
	aviraUpdateSrv types.UpdateDEngin,
	clamavUpdateSrv types.UpdateDEngin) *SubScanner {
	srv := &SubScanner{
		AviraUpdate:  aviraUpdateSrv,
		ClamavUpdate: clamavUpdateSrv,
	}
	return srv
}

func (s *DBUpdateSrv) UpdateDB(ctx context.Context, param imagesecModel.UpdateDbParam) error {
	logging.Get().Info().Str("module", "imagescan").Str("dbType", param.DbType).Msg("sub scanner start update db")

	var err error

	if param.DbType == consts.AviraName {
		_, err = s.AviraUpdate.UpdateDB(ctx, param)
	}

	if param.DbType == consts.ClamavName {
		_, err = s.ClamavUpdate.UpdateDB(ctx, param)
	}

	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Str("dbType", param.DbType).Msg("update db")
		return err
	}

	logging.Get().Info().Str("module", "imagescan").Str("dbType", param.DbType).Msg("sub scanner update db ok")
	return nil
}

func (s *SubScanner) ReceiveFromRPC(ctx context.Context) error {
	if os.Getenv("IS_MAIN_CLUSTER") == consts.TrueString {
		logging.Get().Info().Str("module", "imagescan").Msg("in main cluster do not receive db")
		return nil
	}
	// connect to grpc server
	clusterGrpcAddr := os.Getenv("CLUSTER_MANAGER_GRPC_ADDR")
	if clusterGrpcAddr == "" {
		logging.Get().Error().Msg("failed to get env CLUSTER_MANAGER_GRPC_ADDR value")
		return fmt.Errorf("failed to get cluster grpc address failed")
	}

	logging.Get().Debug().Str("module", "imagescan").Str("grpcServer", clusterGrpcAddr).Msg("get grpc server addr")

	rpcStream := rpcstream.NewStreamFactory().Client(clusterGrpcAddr)

	err := rpcStream.AddHandler(&pb.ImageSecReq{}, NewSubScannerHandler(NewDBUpdateSrv(s.AviraUpdate, s.ClamavUpdate)))
	if err != nil {
		logging.Get().Err(err).Str("module", "imagescan").Msg("failed to add rpc stream handler")
		return err
	}

	go func() {
		// cluster manager's grpc server may delay,so we wait
		stopChan := make(chan struct{})
		wait.Until(func() {
			err := rpcStream.Start()
			if err != nil {
				logging.Get().Warn().Msgf("failed to connect grpc server, will try again.%v", err)
			} else {
				logging.Get().Info().Str("module", "imagescan").Msg("connect to grpc server ok")
				stopChan <- struct{}{}
			}
		}, 5*time.Second, stopChan)
	}()

	return nil
}
