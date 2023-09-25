package stream2

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"

	imageScanJob "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/scanjob"
	regSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/sync"
	imagesecStream "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/stream"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
)

const (
	serviceName = "scanner-rpc-stream"
)

type RpcStream struct {
	Stream *imagesecStream.RpcStream
}

func (s *RpcStream) Start(ctx context.Context) error {

	if err := s.Stream.Start(ctx); err != nil {
		logging.Get().Err(err).Msg("RpcStream scanner start fail")
		return err
	}
	logging.Get().Info().Msg("RpcStream scanner start success")

	return nil
}

func (s *RpcStream) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.Get().Err(err).Str("serviceName", serviceName).Msg("failed to register service")
		return
	}
	logging.Get().Err(err).Str("serviceName", serviceName).Msg("succeed to register service")
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	mqWriter, err := mq.GetClientFactory().Writer(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("failed to create mq reader")
		return nil, err
	}

	rdb := store.GetRDBInstance()
	cli, err := store.GetRedisClient(1)
	if err != nil {
		return nil, err
	}

	registryDal := imagesecStore.NewRegistryDao(rdb)
	scanInstanceDal := imagesecStore.NewScannerInstanceDao(rdb)
	syncTaskDal := imagesecStore.NewSyncTaskDao(rdb)
	policyDal := imagesecStore.NewDetectPolicyDao(rdb)
	scanConfigDal := imagesecStore.NewScanImageConfigDao(rdb)
	syncSrv := sync.NewRegSyncSrv(mqWriter, registryDal, syncTaskDal, scanInstanceDal)

	registrySrv := regSrv.NewRegistrySrv(registryDal, syncTaskDal, scanInstanceDal, policyDal, scanConfigDal)

	libImageScanner, err := imageScanJob.NewRegistryImageScan(mqWriter, *cli)
	if err != nil {
		return nil, err
	}
	handler := imagesecStream.NewHandler(libImageScanner, syncSrv, registrySrv)

	sr := imagesecStream.NewRpcStream(handler)

	n := &RpcStream{
		Stream: sr,
	}

	return n, nil
}
