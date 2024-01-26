package registry

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"

	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse/support/aliacr"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse/support/aliacr-ee"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse/support/docker"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse/support/harborv1"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse/support/harborv2"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse/support/hw-swr"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse/support/hw-swr-en"
	_ "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/warehouse/support/jfrog"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store/adaptStore"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/dispatch"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/sync"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
)

const (
	serviceName = "image-registry-service"
)

type RegSyncTask struct {
	SyncSrv            sync.ImageSyncService
	SyncTaskDispatcher dispatch.SyncTaskDispatcher
}

func (s *RegSyncTask) Start(ctx context.Context) error {
	if !scannerUtils.MainCluster() {
		logging.Get().Info().Msg("RegSyncTask not in main cluster")
		return nil
	}
	_ = s.SyncSrv.CreateSyncTask(ctx)
	_ = s.SyncSrv.SyncImageMeta(ctx)
	logging.Get().Info().Str("serviceName", serviceName).Msg("start success AddSyncTask")
	_ = s.SyncTaskDispatcher.DispatchSyncTask(ctx)
	logging.Get().Info().Str("serviceName", serviceName).Msg("start success DispatchSyncTask")
	return nil
}

func (s *RegSyncTask) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.Get().Err(err).Str("serviceName", serviceName).Msg("int service err")
		return
	}
	logging.Get().Info().Str("serviceName", serviceName).Msg("register success")
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	rdbInstance := store.GetRDBInstance()
	mqWriter, err := mq.GetClientFactory().Writer(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("not get mqWriter")
		return nil, err
	}

	registryDal := imagesecStore.NewRegistryDao(rdbInstance)
	scanInstanceDal := imagesecStore.NewScannerInstanceDao(rdbInstance)
	syncTaskDal := imagesecStore.NewSyncTaskDao(rdbInstance)
	preImageDal := adaptStore.NewScannerOrm(rdbInstance)

	syncSrv := sync.NewRegSyncSrv(mqWriter, registryDal, syncTaskDal, scanInstanceDal, preImageDal)

	syncTaskDispatcher := dispatch.NewRegDispatchSrv(registryDal, syncTaskDal, scanInstanceDal)

	p := &RegSyncTask{SyncSrv: syncSrv, SyncTaskDispatcher: syncTaskDispatcher}

	return p, nil
}
