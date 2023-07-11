package imagescan

import (
	"context"
	"os"

	"gitlab.com/security-rd/go-pkg/logging"

	imagemataSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	dispatcherSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"

	// "gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register/stream"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
)

const (
	serviceName = "task-dispatcher"
)

type Dispatcher struct {
	DispatcherSrv dispatcherSrv.TaskDispatcherService
}

func (s *Dispatcher) Start(ctx context.Context) error {

	if os.Getenv("IS_MAIN_CLUSTER") != consts.TrueString {
		logging.Get().Info().Msg("Dispatcher not in main cluster ")
		return nil
	}

	logging.Get().Info().Msg("Dispatcher in main cluster")

	if err := s.DispatcherSrv.PublishSubtask(ctx); err != nil {
		logging.Get().Err(err).Str("serviceName", serviceName).Msg("Start")
		return err
	}

	logging.Get().Info().Str("serviceName", serviceName).Msg("Started")
	return nil
}

func (s *Dispatcher) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.Get().Err(err).Str("serviceName", serviceName).Msg("failed to register service")
	}
	logging.Get().Err(err).Str("serviceName", serviceName).Msg("register service succeed")
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {

	scannerWrapperDb := store.GetScannerWrapperDb()
	registryDal := store.NewRegistryDao(scannerWrapperDb)
	nodeImageDal := imagesecStore.NewImageMetaDao(scannerWrapperDb, nil)
	nodeReportDal := imagesecStore.NewNodeReportDao(scannerWrapperDb)
	policyDal := imagesecStore.NewDetectPolicyDao(scannerWrapperDb)
	nodeScanResultDal := imagesecStore.NewScanResultDao(scannerWrapperDb)
	scannerConfigDal := imagesecStore.NewScannerConfigDao(scannerWrapperDb)
	resourceDal := store.NewResourceDao(scannerWrapperDb)
	trustedImageDal := store.NewScannerOrm(scannerWrapperDb)
	detectResultDal := imagesecStore.NewImageDetectResultDao(scannerWrapperDb)
	sensitiveRuleDal := imagesecStore.NewSensitiveRuleDao(scannerWrapperDb)

	nodeScanTaskDal := imagesecStore.NewScanTaskDao(scannerWrapperDb)
	nodeImageSvc := imagemataSrv.NewNodeImageSrv(nodeImageDal, registryDal, nodeScanResultDal,
		resourceDal, nodeReportDal, policyDal, detectResultDal, trustedImageDal, scannerConfigDal, nodeScanTaskDal)

	imageTaskDispatcher := dispatcherSrv.NewImageScanTaskDispatcher(nodeScanTaskDal, nodeImageSvc, nodeReportDal, sensitiveRuleDal)

	d := Dispatcher{DispatcherSrv: imageTaskDispatcher}

	return &d, nil
}
