package imagescan

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"

	imagemataSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	dispatcherSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/dispatch"
	aviraengin "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/avira"
	clamavengin "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/clamav2"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/managedb/mainscanner"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/managedb/subscanner"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/types"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
)

const (
	serviceName = "imagescan"
)

type Dispatcher struct {
	DispatcherSrv    dispatcherSrv.TaskDispatcherService
	NewDispatchDBSrv types.DispatchDBService
	RPCReceiver      types.RPCReceiver
}

func (s *Dispatcher) Start(ctx context.Context) error {

	// _ = s.NewDispatchDBSrv.SendToSubScanner(ctx)
	// _ = s.NewDispatchDBSrv.SendToNode(ctx)
	// _ = s.RPCReceiver.ReceiveFromRPC(ctx)

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

	rdbInstance := store.GetRDBInstance()
	registryDal := imagesecStore.NewRegistryDao(rdbInstance)
	nodeImageDal := imagesecStore.NewImageMetaDao(rdbInstance, nil)
	nodeReportDal := imagesecStore.NewNodeReportDao(rdbInstance)
	policyDal := imagesecStore.NewDetectPolicyDao(rdbInstance)
	nodeScanResultDal := imagesecStore.NewScanResultDao(rdbInstance)
	scannerConfigDal := imagesecStore.NewScanImageConfigDao(rdbInstance)
	resourceDal := imagesecStore.NewResourceDao(rdbInstance)
	trustedImageDal := store.NewScannerOrm(rdbInstance)
	detectResultDal := imagesecStore.NewImageDetectResultDao(rdbInstance)
	sensitiveRuleDal := imagesecStore.NewSensitiveRuleDao(rdbInstance)
	scannerInstanceDal := imagesecStore.NewScannerInstanceDao(rdbInstance)
	deployDal := imagesecStore.NewDeployDao(rdbInstance)
	nodeScanTaskDal := imagesecStore.NewScanTaskDao(rdbInstance)
	cacheDal := imagesecStore.NewImageCacheDao(rdbInstance)

	imageSvc := imagemataSrv.NewImageMetaSrv(nodeImageDal, registryDal, nodeScanResultDal,
		resourceDal, nodeReportDal, policyDal, detectResultDal, trustedImageDal, scannerConfigDal,
		nodeScanTaskDal, scannerInstanceDal, deployDal, cacheDal)

	imageTaskDispatcher := dispatcherSrv.NewImageScanTaskDispatcher(nodeScanTaskDal, imageSvc,
		nodeReportDal, scannerInstanceDal, sensitiveRuleDal, scannerConfigDal)
	aviraUpdateSrv := aviraengin.NewAviraUpdateSrv()
	clamavUpdateSrv := clamavengin.NewClamavUpdateSrv()
	scanDbMetaDal := imagesecStore.NewScanDbMetaDao(rdbInstance)
	nodeInfoDal := imagesecStore.NewNodeReportDao(rdbInstance)
	scanInstanceDal := imagesecStore.NewScannerInstanceDao(rdbInstance)

	d := Dispatcher{
		DispatcherSrv:    imageTaskDispatcher,
		NewDispatchDBSrv: mainscanner.NewDispatchDBSrv(scanDbMetaDal, nodeInfoDal, scanInstanceDal),
		RPCReceiver:      subscanner.NewSubScanner(aviraUpdateSrv, clamavUpdateSrv),
	}

	return &d, nil
}
