package nodeimage

import (
	"context"
	"os"

	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/detect"
	imageMetaSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan"
	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	nodereport "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/node-report"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
)

const (
	serviceName = "node-image-asset"
)

type NodeImage struct {
	nodeImageReportService nodereport.ReceiveNodeReportService
	scanTaskService        imagescan.ScanTaskService
	nodeUpdateImageService imageMetaSrv.ImageUpdateService
	scanResultService      nodereport.ReceiveNodeReportService
	detectTaskService      detect.ImageDetectTaskService
	syncConfigService      imagescan.ScanImageConfigSyncService
}

func (n *NodeImage) Start(ctx context.Context) error {

	if os.Getenv("IS_MAIN_CLUSTER") != consts.TrueString {
		logging.Get().Info().Msg("NodeImage not in main cluster ")
		return nil
	}

	logging.Get().Info().Msg("NodeImage in  main cluster")

	if err := n.nodeImageReportService.ReceiveNodeReport(ctx); err != nil {
		logging.Get().Err(err).Msg("nodeImageReportService.ReceiveNodeReport")
	}
	logging.Get().Info().Msg("nodeImageReportService.ReceiveNodeReport succeed")

	if err := n.scanResultService.ReceiveNodeReport(ctx); err != nil {
		logging.Get().Err(err).Msg("scanResultService.ReceiveNodeReport")
	}

	if err := n.scanResultService.AddDetectTask(ctx); err != nil {
		logging.Get().Err(err).Msg("scanResultService.AddDetectTask")
	}

	logging.Get().Info().Msg("scanResultService.ReceiveNodeReport succeed")

	if err := n.scanTaskService.AddScanTaskByConfig(ctx); err != nil {
		logging.Get().Err(err).Msg("scanTaskService.AddScanTaskByConfig")
	}

	logging.Get().Info().Msg("scanTaskService.AddScanTaskByConfig succeed")

	if err := n.scanTaskService.ContinueUpdateTaskAndSubtask(ctx); err != nil {
		logging.Get().Err(err).Msg("scanTaskService.ContinueUpdateScanTask")
	}

	logging.Get().Info().Msg("scanTaskService.ContinueUpdateScanTask succeed")

	if err := n.nodeUpdateImageService.ContinueUpdateAndCleanImage(ctx); err != nil {
		logging.Get().Err(err).Msg("nodeUpdateImageService.ContinueUpdateAndCleanImage")
	}
	logging.Get().Info().Msg("nodeUpdateImageService.ContinueUpdateDeleteImage succeed")

	if err := n.syncConfigService.SyncConfig(ctx); err != nil {
		logging.Get().Err(err).Msg("failed to start config sync service")
	}

	return nil
}

func (n *NodeImage) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.Get().Err(err).Str("serviceName", serviceName).Msg("failed to register service")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {

	mqReader, err := mq.GetClientFactory().Reader(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("failed to create mq reader")
		return nil, err
	}
	redisCli, err := store.GetRedisClient(consts.DefaultRedisDB)
	if err != nil {
		logging.Get().Err(err).Msg("failed get redis client")
		return nil, err
	}
	scannerWrapperDb := store.GetScannerWrapperDb()
	libImageDal := store.NewScannerOrm(scannerWrapperDb)
	nodeReportDal := imagesecStore.NewNodeReportDao(scannerWrapperDb)
	scanResultDal := imagesecStore.NewScanResultDao(scannerWrapperDb)

	registryDal := store.NewRegistryDao(scannerWrapperDb)
	nodeImageDal := imagesecStore.NewImageMetaDao(scannerWrapperDb, redisCli)
	policyDal := imagesecStore.NewDetectPolicyDao(scannerWrapperDb)
	nodeScanTaskDal := imagesecStore.NewScanTaskDao(scannerWrapperDb)
	nodeScanResultDal := imagesecStore.NewScanResultDao(scannerWrapperDb)
	scannerConfigDal := imagesecStore.NewScannerConfigDao(scannerWrapperDb)
	issueDal := imagesecStore.NewScanIssueDao(scannerWrapperDb)
	resourceDal := store.NewResourceDao(scannerWrapperDb)
	trustedImageDal := store.NewScannerOrm(scannerWrapperDb)
	detectResultDal := imagesecStore.NewImageDetectResultDao(scannerWrapperDb)
	configDal := imagesecStore.NewScannerConfigDao(scannerWrapperDb)

	nodeImageSvc := imageMetaSrv.NewNodeImageSrv(nodeImageDal, registryDal, nodeScanResultDal,
		resourceDal, nodeReportDal, policyDal, detectResultDal, trustedImageDal, scannerConfigDal, nodeScanTaskDal)

	nodeUpdateImageSvc := imageMetaSrv.NewImageUpdateSrv(nodeImageDal, registryDal, policyDal,
		detectResultDal, trustedImageDal, scannerConfigDal, nodeScanTaskDal, libImageDal)

	detectTaskDal := imagesecStore.NewDetectTaskDao(scannerWrapperDb)
	versionDal := imagesecStore.NewScanVersionDao(scannerWrapperDb)
	detectTaskSrv := detect.NewImageDetectTaskSrv(nodeImageSvc, detectTaskDal, policyDal)

	scanTaskSrv := imagescan.NewScanTaskSrv(nodeScanTaskDal, nodeImageSvc, scannerConfigDal)

	nodeImageReportSrv := nodereport.NewNodeImageReport(nodeImageDal, nodeReportDal, scanResultDal, mqReader, configDal, scanTaskSrv)
	nodeInfoSrv := imagesecSrv.NewNodeReportSrv(nodeReportDal)

	scanResultSrv := nodereport.NewScanResultReportSrv(nodeScanTaskDal, nodeImageDal, scanResultDal, issueDal,
		versionDal, detectTaskSrv, mqReader)

	scanConfigSyncSrv := imagescan.NewScannerConfigSyncSrv(scannerConfigDal, nodeInfoSrv)

	n := &NodeImage{
		nodeImageReportService: nodeImageReportSrv,
		scanTaskService:        scanTaskSrv,
		nodeUpdateImageService: nodeUpdateImageSvc,
		scanResultService:      scanResultSrv,
		detectTaskService:      detectTaskSrv,
		syncConfigService:      scanConfigSyncSrv,
	}

	return n, nil
}
