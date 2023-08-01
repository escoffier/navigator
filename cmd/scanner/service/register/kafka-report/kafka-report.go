package nodereport

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/detect"
	imageMetaSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/dispatch"
	imagescanSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/service"
	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	imagesecReport "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/kafkaReport"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
)

const (
	serviceName = "imagesec-kafka-report"
)

type NodeImage struct {
	ImageReport        *imagesecReport.ImageReport
	ScanInstanceReport *imagesecReport.ScanInstanceReport
	FileUploadSrv      *imagesecReport.FileUploadSrv
	ScanTaskSrv        *imagescanSrv.ScanTaskSrv
	ImageUpdateSrv     *imageMetaSrv.ImageUpdateSrv
	scanResultService  *imagesecReport.ScanResultReportSrv
	detectTaskService  detect.ImageDetectTaskService
	syncConfigService  dispatch.ScanImageConfigSyncService
}

func (n *NodeImage) Start(ctx context.Context) error {
	// 所有集群都得上报 scanner instance 的信息
	if err := n.ScanInstanceReport.ReportScanInstance(ctx); err != nil {
		logging.Get().Err(err).Msg("ScanInstanceReport ReportScanInstance")
	}
	logging.Get().Info().Msg("ScanInstanceReport ReportScanInstance succeed")

	if !scannerUtils.MainCluster() {
		logging.Get().Info().Msg("NodeImage not in main cluster ")
		return nil
	}

	logging.Get().Info().Msg("NodeImage in  main cluster")

	if err := n.ImageReport.ReceiveReport(ctx); err != nil {
		logging.Get().Err(err).Msg("ImageReport.ReceiveReport")
	}
	logging.Get().Info().Msg("ImageReport.ReceiveReport succeed")

	if err := n.FileUploadSrv.ReceiveKafkaReport(ctx); err != nil {
		logging.Get().Err(err).Msg("FileUploadSrv.ReceiveReport")
	}
	logging.Get().Info().Msg("FileUploadSrv.ReceiveReport succeed")

	// 删除过期文件
	if err := n.FileUploadSrv.DeleteExpirationFile(ctx); err != nil {
		logging.Get().Err(err).Msg("FileUploadSrv.ReceiveReport")
	}
	logging.Get().Info().Msg("FileUploadSrv.ReceiveReport succeed")

	if err := n.ScanInstanceReport.ReceiveReport(ctx); err != nil {
		logging.Get().Err(err).Msg("scanResultService.ReceiveReport")
	}
	logging.Get().Info().Msg("scanResultService.ReceiveReport succeed")

	if err := n.scanResultService.ReceiveReport(ctx); err != nil {
		logging.Get().Err(err).Msg("scanResultService.ReceiveReport")
	}

	if err := n.ScanTaskSrv.CreateCycleScanTaskByConfig(ctx); err != nil {
		logging.Get().Err(err).Msg("ScanTaskSrv.CreateCycleScanTaskByConfig")
	}

	logging.Get().Info().Msg("ScanTaskSrv.CreateCycleScanTaskByConfig succeed")

	if err := n.ScanTaskSrv.ContinueUpdateTaskAndSubtask(ctx); err != nil {
		logging.Get().Err(err).Msg("ScanTaskSrv.ContinueUpdateScanTask")
	}

	logging.Get().Info().Msg("ScanTaskSrv.ContinueUpdateScanTask succeed")

	if err := n.ImageUpdateSrv.ContinueUpdate(ctx); err != nil {
		logging.Get().Err(err).Msg("ImageUpdateSrv.ContinueUpdate")
	}
	logging.Get().Info().Msg("ImageUpdateSrv.ContinueUpdate succeed")

	if err := n.syncConfigService.SyncConfig(ctx); err != nil {
		logging.Get().Err(err).Msg("failed to start config sync imagescanSrv")
	}

	return nil
}

func (n *NodeImage) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.Get().Err(err).Str("serviceName", serviceName).Msg("failed to register imagescanSrv")
		return
	}

	logging.Get().Info().Str("serviceName", serviceName).Msg("succeed to register imagescanSrv")
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {

	mqReader, err := mq.GetClientFactory().Reader(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("failed to create mq reader")
		return nil, err
	}

	mqWriter, err := mq.GetClientFactory().Writer(context.Background())
	if err != nil {
		logging.Get().Err(err).Msg("failed to create mq Writer")
		return nil, err
	}

	redisCli, err := store.GetRedisClient(consts.DefaultRedisDB)
	if err != nil {
		logging.Get().Err(err).Msg("failed get redis client")
		return nil, err
	}
	rdbInstance := store.GetRDBInstance()
	nodeReportDal := imagesecStore.NewNodeReportDao(rdbInstance)
	scanResultDal := imagesecStore.NewScanResultDao(rdbInstance)

	registryDal := imagesecStore.NewRegistryDao(rdbInstance)
	imageDal := imagesecStore.NewImageMetaDao(rdbInstance, redisCli)
	userDal := imagesecStore.NewUserDao(rdbInstance)
	policyDal := imagesecStore.NewDetectPolicyDao(rdbInstance)
	nodeScanTaskDal := imagesecStore.NewScanTaskDao(rdbInstance)
	preTaskDal := imagesecStore.NewScanTaskPreDao(rdbInstance)
	nodeDal := imagesecStore.NewNodeReportDao(rdbInstance)
	nodeScanResultDal := imagesecStore.NewScanResultDao(rdbInstance)
	scannerConfigDal := imagesecStore.NewScanImageConfigDao(rdbInstance)
	issueDal := imagesecStore.NewScanIssueDao(rdbInstance)
	resourceDal := imagesecStore.NewResourceDao(rdbInstance)
	trustedImageDal := store.NewScannerOrm(rdbInstance)
	detectResultDal := imagesecStore.NewImageDetectResultDao(rdbInstance)
	detectTaskDal := imagesecStore.NewDetectTaskDao(rdbInstance)
	configDal := imagesecStore.NewScanImageConfigDao(rdbInstance)
	scanInstanceDal := imagesecStore.NewScannerInstanceDao(rdbInstance)
	deployRecordDal := imagesecStore.NewDeployDao(rdbInstance)

	imageSvc := imageMetaSrv.NewImageMetaSrv(
		imageDal,
		registryDal,
		nodeScanResultDal,
		resourceDal,
		nodeReportDal,
		policyDal,
		detectResultDal,
		trustedImageDal,
		scannerConfigDal,
		nodeScanTaskDal,
		scanInstanceDal,
		deployRecordDal,
	)

	nodeUpdateImageSvc := imageMetaSrv.NewImageUpdateSrv(
		imageDal,
		registryDal,
		policyDal,
		detectResultDal,
		detectTaskDal,
		issueDal,
		trustedImageDal,
		scannerConfigDal,
		nodeScanTaskDal,
		nodeDal,
		scanResultDal,
	)

	versionDal := imagesecStore.NewScanDbMetaDao(rdbInstance)
	detectTaskSrv := detect.NewImageDetectTaskSrv(imageSvc, detectTaskDal, policyDal, detectResultDal)

	scanTaskSrv := imagescanSrv.NewScanTaskSrv(
		nodeScanTaskDal,
		preTaskDal,
		detectTaskDal,
		imageSvc,
		imageDal,
		scannerConfigDal,
		imageDal,
		userDal,
	)

	nodeImageReportSrv := imagesecReport.NewImageReport(imageDal, nodeReportDal, scanResultDal, mqReader, configDal, scanTaskSrv)
	scanInstanceReport := imagesecReport.NewScanInstanceReport(scanInstanceDal, mqReader, mqWriter)
	fileUploadSrv := imagesecReport.NewFileUploadSrv(mqReader)
	nodeInfoSrv := imagesecSrv.NewNodeReportSrv(nodeReportDal)

	scanResultSrv := imagesecReport.NewScanResultReportSrv(nodeScanTaskDal, imageDal, scanResultDal, issueDal,
		versionDal, detectTaskSrv, mqReader, redisCli)

	scanConfigSyncSrv := dispatch.NewScannerConfigSyncSrv(scannerConfigDal, nodeInfoSrv)

	n := &NodeImage{
		ImageReport:        nodeImageReportSrv,
		ScanInstanceReport: scanInstanceReport,
		FileUploadSrv:      fileUploadSrv,
		ScanTaskSrv:        scanTaskSrv,
		ImageUpdateSrv:     nodeUpdateImageSvc,
		scanResultService:  scanResultSrv,
		detectTaskService:  detectTaskSrv,
		syncConfigService:  scanConfigSyncSrv,
	}

	return n, nil
}
