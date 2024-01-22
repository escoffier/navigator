package kafkaReport

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"
	"gitlab.com/security-rd/go-pkg/mq"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/detect"
	imageMetaSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/dispatch"
	scanTrivy "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/trivy"
	imagescanSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/service"
	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/kafkaReport/kafkaAsset"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/kafkaReport/kafkaFile"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/kafkaReport/kafkaScan"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/kafkaReport/scanIns"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store/adaptStore"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
)

const (
	serviceName = "imagesec-kafka-report"
)

type KafkaReport struct {
	ImageReport        *kafkaAsset.ImageReport
	ScanInstanceReport *scanIns.ScanInstanceReport
	FileUploadSrv      *kafkaFile.FileUploadSrv
	ScanTaskSrv        *imagescanSrv.ScanTaskSrv
	ImageUpdateSrv     *imageMetaSrv.ImageUpdateSrv
	scanResultService  *kafkaScan.ScanResultReportSrv
	detectTaskService  detect.ImageDetectTaskService
	syncConfigService  dispatch.ScanImageConfigSyncService
}

func (n *KafkaReport) Start(ctx context.Context) error {
	// 所有集群都得上报 scanner instance 的信息
	if err := n.ScanInstanceReport.ReportScanInstance(ctx); err != nil {
		logging.Get().Err(err).Msg("ScanInstanceReport ReportScanInstance")
	}
	logging.Get().Info().Msg("ScanInstanceReport ReportScanInstance succeed")

	if !scannerUtils.MainCluster() {
		logging.Get().Info().Msg("KafkaReport not in main cluster ")
		return nil
	}

	logging.Get().Info().Msg("KafkaReport in  main cluster")

	if err := n.ScanInstanceReport.ReceiveReport(ctx); err != nil {
		logging.Get().Err(err).Msg("ScanInstanceReport ReceiveReport")
	}
	logging.Get().Info().Msg("ScanInstanceReport ReceiveReport succeed")
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

func (n *KafkaReport) Stop(ctx context.Context) error {
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
	redisCli2, err := store.GetRedisClient(consts.TrivyRedisIndex)
	if err != nil {
		logging.Get().Err(err).Msg("failed get redis client")
		return nil, err
	}
	rdbInstance := store.GetRDBInstance()
	nodeReportDal := imagesecStore.NewNodeReportDao(rdbInstance)
	scanResultDal := imagesecStore.NewScanResultDao(rdbInstance)

	registryDal := imagesecStore.NewRegistryDao(rdbInstance)
	imageDal := imagesecStore.NewImageMetaDao(rdbInstance)
	userDal := imagesecStore.NewUserDao(rdbInstance)
	policyDal := imagesecStore.NewDetectPolicyDao(rdbInstance)
	nodeScanTaskDal := imagesecStore.NewScanTaskDao(rdbInstance)
	preTaskDal := imagesecStore.NewScanTaskPreDao(rdbInstance)
	nodeDal := imagesecStore.NewNodeReportDao(rdbInstance)
	nodeScanResultDal := imagesecStore.NewScanResultDao(rdbInstance)
	scannerConfigDal := imagesecStore.NewScanImageConfigDao(rdbInstance)
	issueDal := imagesecStore.NewScanIssueDao(rdbInstance)
	cacheDal := imagesecStore.NewImageCacheDao(rdbInstance)
	resourceDal := imagesecStore.NewResourceDao(rdbInstance)
	trustedImageDal := adaptStore.NewTrustedImageDao(rdbInstance)
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
		cacheDal,
	)
	versionDal := imagesecStore.NewScanDbMetaDao(rdbInstance)
	detectTaskSrv := detect.NewImageDetectTaskSrv(imageSvc, detectTaskDal, policyDal, detectResultDal)

	updateImageSvc := imageMetaSrv.NewImageUpdateSrv(
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
		detectTaskSrv,
		cacheDal,
	)

	scanTaskSrv := imagescanSrv.NewScanTaskSrv(
		nodeScanTaskDal,
		preTaskDal,
		detectTaskDal,
		imageSvc,
		imageDal,
		scannerConfigDal,
		imageDal,
		userDal,
		nodeDal,
	)

	imageReportSrv := kafkaAsset.NewImageReport(
		imageDal,
		nodeReportDal,
		scanResultDal,
		mqReader,
		configDal,
		scanTaskSrv,
		detectTaskSrv,
		registryDal,
	)

	scanInstanceReport := scanIns.NewScanInstanceReport(scanInstanceDal, mqReader, mqWriter)
	fileUploadSrv := kafkaFile.NewFileUploadSrv(mqReader, scanResultDal)
	nodeInfoSrv := imagesecSrv.NewNodeReportSrv(nodeReportDal)

	// init trivy
	trivySrv, err := scanTrivy.NewTrivySrv(scanTrivy.WithRedisCli(redisCli2))
	if err != nil {
		return nil, err
	}

	scanResultSrv := kafkaScan.NewScanResultReportSrv(nodeScanTaskDal, imageDal, scanResultDal, issueDal,
		versionDal, detectTaskSrv, trivySrv, mqReader, redisCli)

	scanConfigSyncSrv := dispatch.NewScannerConfigSyncSrv(scannerConfigDal, nodeInfoSrv)

	n := &KafkaReport{
		ImageReport:        imageReportSrv,
		ScanInstanceReport: scanInstanceReport,
		FileUploadSrv:      fileUploadSrv,
		ScanTaskSrv:        scanTaskSrv,
		ImageUpdateSrv:     updateImageSvc,
		scanResultService:  scanResultSrv,
		detectTaskService:  detectTaskSrv,
		syncConfigService:  scanConfigSyncSrv,
	}

	return n, nil
}
