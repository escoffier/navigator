package api

import (
	"context"
	"net/http"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/api"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/ci"
	dbManage "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/db-manage"
	deployService "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/deployment"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/detect"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	aviraengin "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/avira"
	clamavengin "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/clamav2"
	imagescanSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/service"
	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	regSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/service"
	scanwebshell "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanner-webshell"
	flag2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/flag"
	scanReportService "gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	imagesecStore "gitlab.com/piccolo_su/vegeta/cmd/scanner/store/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "api-imagescanSrv"
)

type Config struct {
	Options *flag2.ScannerOpts
}

type ScannerAPIService struct {
	config    Config
	ginServer *http.Server
}

func (s *ScannerAPIService) Start(ctx context.Context) error {
	if err := s.ginServer.ListenAndServe(); err != nil {
		if err != http.ErrServerClosed {
			logging.GetLogger().Err(err).Msg("scanner api http server listen failed")
		}
	}
	logging.GetLogger().Error().Msg("scanner api http server exited")
	return nil
}

func (s *ScannerAPIService) Stop(ctx context.Context) error {
	if err := s.ginServer.Shutdown(ctx); err != nil {
		logging.GetLogger().Err(err).Msg("scanner api server stop err")
		return err
	}
	logging.GetLogger().Info().Msg("scanner api server stop")
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Err(err).Str("serviceName", serviceName).Msg("int imagescanSrv err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	dal := store.GetScannerOrmDb()
	rdbInstance := store.GetRDBInstance()

	rc, err := store.GetRedisClient(0)
	if err != nil {
		logging.GetLogger().Err(err).Msg("get redis client failed")
		return nil, err
	}

	registryDal := imagesecStore.NewRegistryDao(rdbInstance)
	vulnDal := store.NewVulnDao(rdbInstance)
	ciDal := store.NewCiDao(rdbInstance)
	webshellDal := store.NewWebsehllDao(rdbInstance)
	scannerInstanceDal := imagesecStore.NewScannerInstanceDao(rdbInstance)
	nodeImageDal := imagesecStore.NewImageMetaDao(rdbInstance, nil)
	nodeReportDal := imagesecStore.NewNodeReportDao(rdbInstance)
	policyDal := imagesecStore.NewDetectPolicyDao(rdbInstance)
	userDal := imagesecStore.NewUserDao(rdbInstance)
	scanInstanceDal := imagesecStore.NewScannerInstanceDao(rdbInstance)
	detectTaskDal := imagesecStore.NewDetectTaskDao(rdbInstance)
	detectResultDal := imagesecStore.NewImageDetectResultDao(rdbInstance)
	scanTaskDal := imagesecStore.NewScanTaskDao(rdbInstance)
	scanTaskPreDal := imagesecStore.NewScanTaskPreDao(rdbInstance)

	scanResultDal := imagesecStore.NewScanResultDao(rdbInstance)
	sensitiveRuleDal := imagesecStore.NewSensitiveRuleDao(rdbInstance)
	scannerConfigDal := imagesecStore.NewScanImageConfigDao(rdbInstance)
	resourceDal := imagesecStore.NewResourceDao(rdbInstance)
	trustedImageDal := store.NewScannerOrm(rdbInstance)
	syncTaskDal := imagesecStore.NewSyncTaskDao(rdbInstance)
	exportDal := imagesecStore.NewExportTaskDao(rdbInstance)
	versionDal := store.NewVersionDao(rdbInstance)
	imageDal := imagesecStore.NewImageMetaDao(rdbInstance, rc)

	detectPolicyDal := imagesecStore.NewDetectPolicyDao(rdbInstance)
	deployRecordDal := imagesecStore.NewDeployDao(rdbInstance)

	scanDbMetaDal := imagesecStore.NewScanDbMetaDao(rdbInstance)
	nodeInfoDal := imagesecStore.NewNodeReportDao(rdbInstance)
	deployDal := imagesecStore.NewDeployDao(rdbInstance)
	cacheDal := imagesecStore.NewImageCacheDao(rdbInstance)

	imageSrv := imagemeta.NewImageMetaSrv(
		nodeImageDal,
		registryDal,
		scanResultDal,
		resourceDal,
		nodeReportDal,
		policyDal,
		detectResultDal,
		trustedImageDal,
		scannerConfigDal,
		scanTaskDal,
		scannerInstanceDal,
		deployDal,
		cacheDal,
	)

	vulnSrv := imagescanSrv.NewScanResultSrv(scanResultDal, cacheDal)
	rejectSvc := component.NewImageRejectSrc(dal)
	registrySrv := regSrv.NewRegistrySrv(registryDal, syncTaskDal, scanInstanceDal, policyDal, scannerConfigDal)
	dbManagerSrv := dbManage.NewDBManageSrv(versionDal, userDal)

	detectTaskSrv := detect.NewImageDetectTaskSrv(imageSrv, detectTaskDal, policyDal, detectResultDal)
	policySrv := detect.NewPolicySrv(policyDal, detectTaskSrv, sensitiveRuleDal, userDal)
	scanInfoSrv := imagesecSrv.NewScanInstanceSrv(imagesecStore.NewScannerInstanceDao(rdbInstance))
	webshellSrv2 := scanwebshell.NewWebshellComponent(webshellDal)
	scanTaskSrv := imagescanSrv.NewScanTaskSrv(scanTaskDal, scanTaskPreDal, detectTaskDal, imageSrv, imageDal, scannerConfigDal, imageDal, userDal)
	scanImageConfigSrv := imagesecSrv.NewScannerConfigSrv(scannerConfigDal)
	sensitiveRuleSrv := imagesecSrv.NewSensitiveRuleSrv(sensitiveRuleDal, scanImageConfigSrv)

	nodeInfoSrv := imagesecSrv.NewNodeReportSrv(nodeReportDal)

	aviraUpdateSrv := aviraengin.NewAviraUpdateSrv()
	clamavUpdateSrv := clamavengin.NewClamavUpdateSrv()

	dbUpdateSrv := imagescanSrv.NewDBManagerSrv(aviraUpdateSrv, clamavUpdateSrv, scanDbMetaDal, nodeInfoDal, scanInstanceDal)
	checker := detect.NewImagePolicyCheck()

	deploySrv := deployService.NewDeploySrv(checker, imageDal, detectPolicyDal, scanResultDal, scanTaskDal, imageSrv, deployRecordDal)

	exportSrv := scanReportService.NewExportTaskSrv(
		exportDal,
		imageSrv,
		scanTaskSrv,
		nil,
		vulnDal,
	)

	s := &ScannerAPIService{}
	s.config.Options = config.Options
	s.ginServer = &http.Server{
		Addr: s.config.Options.HTTPListenAddr,
		Handler: api.SetupGinRouter(
			imageSrv,
			rejectSvc,
			registrySrv,
			vulnSrv,
			ci.NewCiComponent(ciDal, userDal),
			scanInfoSrv,
			webshellSrv2,
			exportSrv,
			dbManagerSrv,
			policySrv,
			scanTaskSrv,
			sensitiveRuleSrv,
			scanImageConfigSrv,
			nodeInfoSrv,
			dbUpdateSrv,
			deploySrv,
		),
	}

	return s, nil
}
