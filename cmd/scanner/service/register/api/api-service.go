package api

import (
	"context"
	"errors"
	"net/http"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/api"
	flag2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/cmd/flag"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/ci"
	deployService "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/deployment"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/detect"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagemeta"
	scanTrivy "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/engin/trivy"
	imagescanSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagescan/service"
	imagesecSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/imagesec"
	regSrv "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/registry/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scanReportService "gitlab.com/piccolo_su/vegeta/cmd/scanner/scan-report/service"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store/adaptStore"
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
		if !errors.Is(err, http.ErrServerClosed) {
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
	redCli, err := store.GetRedisClient(consts.TrivyRedisIndex)
	if err != nil {
		return nil, err
	}
	rdbInstance := store.GetRDBInstance()

	registryDal := imagesecStore.NewRegistryDao(rdbInstance)
	vulnDal := adaptStore.NewVulnDao(rdbInstance)
	ciDal := adaptStore.NewCiDao(rdbInstance)
	scannerInstanceDal := imagesecStore.NewScannerInstanceDao(rdbInstance)
	nodeImageDal := imagesecStore.NewImageMetaDao(rdbInstance)
	nodeDal := imagesecStore.NewNodeReportDao(rdbInstance)
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
	trustedImageDal := adaptStore.NewTrustedImageDao(rdbInstance)
	syncTaskDal := imagesecStore.NewSyncTaskDao(rdbInstance)
	exportDal := imagesecStore.NewExportTaskDao(rdbInstance)
	imageDal := imagesecStore.NewImageMetaDao(rdbInstance)

	detectPolicyDal := imagesecStore.NewDetectPolicyDao(rdbInstance)
	deployRecordDal := imagesecStore.NewDeployDao(rdbInstance)

	deployDal := imagesecStore.NewDeployDao(rdbInstance)
	cacheDal := imagesecStore.NewImageCacheDao(rdbInstance)
	scanDbMetaDal := imagesecStore.NewScanDbMetaDao(rdbInstance)

	imageSrv := imagemeta.NewImageMetaSrv(
		nodeImageDal,
		registryDal,
		scanResultDal,
		resourceDal,
		nodeDal,
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
	trustedImageSrv := imagesecSrv.NewTrustedImageSrv(trustedImageDal)
	registrySrv := regSrv.NewRegistrySrv(registryDal, syncTaskDal, scanInstanceDal, policyDal, scannerConfigDal)

	detectTaskSrv := detect.NewImageDetectTaskSrv(imageSrv, detectTaskDal, policyDal, detectResultDal)
	policySrv := detect.NewPolicySrv(policyDal, detectTaskSrv, sensitiveRuleDal, userDal)
	scanInfoSrv := imagesecSrv.NewScanInstanceSrv(imagesecStore.NewScannerInstanceDao(rdbInstance))
	scanTaskSrv := imagescanSrv.NewScanTaskSrv(scanTaskDal, scanTaskPreDal, detectTaskDal, imageSrv, imageDal, scannerConfigDal, imageDal, userDal, nodeDal)
	scanImageConfigSrv := imagesecSrv.NewScannerConfigSrv(scannerConfigDal)
	sensitiveRuleSrv := imagesecSrv.NewSensitiveRuleSrv(sensitiveRuleDal, scanImageConfigSrv)

	nodeInfoSrv := imagesecSrv.NewNodeReportSrv(nodeDal)
	checker := detect.NewImagePolicyCheck()
	deploySrv := deployService.NewDeploySrv(checker, imageDal, detectPolicyDal, scanResultDal, scanTaskDal, imageSrv, deployRecordDal)

	exportSrv := scanReportService.NewExportTaskSrv(
		exportDal,
		imageSrv,
		scanTaskSrv,
		nil,
		vulnDal,
	)

	trivyJob, err := scanTrivy.NewTrivySrv(scanTrivy.WithRedisCli(redCli))
	if err != nil {
		return nil, err
	}

	dBManager := imagesecSrv.NewDBUpdateSrv(trivyJob, scanDbMetaDal)

	s := &ScannerAPIService{}
	s.config.Options = config.Options
	s.ginServer = &http.Server{
		Addr: s.config.Options.HTTPListenAddr,
		Handler: api.SetupGinRouter(
			imageSrv,
			trustedImageSrv,
			registrySrv,
			vulnSrv,
			ci.NewCiComponent(ciDal, userDal),
			scanInfoSrv,
			exportSrv,
			policySrv,
			scanTaskSrv,
			sensitiveRuleSrv,
			scanImageConfigSrv,
			nodeInfoSrv,
			deploySrv,
			dBManager,
		),
	}

	return s, nil
}
