package api

import (
	"context"
	"fmt"
	"net/http"

	"gitlab.com/security-rd/go-pkg/sdk/palace"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/api"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component/ci"
	scanwebshell "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanner-webshell"
	flag2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/flag"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "api-service"
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
		logging.GetLogger().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	dal := store.GetScannerOrmDb()
	scannerWrapperDb := store.GetScannerWrapperDb()

	rc, err := store.GetRedisClient(0)
	if err != nil {
		logging.GetLogger().Err(err).Msg("get redis client failed")
		return nil, err
	}

	registryDal := store.NewRegistryDao(scannerWrapperDb)
	scanConfigDal := store.NewScanConfigDao(scannerWrapperDb)
	vulnDal := store.NewVulnDao(scannerWrapperDb)
	scanResultDal := store.NewImageScanResultDao(scannerWrapperDb)
	ciDal := store.NewCiDao(scannerWrapperDb)
	webshellDal := store.NewWebsehllDao(scannerWrapperDb)
	scannerInstanceDal := store.NewScannerInstanceDao(scannerWrapperDb)
	scanTaskDal := store.NewScannerOrm(scannerWrapperDb)
	imageDal := store.NewScannerOrm(scannerWrapperDb)
	resourceDal := store.NewResourceDao(scannerWrapperDb)
	trustedImageDal := store.NewScannerOrm(scannerWrapperDb)
	syncTaskDal := store.NewSyncTaskDao(scannerWrapperDb)

	palaceHandler, err := palace.Init()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("Failed to init palaceHandler, %v", err)
		return nil, fmt.Errorf("failed to init palaceHandler, %v", err)
	}

	scannerSvc := component.NewConScannerSrv(dal, registryDal, scanTaskDal, scanConfigDal, vulnDal, webshellDal, &palaceHandler)
	imageSvc := component.NewImageSrv(imageDal, registryDal, scanTaskDal, vulnDal, scanResultDal, webshellDal, trustedImageDal, resourceDal, scannerInstanceDal)
	rejectSvc := component.NewImageRejectSrc(dal)
	harborSvc := component.NewHarborSrc(dal, rc)
	registrySrv := component.NewRegistrySrv(registryDal, scanConfigDal, syncTaskDal)
	scanConfigSrv := component.NewScanConfigSrv(scanConfigDal, registryDal, dal, scanTaskDal, scannerInstanceDal)
	syncSrv := component.NewSyncRepoImage(registryDal, imageDal, scanConfigDal, vulnDal, syncTaskDal)

	s := &ScannerAPIService{}
	s.config.Options = config.Options
	s.ginServer = &http.Server{
		Addr: s.config.Options.HTTPListenAddr,
		Handler: api.SetupGinRouter(
			scannerSvc,
			imageSvc,
			rejectSvc,
			harborSvc,
			registrySrv,
			scanConfigSrv,
			component.NewVulnService(vulnDal, scanTaskDal),
			syncSrv,
			ci.NewCiComponent(ciDal),
			component.NewScannerInstanceInfoSrv(store.NewScannerInstanceDao(scannerWrapperDb)),
			scanwebshell.NewWebshellComponent(webshellDal),
		),
	}

	return s, nil
}
