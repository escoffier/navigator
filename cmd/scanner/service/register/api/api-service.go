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
	// sdb := store.GetScannerDb()
	rc, err := store.GetRedisClient(0)
	if err != nil {
		logging.GetLogger().Err(err).Msg("get redis client failed")
		return nil, err
	}
	scanTaskDal := store.NewScannerOrm(store.GetScannerWrapperDb())

	registryDal := store.NewRegistryDao(scannerWrapperDb)
	scanConfigDal := store.NewScanConfigDao(scannerWrapperDb)
	vulnDal := store.NewVulnDao(scannerWrapperDb)
	scanResultDal := store.NewImageScanResultDao(scannerWrapperDb)
	podResourceRelationDal := store.NewPodResourceRelationDao(scannerWrapperDb)
	syncRetryImageDal := store.NewSyncRetryImageDao(scannerWrapperDb)
	scannerDB := store.NewScannerDB(scannerWrapperDb)
	ciDal := store.NewCiDao(scannerWrapperDb)
	webshellDal := store.NewWebsehllDao(scannerWrapperDb)
	scannerInstanceDal := store.NewScannerInstanceDao(scannerWrapperDb)
	palaceHandler, err := palace.Init()
	if err != nil {
		logging.GetLogger().Error().Err(err).Msgf("Failed to init palaceHandler, %v", err)
		return nil, fmt.Errorf("failed to init palaceHandler, %v", err)
	}

	syncTaskDal := store.NewSyncTaskDao(scannerWrapperDb)

	s := &ScannerAPIService{}
	s.config.Options = config.Options
	s.ginServer = &http.Server{
		Addr: s.config.Options.HTTPListenAddr,
		Handler: api.SetupGinRouter(
			rc,
			component.NewConScannerSrv(dal, registryDal, dal, scanConfigDal, store.GetSingeVulnDao(), &palaceHandler),
			component.NewImageService(dal, registryDal, scanTaskDal, vulnDal, scanResultDal, webshellDal),
			component.NewImageRejectSrc(dal),
			component.NewHarborSrc(dal, rc, nil), // todo: use new task interface,not redclair
			component.NewRegistrySrv(registryDal, scanConfigDal, syncTaskDal),
			component.NewScanConfigSrv(scanConfigDal, registryDal, dal, scanTaskDal, scannerInstanceDal),
			component.NewVulnService(vulnDal, scanTaskDal),
			component.NewSyncRepoImage(registryDal, dal, podResourceRelationDal, scanConfigDal, syncRetryImageDal, vulnDal, scannerDB, syncTaskDal),
			ci.NewCiComponent(ciDal),
			component.NewScannerInstanceInfoSrv(store.NewScannerInstanceDao(scannerWrapperDb)),
			scanwebshell.NewWebshellComponent(webshellDal),
			component.NewImageScanResultSrv(store.NewImageScanResultDao(store.GetScannerWrapperDb())),
		),
	}

	return s, nil
}
