package api

import (
	"context"
	"net/http"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/api"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
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

type ScannerApiService struct {
	config    Config
	ginServer *http.Server
}

func (s *ScannerApiService) Start(ctx context.Context) error {
	if err := s.ginServer.ListenAndServe(); err != nil {
		if err != http.ErrServerClosed {
			logging.GetLogger().Error().Err(err).Msg("scanner api http server listen failed")
		}
	}
	logging.GetLogger().Error().Msg("scanner api http server exited")
	return nil
}

func (s *ScannerApiService) Stop(ctx context.Context) error {
	if err := s.ginServer.Shutdown(ctx); err != nil {
		logging.GetLogger().Error().Err(err).Msg("scanner api server stop err")
		return err
	}
	logging.GetLogger().Info().Msg("scanner api server stop")
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	dal := store.GetScannerOrmDb()
	scannerWrapperDb := store.GetScannerWrapperDb()
	// sdb := store.GetScannerDb()
	rc, err := store.GetRedisClient(0)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("get redis client failed")
		return nil, err
	}

	registryDal := store.NewRegistryDao(scannerWrapperDb)
	s := &ScannerApiService{}
	s.config.Options = config.Options
	s.ginServer = &http.Server{
		Addr: s.config.Options.HttpListenAddr,
		Handler: api.SetupGinRouter(
			component.NewConScannerSrv(dal, registryDal, nil, nil, nil, nil, nil, dal, dal),
			component.NewImageRejectSrc(dal),
			component.NewHarborSrc(dal, rc, nil), // todo: use new task interface,not redclair
			component.NewRegistrySrv(store.NewRegistryDao(scannerWrapperDb)),
			component.NewScanConfigSrv(store.NewScanConfigDao(store.GetScannerWrapperDb()),
				store.NewRegistryDao(store.GetScannerWrapperDb()),
				store.NewScannerOrm(store.GetScannerWrapperDb()),
				store.NewScannerOrm(store.GetScannerWrapperDb()),
			),
		),
	}

	return s, nil
}
