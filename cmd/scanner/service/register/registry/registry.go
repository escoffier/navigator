package registry

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "scanner-registry"
)

type Registry struct {
	update component.RegistrySrvInterface
}

func (s *Registry) Start(ctx context.Context) error {
	// 检查仓库的健康状况
	go func() {
		defer func() {
			if err := recover(); err != nil {
				logging.GetLogger().Error().Msg("CheckHealth recover")
			}
		}()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for {
			<-ticker.C
			if global.ScannerInstance == "" {
				logging.GetLogger().Info().Msg("CheckHealth Registry global.ScannerInstance is empty ")
				continue
			}
			if err := s.update.CheckHealth(ctx, global.ScannerInstance); err != nil {
				logging.GetLogger().Err(err).Msg("CheckHealth service end")
				continue
			}
			logging.GetLogger().Debug().Str("ScannerInstance", global.ScannerInstance).Msg("CheckHealth start success")
		}
	}()

	return nil
}

func (s *Registry) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Err(err).Str("serviceName", serviceName).Msg("scanner-registry int service err")
	}
	logging.GetLogger().Info().Msg("scanner-registry register success")
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	scannerWrapperDb := store.GetScannerWrapperDb()

	registryDal := store.NewRegistryDao(scannerWrapperDb)
	scanConfigDal := store.NewScanConfigDao(scannerWrapperDb)
	s := component.NewRegistrySrv(registryDal, scanConfigDal)
	return &Registry{update: s}, nil
}
