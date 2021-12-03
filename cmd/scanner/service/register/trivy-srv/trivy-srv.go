package trivy_srv

import (
	"context"
	"os"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "trivy-srv"
)

type Config struct {
}

type TrivyService struct {
	// config       Config
	trivyService *component.TrivyServer
}

func (t *TrivyService) Start(ctx context.Context) error {
	return t.trivyService.Run(ctx)
}

func (t *TrivyService) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("serviceName", serviceName).Msg("init service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	os.Setenv("TRIVY_NON_SSL", "true")
	t := &TrivyService{}
	rc, err := store.GetRedisClient(1)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("New trivyServer failed")
		return nil, err
	}
	TrivyServer, err := component.NewTrivyServer(*rc, config.Options.PvcPath)
	if err != nil {
		logging.GetLogger().Error().Err(err).Msg("New trivyServer failed")
		return nil, err
	}
	t.trivyService = TrivyServer

	return t, nil
}
