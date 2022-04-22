package cleanregistry

import (
	"context"

	"github.com/mileusna/crontab"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	flag2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/flag"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "clean-registry-service"
)

type Config struct {
	BuffRegistryURL string // buffer registry url, store in ENV variables
	Options         *flag2.ScannerOpts
}

type Service struct {
	config Config // nolint:structcheck,unused
}

func (s *Service) Start(ctx context.Context) error {
	dal := store.GetScannerOrmDb()
	sdb := store.GetScannerDb()
	registryDal := store.NewRegistryDao(store.GetScannerWrapperDb())
	scanConfigDal := store.NewScanConfigDao(store.GetScannerWrapperDb())
	scannerSrv := component.NewConScannerSrv(dal, registryDal, nil, nil, sdb, nil, nil, dal, dal, scanConfigDal, nil)
	cleanJob := crontab.New() // create cron table

	// AddJob ,每天0点过2分时运行一次
	if err := cleanJob.AddJob("2 0 * * *", scannerSrv.DeleteCICDImage, context.Background()); err != nil {
		logging.GetLogger().Error().Err(err).Msg("add buffer registry GC job")
		return err
	}

	return nil
}

func (s *Service) Stop(ctx context.Context) error {

	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	c := &Service{}

	return c, nil
}
