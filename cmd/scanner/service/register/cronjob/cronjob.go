package cronjob

import (
	"context"
	"os"

	"github.com/mileusna/crontab"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	flag2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/flag"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "cron-job"
)

type Config struct {
	BuffRegistryURL string // buffer registry url, store in ENV variables
	Options         *flag2.ScannerOpts
}

type Service struct {
	config Config // nolint:structcheck,unused
}

func (s *Service) Start(ctx context.Context) error {
	scannerWrapperDb := store.GetScannerWrapperDb()
	dal := store.GetScannerOrmDb()
	registryDal := store.NewRegistryDao(store.GetScannerWrapperDb())
	scanConfigDal := store.NewScanConfigDao(store.GetScannerWrapperDb())
	scannerSrv := component.NewConScannerSrv(dal, registryDal, dal, scanConfigDal, nil)
	cronjob := crontab.New() // create cron table

	// AddJob ,每月1日0点过2分时运行一次
	if err := cronjob.AddJob("2 0 1 * *", scannerSrv.DeleteCICDImage, ctx); err != nil {
		logging.GetLogger().Err(err).Msg("add buffer registry GC job")
		return err
	}
	podDal := store.NewPodResourceRelationDao(store.GetScannerWrapperDb())
	syncRetryDal := store.NewSyncRetryImageDao(store.GetScannerWrapperDb())
	vulnDal := store.NewVulnDao(scannerWrapperDb)
	scannerDB := store.NewScannerDB(scannerWrapperDb)

	syncSrv := component.NewSyncRepoImage(registryDal, dal, podDal, scanConfigDal, syncRetryDal, vulnDal, scannerDB)

	syncAllImage := os.Getenv("SyncAllImage") // 使用一个环境变量，方便测试
	if syncAllImage == "" {
		// AddJob ,每天凌晨3点4分运行一次,注意使用的是UTC时间
		syncAllImage = "4 19 * * *"
	}

	if err := cronjob.AddJob(syncAllImage, syncSrv.SyncAllImage, ctx,
		component.SyncAllImageParam{SyncType: consts.TimingFullSync}); err != nil {
		logging.GetLogger().Err(err).Msg("add SyncAllImage cronjob")
		return err
	}

	logging.GetLogger().Info().Msg("add SyncAllImage job")

	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	c := &Service{}

	return c, nil
}
