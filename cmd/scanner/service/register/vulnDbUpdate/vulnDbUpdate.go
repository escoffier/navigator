package vulnDbUpdate

import (
	"context"

	"github.com/mileusna/crontab"
	vuln_updata "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "vulnDb-update-service"
)

type Config struct {
}

type VulnDbUpdateService struct {
}

func (s *VulnDbUpdateService) Vuln_updata_fn() {
	err := vuln_updata.GetUpdataService().AutoScanAll(context.Background(), 1, "漏洞库每日1点定时触发")
	logging.GetLogger().Error().Err(err).Msg("VulnDb auto Updata error")
}

func (s *VulnDbUpdateService) Start(ctx context.Context) error {

	cleanJob := crontab.New() // create cron table
	// AddJob ,每天1点过2分时运行一次
	if err := cleanJob.AddJob("2 1 * * *", s.Vuln_updata_fn); err != nil {
		logging.GetLogger().Error().Err(err).Msg("VulnDb auto Updata error")
		return err
	}

	return nil
}

func (s *VulnDbUpdateService) Stop(ctx context.Context) error {

	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	c := &VulnDbUpdateService{}

	return c, nil
}
