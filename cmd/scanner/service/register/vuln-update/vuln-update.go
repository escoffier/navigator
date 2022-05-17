package vulnupdate

import (
	"context"

	"github.com/mileusna/crontab"

	vulnUpdata "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/vuln-updata"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "vuln-update-service"
)

type Config struct {
}

type VulnUpdateService struct { // nolint
}

func (s *VulnUpdateService) VulnUpdateFn() {
	err := vulnUpdata.GetUpdataService().AutoScanAll(context.Background(), 1, "漏洞库每日1点定时触发")
	logging.GetLogger().Err(err).Msg("VulnDb auto Updata error")
}

func (s *VulnUpdateService) Start(ctx context.Context) error {

	cleanJob := crontab.New() // create cron table
	// AddJob ,每天1点过2分时运行一次
	if err := cleanJob.AddJob("2 1 * * *", s.VulnUpdateFn); err != nil {
		logging.GetLogger().Err(err).Msg("VulnDb auto Updata error")
		return err
	}

	return nil
}

func (s *VulnUpdateService) Stop(ctx context.Context) error {

	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	c := &VulnUpdateService{}

	return c, nil
}
