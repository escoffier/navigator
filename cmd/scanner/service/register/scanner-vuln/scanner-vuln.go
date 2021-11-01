package scanner_vuln

import (
	"context"

	scanner_vuln "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/scanner-vuln"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "scanner-vuln"
)

type Config struct {
}

type ScannerVulnService struct {
	//config      Config
	scannerVuln *scanner_vuln.ScannerVuln
}

func (s *ScannerVulnService) Start(ctx context.Context) error {
	s.scannerVuln.Run()
	return nil
}

func (s *ScannerVulnService) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	s := &ScannerVulnService{}
	s.scannerVuln = scanner_vuln.NewScannerVuln(config.Options.PvcPath)
	return s, nil
}
