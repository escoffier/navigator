package scanvuln

import (
	"context"
	"path/filepath"

	scanVuln "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/bolt-vuln"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "scanner-vuln"
)

type Config struct {
}

type ScannerVulnService struct {
	// config      Config
	scannerVuln *scanVuln.BoltVuln
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
		logging.GetLogger().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	s := &ScannerVulnService{}
	s.scannerVuln = scanVuln.NewScannerVuln(filepath.Join(config.Options.PvcPath, "trivy"))
	return s, nil
}
