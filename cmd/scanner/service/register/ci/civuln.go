package civuln

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	scanVuln "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/ci"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "ci-vuln"
)

type Config struct {
}

type ScannerVulnService struct {
	scannerVuln *scanVuln.BoltVuln
}

func (s *ScannerVulnService) Start(ctx context.Context) error {
	s.scannerVuln.Run()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			dal := store.GetCiDb()
			if dal == nil {
				continue
			}
			dal.TickerCleanRecord(context.Background(), 50000)
		}
	}()
	wg.Wait()

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
