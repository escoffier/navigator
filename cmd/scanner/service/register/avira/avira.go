package avira

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "avira_service"
)

type AviraService struct {
}

func (c *AviraService) Start(ctx context.Context) error {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		failCount := 0

		for {

			var out, stderr bytes.Buffer

			cmd := exec.Command("/usr/local/savapi-sdk-linux64/bin/savapi", "-N", "-C", "/etc/savapi/savapi.conf")
			cmd.Stdout = &out
			cmd.Stderr = &stderr
			err := cmd.Start()
			if err != nil {
				logging.GetLogger().Err(err).Str("serviceName", serviceName).Msg("start avira service err")
			}
			logging.GetLogger().Info().Str("serviceName", serviceName).Msg("start avira service")
			cmd.Wait()
			failCount++
			logging.GetLogger().Err(err).Str("serviceName", serviceName).Msgf("avira service exit, failCount: %d", failCount)
			time.Sleep(5 * time.Second)
		}
	}()
	return nil
}

func (c *AviraService) Stop(ctx context.Context) error {
	return nil
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	m := &AviraService{}

	return m, nil
}

func init() {
	if os.Getenv("SCAN_VIRUS") == "avira" {
		err := register.Register(serviceName, newService)
		if err != nil {
			logging.GetLogger().Err(err).Str("serviceName", serviceName).Msg("init service err")
		}
	}
}
