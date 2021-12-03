package malicious

import (
	"context"
	"os/exec"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "malicious-service"
)

type Config struct {
}

type MaliceService struct {
	// config Config
}

func (m *MaliceService) Start(ctx context.Context) error {
	cmd := exec.Command("service", "clamav-daemon", "start") // start clamd service
	out, err := cmd.Output()
	if err != nil {
		logging.GetLogger().Err(err).Msg("start malice service error")
		return err
	}
	logging.GetLogger().Info().Msgf("start malice service ok.%v", string(out))

	return nil
}

func (m *MaliceService) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	m := &MaliceService{}

	return m, nil
}
