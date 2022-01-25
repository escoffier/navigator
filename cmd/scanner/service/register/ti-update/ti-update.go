// Package ti_update update all thread intelligent database file where they are ready
package tiupdate

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/global"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "ti-update"
)

type TiUpdate struct {
}

func (s *TiUpdate) Update(ctx context.Context) error {
	time.Sleep(time.Duration(23) * time.Second)
	logging.GetLogger().Info().Msg("Suspending all task during DB update")
	global.TiDbUpdateWg.Add(1)
	defer global.TiDbUpdateWg.Done()

	logging.GetLogger().Info().Msg("Waiting for all task to be processed before DB update...")
	global.TaskWg.Wait()

	// pretend update
	time.Sleep(time.Duration(20) * time.Second)

	// todo: update db,set flag and timestamp,so task cronjob can generate new task

	logging.GetLogger().Info().Msg("ti update end")
	return nil
}

func (s *TiUpdate) Start(ctx context.Context) error {

	for {
		// mock update
		if err := s.Update(ctx); err != nil {
			logging.GetLogger().Err(err).Msg("ti update err")
		}
	}
}

func (s *TiUpdate) Stop(ctx context.Context) error {

	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Error().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	t := &TiUpdate{}

	return t, nil
}
