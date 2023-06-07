// Package task_policy generate task by config policy
package scantask

import (
	"context"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/component"
	flag2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/flag"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "scan-task-service"
)

type Config struct {
	Options *flag2.ScannerOpts
}

type Service struct {
	ScanConfigSrv component.ScanConfigSrvInterface
}

func (s *Service) Start(ctx context.Context) error {
	err := s.ScanConfigSrv.AddTaskByStrategy(ctx)
	if err != nil {
		logging.GetLogger().Err(err).Msg("AddTaskByStrategy start failure")
		return err
	}
	logging.GetLogger().Info().Msg("AddTaskByStrategy start success")
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
	s := &Service{}
	scanConfigSrv := component.NewScanConfigSrv(
		store.NewScanConfigDao(store.GetScannerWrapperDb()),
		store.NewRegistryDao(store.GetScannerWrapperDb()),
		store.NewScannerOrm(store.GetScannerWrapperDb()),
		store.NewScannerOrm(store.GetScannerWrapperDb()),
		store.NewScannerInstanceDao(store.GetScannerWrapperDb()),
	)
	s.ScanConfigSrv = scanConfigSrv

	return s, nil
}
