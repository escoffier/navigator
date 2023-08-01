package datamigrate

import (
	"context"

	"gitlab.com/security-rd/go-pkg/logging"

	datamigrate2 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/dataMigrate"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
)

const (
	serviceName = "data-migrate"
)

type MigrateSrv struct {
	MigratorSrv *datamigrate2.MigratorSrv
}

func (n *MigrateSrv) Start(ctx context.Context) error {

	if !scannerUtils.MainCluster() {
		logging.Get().Info().Msg("MigrateSrv not in main cluster ")
		return nil
	}

	logging.Get().Info().Msg("MigrateSrv in  main cluster")

	if err := n.MigratorSrv.Start(ctx); err != nil {
		logging.Get().Err(err).Msg("MigrateSrv start")
		return err
	}
	logging.Get().Info().Msg("MigrateSrv start succeed")

	return nil
}

func (n *MigrateSrv) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.Get().Err(err).Str("serviceName", serviceName).Msg("failed to register service")
		return
	}

	logging.Get().Info().Str("serviceName", serviceName).Msg("succeed to register service")
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	d := &MigrateSrv{MigratorSrv: datamigrate2.NewMigratorSrv()}
	return d, nil
}
