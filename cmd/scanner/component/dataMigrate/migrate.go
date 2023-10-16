package datamigrate

import (
	"context"
	"os"
	"time"

	ver220 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/dataMigrate/220"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
)

type Migrator interface {
	Migrate(ctx context.Context, ver string) error
}

type MigratorSrv struct {
	Migrator []Migrator
	Log      *scannerUtils.LogEvent
}

func NewMigratorSrv() *MigratorSrv {
	s := &MigratorSrv{Migrator: make([]Migrator, 0)}
	ver210M, err := ver220.GetImageMigrate()
	if err != nil {
		s.Log.Err(err).Msg("GetImageMigrate ver210")
	} else {
		s.Migrator = append(s.Migrator, ver210M)
	}
	s.Log = scannerUtils.NewLogEvent(
		scannerUtils.WithSubModule("Migrator"),
		scannerUtils.WithModule(consts.ModuleMigrate))

	return s
}

func (s *MigratorSrv) Start(ctx context.Context) error {
	if !scannerUtils.MainCluster() {
		s.Log.Info().Msg("not in main cluster do not do data migrate")
		return nil
	}

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for {
			ver := os.Getenv("SOFT_VERSION")
			errs := make([]error, 0)
			<-ticker.C
			for i := range s.Migrator {
				if err := s.Migrator[i].Migrate(ctx, ver); err != nil {
					s.Log.Err(err).Str("SOFT_VERSION", ver).Msg("Migrate")
					errs = append(errs, err)
				}
			}
			if len(errs) == 0 {
				ticker.Reset(time.Hour)
			}
		}
	}()
	return nil
}
