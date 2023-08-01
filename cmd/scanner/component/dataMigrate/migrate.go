package datamigrate

import (
	"context"
	"os"
	"time"

	"gitlab.com/security-rd/go-pkg/logging"

	ver220 "gitlab.com/piccolo_su/vegeta/cmd/scanner/component/dataMigrate/220"
	scannerUtils "gitlab.com/piccolo_su/vegeta/cmd/scanner/utils"
)

type Migrator interface {
	Migrate(ctx context.Context, ver string) error
}

type MigratorSrv struct {
	Migrator []Migrator
}

func NewMigratorSrv() *MigratorSrv {
	s := &MigratorSrv{Migrator: make([]Migrator, 0)}
	ver210M, err := ver220.GetImageMigrate()
	if err != nil {
		logging.Get().Err(err).Str("module", "migrate").Msg("GetImageMigrate ver210")
	} else {
		s.Migrator = append(s.Migrator, ver210M)
	}

	return s
}

func (s *MigratorSrv) Start(ctx context.Context) error {
	if !scannerUtils.MainCluster() {
		logging.Get().Info().Str("module", "migrate").Msg("not in main cluster do not do data migrate")
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
					logging.Get().Err(err).Str("module", "migrate").Str("SOFT_VERSION", ver).Msg("Migrate")
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
