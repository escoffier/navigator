package dbCleaner

import (
	"context"
	"sync"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/service/register"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/store"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
)

const (
	serviceName = "db_cleaner_service"
)

type CleanService struct {
}

func (c *CleanService) Start(ctx context.Context) error {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for _ = range ticker.C {
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

func (c *CleanService) Stop(ctx context.Context) error {
	return nil
}

func init() {
	err := register.Register(serviceName, newService)
	if err != nil {
		logging.GetLogger().Err(err).Str("serviceName", serviceName).Msg("int service err")
	}
}

func newService(config register.ScannerServiceConfig) (register.ScannerService, error) {
	m := &CleanService{}

	return m, nil
}
