package rdbtools

import (
	"context"
	"time"

	"github.com/avast/retry-go"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

var (
	migrateRetryOptions = []retry.Option{
		retry.MaxDelay(time.Duration(5) * time.Second),
		retry.DelayType(retry.FixedDelay),
		retry.Attempts(uint(3)),
		retry.Delay(time.Duration(5) * time.Second),
	}
)

type GormTable interface {
	TableName() string
}

func MigrateTable(ctx context.Context, rdb *GormWrapper, model GormTable) error {
	return util.RetryWithBackoff(ctx, func() error {
		oneCtx, cancel := context.WithTimeout(ctx, 3*time.Millisecond)
		defer cancel()
		return rdb.Get().WithContext(oneCtx).AutoMigrate(&model)
	}, migrateRetryOptions...)
}
