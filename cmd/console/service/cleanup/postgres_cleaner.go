package cleanup

import (
	"context"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"time"
)

type PostgresCleaner struct {
	db *rdbtools.GormWrapper
}

func NewPostgresCleaner(db *rdbtools.GormWrapper) *PostgresCleaner {
	return &PostgresCleaner{db: db}
}

const (
	postgresBatch         = 1000
	postgresCleanInterval = time.Millisecond * 400
)

func (c *PostgresCleaner) Clean(ctx context.Context, daysOffset int) error {
	logging.GetLogger().Info().Msgf("postgres cleaner start, daysOffset:%d", daysOffset)
	offsetTimestamp := time.Now().Add(-time.Hour * 24 * time.Duration(daysOffset)).UnixNano()
	finished := false
	totalDeletedRows := int64(0)
	sql := "with temp as (select id from events where timestamp < ? limit ?) delete from events where id in (select * from temp)"

	cleanFunc := func() error {
		db := c.db.Get().WithContext(ctx).Exec(sql, offsetTimestamp, postgresBatch)
		if db.Error != nil {
			return db.Error
		}

		totalDeletedRows += db.RowsAffected
		if db.RowsAffected < postgresBatch {
			finished = true
		}
		return nil
	}

	for !finished {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := util.WithRetry(cleanFunc, util.DefaultRetryConf); err != nil {
				return err
			}
			time.Sleep(postgresCleanInterval)
		}
	}

	logging.GetLogger().Info().Msgf("postgres cleaner finished successfully, totalDeletedRows:%d", totalDeletedRows)
	return nil
}
