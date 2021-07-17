package dal

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func GetConfig(ctx context.Context, rdb *rdbtools.GormWrapper, key string) (*model.TensorConfig, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	var config []*model.TensorConfig
	var innerErr error
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(pgCtx, 300*time.Millisecond)
		defer cancel()

		innerErr = rdb.Get().WithContext(oneCtx).Model(&config).Where("key = ? AND status = ?", key, 0).Find(&config).Error
		if innerErr == gorm.ErrRecordNotFound {
			return nil
		}
		return innerErr
	})

	if innerErr == gorm.ErrRecordNotFound {
		return nil, nil
	} else if err != nil {
		return nil, err
	} else if len(config) == 0 {
		return nil, nil
	}
	return config[0], nil
}

func newConfig(ctx context.Context, key string, val []byte, utime time.Time) *model.TensorConfig {
	user := util.GetUserFromContext(ctx)
	c := model.TensorConfig{
		Key:       key,
		Config:    val,
		CreatedAt: utime,
		UpdatedAt: utime,
		Status:    0,
		Creator:   user,
		Updater:   user,
	}
	return &c
}
func SetConfig(ctx context.Context, rdb *rdbtools.GormWrapper, key string, val []byte) error {
	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	config := newConfig(ctx, key, val, time.Now())
	return util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(pgCtx, 500*time.Millisecond)
		defer cancel()

		return rdb.Get().WithContext(oneCtx).Model(config).Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "key"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"updated_at",
				"config",
				"status",
				"updater",
			}),
		}).Create(config).Error
	})
}
