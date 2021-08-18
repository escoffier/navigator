package dal

import (
	"context"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

func GetConfig(ctx context.Context, rdb *rdbtools.GormWrapper, key string) (*model.TensorConfig, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	var config model.TensorConfig
	var innerErr error
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(pgCtx, 300*time.Millisecond)
		defer cancel()

		innerErr = rdb.Get().WithContext(oneCtx).Model(&config).Where("key = ? AND status = ?", key, 0).First(&config).Error
		if innerErr == gorm.ErrRecordNotFound {
			return nil
		}
		return innerErr
	})

	if err != nil {
		return nil, err
	}

	if innerErr == gorm.ErrRecordNotFound {
		return nil, nil
	}

	return &config, nil
}

func newConfig(ctx context.Context, key string, val []byte, utime time.Time) *model.TensorConfig {
	user, ok := util.GetUserFromContext(ctx)
	userName := ""
	if ok {
		userName = user.UserName
	}
	c := model.TensorConfig{
		Key:       key,
		Config:    val,
		CreatedAt: utime,
		UpdatedAt: utime,
		Status:    0,
		Creator:   userName,
		Updater:   userName,
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
