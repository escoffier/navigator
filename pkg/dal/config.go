package dal

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func GetConfig(ctx context.Context, rdb *gorm.DB, key string) (*model.TensorConfig, error) {
	pgCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	var config model.TensorConfig
	var innerErr error
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(pgCtx, 300*time.Millisecond)
		defer cancel()

		innerErr = rdb.WithContext(oneCtx).Model(&config).Where("k = ? AND status = ?", key, 0).First(&config).Error
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

func NewConfig(ctx context.Context, key string, val []byte, utime time.Time) *model.TensorConfig {
	user, ok := model.GetSessionFromContext(ctx)
	userName := ""
	if ok {
		userName = user.Username
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
func SetConfig(ctx context.Context, rdb *gorm.DB, key string, val []byte) error {
	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	config := NewConfig(ctx, key, val, time.Now())
	return util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(pgCtx, 500*time.Millisecond)
		defer cancel()

		return rdb.WithContext(oneCtx).Model(config).Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "k"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"updated_at",
				"config",
				"status",
				"updater",
			}),
		}).Create(config).Error
	})
}

func BatchSetConfig(ctx context.Context, rdb *gorm.DB, configs []*model.TensorConfig) error {
	if len(configs) == 0 {
		return nil
	}
	pgCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	return util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(pgCtx, 500*time.Millisecond)
		defer cancel()

		return rdb.WithContext(oneCtx).Model(&model.TensorConfig{}).Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "k"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"updated_at",
				"config",
				"status",
				"updater",
			}),
		}).CreateInBatches(configs, 10).Error
	})
}

func BatchGetConfig(ctx context.Context, rdb *gorm.DB, keys []string) ([]*model.TensorConfig, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	pgCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	var configs []*model.TensorConfig
	err := util.RetryWithBackoff(pgCtx, func() error {
		oneCtx, cancel := context.WithTimeout(pgCtx, 300*time.Millisecond)
		defer cancel()

		return rdb.WithContext(oneCtx).Model(&model.TensorConfig{}).Where("k in (?) AND status = ?", keys, 0).Find(&configs).Error
	})

	if err != nil {
		return nil, err
	}

	return configs, nil
}
