package store

import (
	"context"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type IdempotentDal interface {
	CreateIdempotent(ctx context.Context, data *model.Idempotent) error
	DeleteIdempotent(ctx context.Context, param SearchIdempotentParam) error
}

type IdempotentDao struct {
	db *databases.RDBInstance
}

func NewIdempotentDao(db *databases.RDBInstance) *IdempotentDao {
	return &IdempotentDao{db: db}
}

func (dal *IdempotentDao) DeleteIdempotent(ctx context.Context, param SearchIdempotentParam) error {
	if err := param.Valid(); err != nil {
		return err
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(&model.Idempotent{})
	db = db.Where("data_id = ?", param.TableId)
	db = db.Where("table_name = ?", param.TableNAME)
	err := db.Delete(&model.Idempotent{}).Error
	return err
}

func (dal *IdempotentDao) CreateIdempotent(ctx context.Context, data *model.Idempotent) error {
	if err := data.Valid(); err != nil {
		return err
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(model.Idempotent{})
	err := db.Create(data).Error
	return err
}
