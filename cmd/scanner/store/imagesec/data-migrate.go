package imagesecStore

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type DataMigrateDal interface {
	CreateDataMigrate(ctx context.Context, data *imagesecModel.DataMigrate) error
	SearchDataMigrate(ctx context.Context, param imagesecModel.SearchDataMigrateParam) ([]imagesecModel.DataMigrate, error)
	UpdateDataMigrate(ctx context.Context, id int64, updater map[string]interface{}) error
}

type DataMigrateDao struct {
	db *databases.RDBInstance
}

func (dal *DataMigrateDao) CreateDataMigrate(ctx context.Context, data *imagesecModel.DataMigrate) error {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	return dal.db.Get().WithContext(cancelCtx).Model(&imagesecModel.DataMigrate{}).Create(data).Error
}

func (dal *DataMigrateDao) SearchDataMigrate(ctx context.Context, param imagesecModel.SearchDataMigrateParam) ([]imagesecModel.DataMigrate, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := dal.db.Get().WithContext(cancelCtx).Model(&imagesecModel.DataMigrate{})

	if param.Model != "" {
		db = db.Where("model = ?", param.Model)
	}
	if param.SoftVersion != "" {
		db = db.Where("soft_version LIKE  ?", fmt.Sprintf("%%%s%%", param.SoftVersion))
	}
	param.Filter = param.Filter.SetMaxLimit(consts.DefaultMaxLimit)
	db = imagesecModel.AddFilter(db, param.Filter)
	ans := make([]imagesecModel.DataMigrate, 0)
	err := db.Find(&ans).Error
	return ans, err
}

func (dal *DataMigrateDao) UpdateDataMigrate(ctx context.Context, id int64, updater map[string]interface{}) error {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := dal.db.Get().WithContext(cancelCtx).Model(&imagesecModel.DataMigrate{})
	db = db.Where("id = ?", id)
	return db.Updates(updater).Error
}

func NewDataMigrateDao(db *databases.RDBInstance) *DataMigrateDao {
	return &DataMigrateDao{db: db}
}
