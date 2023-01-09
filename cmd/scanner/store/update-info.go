package store

import (
	"context"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"
	"gorm.io/gorm/clause"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

type ScannerInstanceInfoDal interface {
	CreateAndReplace(ctx context.Context, info model.ScannerInstanceInfo) (int64, error)
	SearchScannerInfo(ctx context.Context, param ScannerInstanceInfoDaoParam) ([]model.ScannerInstanceInfo, error)
}

type ScannerInstanceInfoDao struct {
	db *databases.RDBInstance
}

func (dal *ScannerInstanceInfoDao) SearchScannerInfo(ctx context.Context, param ScannerInstanceInfoDaoParam) ([]model.ScannerInstanceInfo, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(new(model.ScannerInstanceInfo))
	if param.ScannerInstance != "" {
		db = db.Where("scanner_instance = ?", param.ScannerInstance)
	}

	res := make([]model.ScannerInstanceInfo, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	return res, nil
}

func (dal *ScannerInstanceInfoDao) CreateAndReplace(ctx context.Context, info model.ScannerInstanceInfo) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(new(model.ScannerInstanceInfo))

	// 先查，有变动才更新，
	exist := make([]model.ScannerInstanceInfo, 0)
	if err := db.Where("scanner_instance = ?", info.ScannerInstance).Find(&exist).Error; err != nil {
		return 0, err
	}
	// 没有变动
	if len(exist) > 0 && info.Same(exist[0]) {
		// 更新心跳及scanner的版本号
		if err := dal.db.Get().WithContext(ctx).Model(new(model.ScannerInstanceInfo)).
			Where("scanner_instance = ?", info.ScannerInstance).Updates(info.ToHeartBeatAt()).Error; err != nil {
			return 0, err
		}
		return exist[0].ID, nil
	}

	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "scanner_instance"}},
		DoUpdates: clause.Assignments(info.ToUpdater()),
	}).Create(&info).Error; err != nil {
		return 0, err
	}

	return info.ID, nil
}

func NewScannerInstanceDao(db *databases.RDBInstance) *ScannerInstanceInfoDao {
	return &ScannerInstanceInfoDao{db: db}
}
