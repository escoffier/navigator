package imagesec

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ScanDbMetaDal interface {
	CreateScanDbMeta(ctx context.Context, data *imagesecModel.ScanDbMeta) error
	SearchScanDbMeta(ctx context.Context, param imagesecModel.SearchScanDbMetaParam) ([]*imagesecModel.ScanDbMeta, int64, error)
}

type ScanDbMetaDao struct {
	db *databases.RDBInstance
}

func NewScanDbMetaDao(db *databases.RDBInstance) *ScanDbMetaDao {
	return &ScanDbMetaDao{db: db}
}

func (dal *ScanDbMetaDao) CreateScanDbMeta(ctx context.Context, data *imagesecModel.ScanDbMeta) error {
	data.Serialize()
	if err := data.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	pre := make([]*imagesecModel.ScanDbMeta, 0)
	if err := dal.db.Get().WithContext(cancelCtx).Table(data.TableName()).
		Where("unique_id = ?", data.UniqueID).Find(&pre).Error; err != nil {
		return err
	}

	if len(pre) > 0 {
		if data.Same(pre[0]) {
			return nil
		}
		if err := dal.db.Get().WithContext(cancelCtx).Table(data.TableName()).
			Where("unique_id = ?", pre[0].UniqueID).Delete(pre[0]).Error; err != nil {
			return err
		}
	}
	db := dal.db.Get().WithContext(cancelCtx).Table(data.TableName())
	if err := db.Create(data).Error; err != nil {
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			return nil
		}
		return err
	}
	return nil
}

func (dal *ScanDbMetaDao) SearchScanDbMeta(ctx context.Context, param imagesecModel.SearchScanDbMetaParam) (
	[]*imagesecModel.ScanDbMeta, int64, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesecModel.ScanDbMeta).TableName())
	if param.Keyword != "" {
		db = db.Where("db_version LIKE ? ", fmt.Sprintf("%%%s%%", param.Keyword))
	}
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	if param.DBType != "" {
		db = db.Where("db_type = ?", param.DBType)
	}
	if param.UniqueID > 0 {
		db = db.Where("unique_id = ?", param.UniqueID)
	}
	if param.Enable == consts.TrueString {
		db = db.Where("enable = ?", true)
	} else if param.Enable == consts.FalseString {
		db = db.Where("enable = ?", false)
	}
	// 先查总数
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	res := make([]*imagesecModel.ScanDbMeta, 0)
	db = model.AddFilter(db, param.Filter)
	err := db.Find(&res).Error
	return res, cnt, err
}
