package imagesecStore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ScanDbMetaDal interface {
	CreateScanDbMeta(ctx context.Context, data *imagesecModel.ScanConfigDB) error
	SearchScanDbMeta(ctx context.Context, param imagesecModel.SearchScanDbParam) ([]*imagesecModel.ScanConfigDB, int64, error)
	GetLastDBVersion(ctx context.Context) (imagesecModel.LastDB, error)
	UpdateScanDbMeta(ctx context.Context, id int64, updater map[string]interface{}) error
}

type ScanDbMetaDao struct {
	db *databases.RDBInstance
}

func NewScanDbMetaDao(db *databases.RDBInstance) *ScanDbMetaDao {
	return &ScanDbMetaDao{db: db}
}

func (dal *ScanDbMetaDao) CreateScanDbMeta(ctx context.Context, data *imagesecModel.ScanConfigDB) error {
	data.Serialize()
	if err := data.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	db := dal.db.Get().WithContext(cancelCtx).Table(data.TableName())
	if err := db.Create(data).Error; err != nil {
		if strings.Contains(err.Error(), consts.DuplicateKey) {
			return nil
		}
		return err
	}
	return nil
}

func (dal *ScanDbMetaDao) UpdateScanDbMeta(ctx context.Context, id int64, updater map[string]interface{}) error {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesecModel.ScanConfigDB).TableName())

	return db.Where("id = ?", id).Updates(updater).Error
}

func (dal *ScanDbMetaDao) SearchScanDbMeta(ctx context.Context, param imagesecModel.SearchScanDbParam) (
	[]*imagesecModel.ScanConfigDB, int64, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesecModel.ScanConfigDB).TableName())
	if param.Keyword != "" {
		db = db.Where("db_version LIKE ? ", fmt.Sprintf("%%%s%%", param.Keyword))
	}
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	if param.DBVersion != "" {
		db = db.Where("db_version = ? ", param.DBVersion)
	}
	if param.DBType != "" {
		db = db.Where("db_type = ?", param.DBType)
	}
	if param.UniqueID > 0 {
		db = db.Where("unique_id = ?", param.UniqueID)
	}
	// 先查总数
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	res := make([]*imagesecModel.ScanConfigDB, 0)
	db = imagesecModel.AddFilter(db, param.Filter)
	err := db.Find(&res).Error
	return res, cnt, err
}

func (dal *ScanDbMetaDao) GetLastDBVersion(ctx context.Context) (imagesecModel.LastDB, error) {
	res := imagesecModel.LastDB{}
	last, err := dal.getLast(ctx, imagesecModel.DBMetaTypeVuln)
	if err != nil {
		return imagesecModel.LastDB{}, err
	}
	res.VulnDb = last

	last, err = dal.getLast(ctx, imagesecModel.DBMetaTypeWebshell)
	if err != nil {
		return imagesecModel.LastDB{}, err
	}
	res.WebshellDB = last

	last, err = dal.getLast(ctx, imagesecModel.DBMetaTypeClamav)
	if err != nil {
		return imagesecModel.LastDB{}, err
	}
	res.ClamavDB = last

	last, err = dal.getLast(ctx, imagesecModel.DBMetaTypeAvira)
	if err != nil {
		return imagesecModel.LastDB{}, err
	}
	res.AviraDB = last

	return res, nil

}

func (dal *ScanDbMetaDao) getLast(ctx context.Context, col string) (imagesecModel.ScanConfigDB, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesecModel.ScanConfigDB).TableName()).Where("db_type = ?", col)

	filter := imagesecModel.EmptyFilter().SetSortFiled("id").SetSortDesc().SetLimit(1)

	db = imagesecModel.AddFilter(db, filter)

	res := make([]imagesecModel.ScanConfigDB, 0)

	err := db.Find(&res).Error
	if err != nil {
		return imagesecModel.ScanConfigDB{}, err
	}
	if len(res) == 0 {
		return imagesecModel.ScanConfigDB{}, nil
	}
	for i := range res {
		res[i].Deserialize()
	}
	return res[0], nil
}
