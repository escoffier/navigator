package imagesec

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type ScanVersionDal interface {
	// 创建
	CreateMalwareVersion(ctx context.Context, data *imagesec.MalwareVersion) error
	CreateWebshellVersion(ctx context.Context, data *imagesec.WebshellVersion) error
	CreateSensitiveVersion(ctx context.Context, data *imagesec.SensitiveVersion) error
	CreateVulnVersion(ctx context.Context, data *imagesec.VulnVersion) error

	// 更新
	UpdateMalwareVersion(ctx context.Context, param imagesec.UpdateScanVersionParam) error
	UpdateWebshellVersion(ctx context.Context, param imagesec.UpdateScanVersionParam) error
	UpdateSensitiveVersion(ctx context.Context, param imagesec.UpdateScanVersionParam) error
	UpdateVulnVersion(ctx context.Context, param imagesec.UpdateScanVersionParam) error

	// 查找
	SearchMalwareVersion(ctx context.Context, param imagesec.SearchScanVersionParam) ([]*imagesec.MalwareVersion, int64, error)
	SearchWebshellVersion(ctx context.Context, param imagesec.SearchScanVersionParam) ([]*imagesec.WebshellVersion, int64, error)
	SearchSensitiveVersion(ctx context.Context, param imagesec.SearchScanVersionParam) ([]*imagesec.SensitiveVersion, int64, error)
	SearchVulnVersion(ctx context.Context, param imagesec.SearchScanVersionParam) ([]*imagesec.VulnVersion, int64, error)
}

type ScanVersionDao struct {
	db *databases.RDBInstance
}

func NewScanVersionDao(db *databases.RDBInstance) *ScanVersionDao {
	return &ScanVersionDao{db: db}
}

func (dal *ScanVersionDao) CreateMalwareVersion(ctx context.Context, data *imagesec.MalwareVersion) error {
	if err := data.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	version, _, err := dal.SearchMalwareVersion(ctx, imagesec.SearchScanVersionParam{UniqueID: data.UniqueID})
	if err != nil {
		return err
	}
	if len(version) > 0 {
		return nil
	}

	return dal.db.Get().WithContext(cancelCtx).Table(data.TableName()).Create(data).Error
}

func (dal *ScanVersionDao) CreateWebshellVersion(ctx context.Context, data *imagesec.WebshellVersion) error {
	if err := data.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	versions, _, err := dal.SearchWebshellVersion(ctx, imagesec.SearchScanVersionParam{UniqueID: data.UniqueID})
	if err != nil {
		return err
	}
	if len(versions) > 0 {
		return nil
	}
	return dal.db.Get().WithContext(cancelCtx).Table(data.TableName()).Create(data).Error
}

func (dal *ScanVersionDao) CreateSensitiveVersion(ctx context.Context, data *imagesec.SensitiveVersion) error {
	if err := data.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	version, _, err := dal.SearchSensitiveVersion(ctx, imagesec.SearchScanVersionParam{UniqueID: data.UniqueID})
	if err != nil {
		return err
	}
	if len(version) > 0 {
		return nil
	}
	return dal.db.Get().WithContext(cancelCtx).Table(data.TableName()).Create(data).Error
}

func (dal *ScanVersionDao) CreateVulnVersion(ctx context.Context, data *imagesec.VulnVersion) error {
	if err := data.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	version, _, err := dal.SearchVulnVersion(ctx, imagesec.SearchScanVersionParam{UniqueID: data.UniqueID})
	if err != nil {
		return err
	}
	if len(version) > 0 {
		return nil
	}
	return dal.db.Get().WithContext(cancelCtx).Table(data.TableName()).Create(data).Error
}

func (dal *ScanVersionDao) UpdateMalwareVersion(ctx context.Context, param imagesec.UpdateScanVersionParam) error {
	if err := param.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesec.MalwareVersion).TableName())
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	if param.UniqueID > 0 {
		db = db.Where("unique_id = ?", param.UniqueID)
	}
	return db.Updates(param.Updater).Error
}

func (dal *ScanVersionDao) UpdateWebshellVersion(ctx context.Context, param imagesec.UpdateScanVersionParam) error {
	if err := param.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesec.WebshellVersion).TableName())
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	if param.UniqueID > 0 {
		db = db.Where("unique_id = ?", param.UniqueID)
	}
	return db.Updates(param.Updater).Error
}

func (dal *ScanVersionDao) UpdateSensitiveVersion(ctx context.Context, param imagesec.UpdateScanVersionParam) error {
	if err := param.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesec.SensitiveVersion).TableName())
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	if param.UniqueID > 0 {
		db = db.Where("unique_id = ?", param.UniqueID)
	}
	return db.Updates(param.Updater).Error
}

func (dal *ScanVersionDao) UpdateVulnVersion(ctx context.Context, param imagesec.UpdateScanVersionParam) error {
	if err := param.Check(); err != nil {
		return err
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesec.VulnVersion).TableName())
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	if param.UniqueID > 0 {
		db = db.Where("unique_id = ?", param.UniqueID)
	}
	return db.Updates(param.Updater).Error
}

func (dal *ScanVersionDao) SearchMalwareVersion(ctx context.Context, param imagesec.SearchScanVersionParam) (
	[]*imagesec.MalwareVersion, int64, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesec.MalwareVersion).TableName())
	if param.Keyword != "" {
		db = db.Where("engine_version LIKE ?  OR db_version LIKE ? ", fmt.Sprintf("%%%s%%", param.Keyword),
			fmt.Sprintf("%%%s%%", param.Keyword))
	}
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
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
	res := make([]*imagesec.MalwareVersion, 0)
	db = model.AddFilter(db, param.Filter)
	err := db.Find(&res).Error
	return res, cnt, err
}

func (dal *ScanVersionDao) SearchWebshellVersion(ctx context.Context, param imagesec.SearchScanVersionParam) (
	[]*imagesec.WebshellVersion, int64, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesec.WebshellVersion).TableName())
	if param.Keyword != "" {
		db = db.Where("engine_version LIKE ?  OR db_version LIKE ? ", fmt.Sprintf("%%%s%%", param.Keyword),
			fmt.Sprintf("%%%s%%", param.Keyword))
	}
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
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
	res := make([]*imagesec.WebshellVersion, 0)
	db = model.AddFilter(db, param.Filter)
	err := db.Find(&res).Error
	return res, cnt, err
}

func (dal *ScanVersionDao) SearchSensitiveVersion(ctx context.Context, param imagesec.SearchScanVersionParam) (
	[]*imagesec.SensitiveVersion, int64, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesec.SensitiveVersion).TableName())
	if param.Keyword != "" {
		db = db.Where("engine_version LIKE ?  OR db_version LIKE ? ", fmt.Sprintf("%%%s%%", param.Keyword),
			fmt.Sprintf("%%%s%%", param.Keyword))
	}
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
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
	res := make([]*imagesec.SensitiveVersion, 0)
	db = model.AddFilter(db, param.Filter)
	err := db.Find(&res).Error
	return res, cnt, err
}

func (dal *ScanVersionDao) SearchVulnVersion(ctx context.Context, param imagesec.SearchScanVersionParam) (
	[]*imagesec.VulnVersion, int64, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesec.VulnVersion).TableName())
	if param.Keyword != "" {
		db = db.Where("engine_version LIKE ?  OR db_version LIKE ? ", fmt.Sprintf("%%%s%%", param.Keyword),
			fmt.Sprintf("%%%s%%", param.Keyword))
	}
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
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
	res := make([]*imagesec.VulnVersion, 0)
	db = model.AddFilter(db, param.Filter)
	err := db.Find(&res).Error
	return res, cnt, err
}
