package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gorm.io/gorm"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type RegistryDal interface {
	CreateRegistry(ctx context.Context, reg model.Registry) (int64, error)
	UpdateRegistry(ctx context.Context, param SearchRegistryParam, updater map[string]interface{}) error
	SearchRegistry(ctx context.Context, param SearchRegistryParam, filter *model.Filter) ([]model.Registry, int64, error)
}

type SyncRetryImageDal interface {
	SearchImageRetry(ctx context.Context, param SearchImageRetryParam) ([]model.SyncRetryImage, error)
	CreateImageRetry(ctx context.Context, image model.SyncRetryImage) error
	AddRetryCount(ctx context.Context, uniqueImage uint64) error
	DeleteImageRetry(ctx context.Context, param SearchImageRetryParam) error
}

type SyncTaskDal interface {
	SearchSyncTask(ctx context.Context, param SearchSyncTaskParam, filter *model.Filter) ([]model.SyncTask, error)
	CreateSyncTask(ctx context.Context, task *model.SyncTask) error
	UpdateSyncTask(ctx context.Context, where string, updater map[string]interface{}) error
}

type RegistryDao struct {
	db *databases.RDBInstance
}

type SyncTaskDao struct {
	db *databases.RDBInstance
}

func (dal *SyncTaskDao) SearchSyncTask(ctx context.Context, param SearchSyncTaskParam, filter *model.Filter) ([]model.SyncTask, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(model.SyncTask{})
	if len(param.RegIds) > 0 {
		db = db.Where("registry_id IN  ? ", param.RegIds)
	}
	if param.Finished == consts.TrueString {
		db = db.Where("finish_at > ?", 0)
	}
	if param.Finished == consts.FalseString {
		db = db.Where("finish_at = ?", 0)
	}
	if param.SyncType != "" {
		db = db.Where("sync_type = ?", param.SyncType)
	}

	db = model.AddFilter(db, filter)

	res := make([]model.SyncTask, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	return res, nil
}

func (dal *SyncTaskDao) CreateSyncTask(ctx context.Context, task *model.SyncTask) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(&model.SyncTask{})
	return db.Create(task).Error
}

func (dal *SyncTaskDao) UpdateSyncTask(ctx context.Context, where string, updater map[string]interface{}) error {
	ctx2, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx2).Model(&model.SyncTask{})
	if where == "" {
		return fmt.Errorf("no where")
	}
	db = db.Where(where)

	if err := db.Updates(updater).Error; err != nil {
		return err
	}
	return nil
}

type SyncRetryImageDao struct {
	db *databases.RDBInstance
}

func (dal *SyncRetryImageDao) AddRetryCount(ctx context.Context, uniqueImage uint64) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(new(model.SyncRetryImage))
	return db.Where("unique_image = ? ", uniqueImage).Update("retry_count", gorm.Expr("retry_count + ?", 1)).Error
}

func (dal *SyncRetryImageDao) DeleteImageRetry(ctx context.Context, param SearchImageRetryParam) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)

	defer cancelFunc()

	db := dal.db.Get().WithContext(ctx).Model(new(model.SyncRetryImage))
	db.Where("retry_count > ?", param.MoreRetryCount)
	if param.UniqueImage > 0 {
		db.Where("unique_image = ?", param.UniqueImage)
	}
	return db.Delete(model.SyncRetryImage{}).Error
}

func NewSyncRetryImageDao(db *databases.RDBInstance) *SyncRetryImageDao {
	return &SyncRetryImageDao{db: db}
}

func NewRegistryDao(db *databases.RDBInstance) *RegistryDao {
	return &RegistryDao{db: db}
}

func NewSyncTaskDao(db *databases.RDBInstance) *SyncTaskDao {
	return &SyncTaskDao{db: db}
}

func (dal *SyncRetryImageDao) CreateImageRetry(ctx context.Context, image model.SyncRetryImage) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(new(model.SyncRetryImage))
	return db.Create(&image).Error
}

func (dal *SyncRetryImageDao) SearchImageRetry(ctx context.Context, param SearchImageRetryParam) ([]model.SyncRetryImage, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)

	defer cancelFunc()

	res := make([]model.SyncRetryImage, 0)
	db := dal.db.Get().WithContext(ctx).Model(new(model.SyncRetryImage))
	if param.MoreRetryCount > 0 {
		db.Where("retry_count > ?", param.MoreRetryCount)
	}
	if param.LessRetryCount > 0 {
		db.Where("retry_count <= ?", param.LessRetryCount)
	}
	if param.UniqueImage > 0 {
		db.Where("unique_image = ?", param.UniqueImage)
	}

	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	return res, nil
}

func (dal *RegistryDao) SearchRegistry(ctx context.Context, param SearchRegistryParam, filter *model.Filter) ([]model.Registry, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(model.Registry{})
	if param.NoDelete {
		db = db.Where("deleted_at = ?", 0)
	}
	if param.ScannerInstance != "" {
		db = db.Where("scanner_instance = ?", param.ScannerInstance)
	}
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	// 默认查询没有删除的,如果不传就是0
	if len(param.RegistryIds) > 0 {
		db = db.Where("id IN ? ", param.RegistryIds)
	}
	if param.LibraryURL != "" {
		db = db.Where("url = ? ", param.LibraryURL)
	}
	if param.Name != "" {
		db = db.Where("name = ? ", param.Name)
	}
	if param.UseType > 0 {
		db = db.Where("use_type = ? ", param.UseType)
	}
	if len(param.UseTypes) > 0 {
		db = db.Where("use_type In ? ", param.UseTypes)
	}
	if param.Search != "" {
		db = db.Where("name LIKE ? OR url LIKE ? ", fmt.Sprintf("%%%s%%", param.Search), fmt.Sprintf("%%%s%%", param.Search))
	}
	if len(param.RegType) > 0 {
		db = db.Where("reg_type IN  ? ", param.RegType)
	}
	if len(param.Fields) > 0 {
		db = db.Select(param.Fields)
	}

	// 先查总数
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}
	db = model.AddFilter(db, filter)

	res := make([]model.Registry, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	for i := range res {
		decryPass, err := util.DesDecrypt(res[i].Password, []byte(consts.EncryptPasswordKey))
		if err == nil {
			res[i].PasswordString = string(decryPass)
			tmpStr := res[i].Username + ":" + string(decryPass)
			authByte := []byte(tmpStr)
			encodeStr := base64.StdEncoding.EncodeToString(authByte)
			res[i].AuthStr = "Basic " + encodeStr
		} else {
			logging.GetLogger().Err(err).Msg("SearchRegistry NewChiper Error")
		}
	}
	return res, cnt, nil
}

func (dal *RegistryDao) CreateRegistry(ctx context.Context, reg model.Registry) (int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	encryPass, err := util.DesEncrypt([]byte(reg.PasswordString), []byte(consts.EncryptPasswordKey))
	if err != nil {
		return 0, err
	}
	reg.Password = encryPass
	if err := dal.db.Get().WithContext(ctx).Model(model.Registry{}).Create(&reg).Error; err != nil {
		return 0, err
	}
	return reg.ID, nil
}

func (dal *RegistryDao) UpdateRegistry(ctx context.Context, param SearchRegistryParam, updater map[string]interface{}) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(model.Registry{})
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	} else {
		return errors.New("请指定要更新ID")
	}

	if err := db.Updates(updater).Error; err != nil {
		return err
	}
	return nil
}
