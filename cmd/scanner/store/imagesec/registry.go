package imagesecStore

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts/preConsts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type SyncTaskDal interface {
	SearchSyncTask(ctx context.Context, param imagesecModel.SearchSyncTaskParam) ([]imagesecModel.ImageSyncTask, error)
	CreateSyncTask(ctx context.Context, task *imagesecModel.ImageSyncTask) error
	UpdateSyncTask(ctx context.Context, where string, updater map[string]interface{}) error
}

type SyncTaskDao struct {
	db *databases.RDBInstance
}

func NewSyncTaskDao(db *databases.RDBInstance) *SyncTaskDao {
	return &SyncTaskDao{db: db}
}

func (dal *SyncTaskDao) SearchSyncTask(ctx context.Context, param imagesecModel.SearchSyncTaskParam) ([]imagesecModel.ImageSyncTask, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(imagesecModel.ImageSyncTask{})
	if len(param.RegIds) > 0 {
		db = db.Where("registry_id IN  ? ", param.RegIds)
	}
	if param.Finished == consts.TrueString {
		db = db.Where("finish_at > ?", 0)
	}
	if param.TaskID > 0 {
		db = db.Where("id = ?", param.TaskID)
	}
	if param.Finished == consts.FalseString {
		db = db.Where("finish_at = ?", 0)
	}
	if param.SyncType != "" {
		db = db.Where("sync_type = ?", param.SyncType)
	}

	db = imagesecModel.AddFilter(db, param.Filter)

	res := make([]imagesecModel.ImageSyncTask, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, err
	}
	return res, nil
}

func (dal *SyncTaskDao) CreateSyncTask(ctx context.Context, task *imagesecModel.ImageSyncTask) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(&imagesecModel.ImageSyncTask{})
	return db.Create(task).Error
}

func (dal *SyncTaskDao) UpdateSyncTask(ctx context.Context, where string, updater map[string]interface{}) error {
	ctx2, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx2).Model(&imagesecModel.ImageSyncTask{})
	if where == "" {
		return fmt.Errorf("no where")
	}
	db = db.Where(where)

	if err := db.Updates(updater).Error; err != nil {
		return err
	}
	return nil
}

type RegistryDal interface {
	CreateRegistry(ctx context.Context, reg *imagesecModel.Registry) error
	UpdateRegistry(ctx context.Context, param imagesecModel.SearchRegistryParam, updater map[string]interface{}) error
	DeleteRegistry(ctx context.Context, id int64) error
	SearchRegistry(ctx context.Context, param imagesecModel.SearchRegistryParam) ([]imagesecModel.Registry, int64, error)
}

type RegistryDao struct {
	db *databases.RDBInstance
}

func NewRegistryDao(db *databases.RDBInstance) *RegistryDao {
	return &RegistryDao{db: db}
}

func (dal *RegistryDao) SearchRegistry(ctx context.Context, param imagesecModel.SearchRegistryParam) ([]imagesecModel.Registry, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(imagesecModel.Registry{})
	if param.Deleted == consts.TrueString {
		db = db.Where("deleted_at > 0")
	} else if param.Deleted == consts.FalseString {
		db = db.Where("deleted_at = 0")
	}
	if len(param.Status) > 0 {
		db = db.Where("status IN ?", param.Status)
	}
	if param.ScannerInstance != "" {
		db = db.Where("scanner_instance = ?", param.ScannerInstance)
	}
	if param.ID > 0 {
		db = db.Where("id = ?", param.ID)
	}
	// 默认查询没有删除的,如果不传就是0
	if len(param.RegIds) > 0 {
		db = db.Where("id IN ? ", param.RegIds)
	}
	if param.LibraryURL != "" {
		db = db.Where("url = ? ", param.LibraryURL)
	}
	if param.Name != "" {
		db = db.Where("name = ? ", param.Name)
	}

	if param.NameKeyword != "" {
		db = db.Where("name LIKE ?  ", fmt.Sprintf("%%%s%%", param.NameKeyword))
	}
	if param.UrlKeyword != "" {
		db = db.Where("url LIKE ? ", fmt.Sprintf("%%%s%%", param.UrlKeyword))
	}
	if param.StartSyncAt > 0 {
		db = db.Where("last_sync_at >= ? ", param.StartSyncAt)
	}
	if param.EndSyncAt > 0 {
		db = db.Where("last_sync_at <= ? ", param.EndSyncAt)
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
	db = imagesecModel.AddFilter(db, param.Filter)

	res := make([]imagesecModel.Registry, 0)
	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	for i := range res {
		decryPass, err := util.DesDecrypt(res[i].Password, []byte(preConsts.EncryptPasswordKey))
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

func (dal *RegistryDao) CreateRegistry(ctx context.Context, reg *imagesecModel.Registry) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	encryPass, err := util.DesEncrypt([]byte(reg.PasswordString), []byte(preConsts.EncryptPasswordKey))
	if err != nil {
		return err
	}
	reg.Password = encryPass
	if err := dal.db.Get().WithContext(ctx).Model(imagesecModel.Registry{}).Create(&reg).Error; err != nil {
		return err
	}
	return nil
}

func (dal *RegistryDao) UpdateRegistry(ctx context.Context, param imagesecModel.SearchRegistryParam, updater map[string]interface{}) error {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*1)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(imagesecModel.Registry{})
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

func (dal *RegistryDao) DeleteRegistry(ctx context.Context, id int64) error {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	m := imagesecModel.Registry{}
	db := dal.db.Get().WithContext(cancelCtx).Table(m.TableName()).Where("id = ?", id)
	return db.Delete(&m).Error
}
