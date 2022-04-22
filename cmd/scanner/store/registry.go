package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/util"
)

type RegistryDalInterface interface {
	CreateRegistry(ctx context.Context, reg model.Registry) (int64, error)
	UpdateRegistry(ctx context.Context, param SearchRegistryParam, updater map[string]interface{}) error
	SearchRegistry(ctx context.Context, param SearchRegistryParam, filter *model.Filter) ([]model.Registry, int64, error)
	// SearchRegistry(ctx context.Context, param SearchRegistryParam, filter *model.Filter) ([]model.Registry, int64, error)
}

type RegistryDao struct {
	db *databases.RDBInstance
}

func NewRegistryDao(db *databases.RDBInstance) *RegistryDao {
	return &RegistryDao{db: db}
}

func (dal *RegistryDao) SearchRegistry(ctx context.Context, param SearchRegistryParam, filter *model.Filter) ([]model.Registry, int64, error) {
	ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	db := dal.db.Get().WithContext(ctx).Model(model.Registry{})
	if param.NoDelete {
		db = db.Where("deleted_at = ?", 0)
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
			logging.GetLogger().Error().Err(err).Msg("SearchRegistry NewChiper Error")
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
