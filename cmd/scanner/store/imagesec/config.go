package imagesec

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/security-rd/go-pkg/databases"

	"gitlab.com/piccolo_su/vegeta/pkg/model"
	imagesecModel "gitlab.com/piccolo_su/vegeta/pkg/model/imagesec"
)

type SensitiveRuleDal interface {
	CreateSensitiveRule(ctx context.Context, data *imagesecModel.SensitiveRule) error
	SearchSensitiveRule(ctx context.Context, filter *model.Filter) ([]*imagesecModel.SensitiveRule, error)
	UpdateSensitiveRule(ctx context.Context, id int64, updater map[string]interface{}) error
	DeleteSensitiveRule(ctx context.Context, id int64) error
}

type SensitiveRuleDao struct {
	db *databases.RDBInstance
}

func NewSensitiveRuleDao(db *databases.RDBInstance) *SensitiveRuleDao {
	return &SensitiveRuleDao{db: db}
}

func (dal *SensitiveRuleDao) CreateSensitiveRule(ctx context.Context, data *imagesecModel.SensitiveRule) error {
	if err := data.Check(); err != nil {
		return err
	}

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	return dal.db.Get().WithContext(cancelCtx).Table(data.TableName()).Create(data).Error
}

func (dal *SensitiveRuleDao) SearchSensitiveRule(ctx context.Context, filter *model.Filter) ([]*imagesecModel.SensitiveRule, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	res := make([]*imagesecModel.SensitiveRule, 0)

	db := dal.db.Get().WithContext(cancelCtx).Table(new(imagesecModel.SensitiveRule).TableName())
	db = model.AddFilter(db, filter)
	err := db.Find(&res).Error

	return res, err
}

func (dal *SensitiveRuleDao) UpdateSensitiveRule(ctx context.Context, id int64, updater map[string]interface{}) error {
	if id <= 0 || len(updater) == 0 {
		return fmt.Errorf("not get id or updater")
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	pre := &imagesecModel.SensitiveRule{}
	tb := pre.TableName()
	if err := dal.db.Get().WithContext(cancelCtx).Table(tb).Where("id = ?", id).First(pre).Error; err != nil {
		return err
	}
	if pre.IsDefault {
		enable, ok := updater["enable"]
		if ok {
			updater = map[string]interface{}{"enable": enable}
		} else {
			return fmt.Errorf("update default rule is not permitted")
		}
	}

	return dal.db.Get().WithContext(cancelCtx).Table(tb).Where("id = ?", id).Updates(updater).Error
}

func (dal *SensitiveRuleDao) DeleteSensitiveRule(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("not get id")
	}
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	pre := &imagesecModel.SensitiveRule{}
	tb := pre.TableName()
	if err := dal.db.Get().WithContext(cancelCtx).Table(tb).Where("id = ?", id).First(pre).Error; err != nil {
		return err
	}
	if pre.IsDefault {
		return fmt.Errorf("delete default rule is not permitted")
	}

	db := dal.db.Get().WithContext(cancelCtx).Table(tb).Where("id = ?", id)
	return db.Delete(&imagesecModel.SensitiveRule{}).Error
}

type ScanImageConfigDal interface {
	CreateScanImageConfig(ctx context.Context, data *imagesecModel.ScanImageConfig) error
	GetScanImageConfig(ctx context.Context, configType string) (*imagesecModel.ScanImageConfig, error)
	UpdateScanImageConfig(ctx context.Context, id int64, data *imagesecModel.ScanImageConfig) error
}

type ScanImageConfigDao struct {
	db *databases.RDBInstance
}

func (dal *ScanImageConfigDao) CreateScanImageConfig(ctx context.Context, data *imagesecModel.ScanImageConfig) error {
	if err := data.Check(); err != nil {
		return err
	}
	data.Serialize()

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	return dal.db.Get().WithContext(cancelCtx).Table(data.TableName()).Create(data).Error
}

func (dal *ScanImageConfigDao) GetScanImageConfig(ctx context.Context, configType string) (*imagesecModel.ScanImageConfig, error) {
	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()
	configType = strings.TrimSpace(configType)
	m := imagesecModel.ScanImageConfig{}
	err := dal.db.Get().WithContext(cancelCtx).Table(m.TableName()).Where("config_type = ?", configType).First(&m).Error
	if err != nil {
		return nil, err
	}
	m.Deserialize()
	return &m, nil
}

func (dal *ScanImageConfigDao) UpdateScanImageConfig(ctx context.Context, id int64, data *imagesecModel.ScanImageConfig) error {
	if id <= 0 {
		return fmt.Errorf("not get id")
	}
	if err := data.Check(); err != nil {
		return err
	}
	data.Serialize()

	cancelCtx, cancelFunc := context.WithTimeout(ctx, time.Second*3)
	defer cancelFunc()
	pre := &imagesecModel.ScanImageConfig{}
	tb := pre.TableName()
	if err := dal.db.Get().WithContext(cancelCtx).Table(tb).Where("id = ?", id).First(pre).Error; err != nil {
		return err
	}
	if pre.ConfigType != data.ConfigType {
		return fmt.Errorf("config type is not correct")
	}

	updater := data.ToUpdater()

	return dal.db.Get().WithContext(cancelCtx).Table(tb).Where("id = ?", id).Updates(updater).Error
}

func NewScannerConfigDao(db *databases.RDBInstance) *ScanImageConfigDao {
	return &ScanImageConfigDao{db: db}
}
