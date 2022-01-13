package store

import (
	"context"
	"time"

	"gitlab.com/piccolo_su/vegeta/cmd/scanner/consts"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
	"gitlab.com/piccolo_su/vegeta/pkg/rdbtools"
)

type ScanConfigDalInterface interface {
	CreateStrategy(ctx context.Context, data *model.ScanStrategy) error
	SearchStrategy(ctx context.Context, parm SearchStrategyParam, filter *model.Filter) ([]model.ScanStrategy, int64, error)
	CreateScanConfig(ctx context.Context, data *model.ScanConfig) error
	SearchScanConfig(ctx context.Context, param SearchScanConfigParam, filter *model.Filter) ([]model.ScanConfig, int64, error)
	UpdateStrategy(ctx context.Context, param SearchStrategyParam, updater map[string]interface{}) error
	DeleteStrategy(ctx context.Context, strategyId int64) error
	UpdateScanConfig(ctx context.Context, configID int64, updater map[string]interface{}) error
	GetAllNodes(ctx context.Context) ([]string, error)
	GetAllProject(ctx context.Context) ([]string, error)
	GetAllRepoName(ctx context.Context) ([]string, error)
}

type ScanConfigDao struct {
	db *rdbtools.GormWrapper
}

func (s *ScanConfigDao) GetAllNodes(ctx context.Context) ([]string, error) {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()
	db := s.db.Get().WithContext(timeoutCtx).Model(new(model.ImageList))
	res := make([]model.ImageList, 0)

	err := db.Distinct("node_hostname").Find(&res).Error
	if err != nil {
		return nil, err
	}
	ans := make([]string, 0)
	for i := range res {
		if res[i].NodeHostname != "" {
			ans = append(ans, res[i].NodeHostname)
		}
	}
	return ans, nil
}
func (s *ScanConfigDao) GetAllProject(ctx context.Context) ([]string, error) {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()
	db := s.db.Get().WithContext(timeoutCtx).Model(new(model.ImageList))
	res := make([]model.ImageList, 0)

	err := db.Distinct("project").Find(&res).Error
	if err != nil {
		return nil, err
	}
	ans := make([]string, 0)
	for i := range res {
		if res[i].Project != "" {
			ans = append(ans, res[i].Project)
		}
	}
	return ans, nil
}
func (s *ScanConfigDao) GetAllRepoName(ctx context.Context) ([]string, error) {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()
	db := s.db.Get().WithContext(timeoutCtx).Model(new(model.ImageList))
	res := make([]model.ImageList, 0)

	err := db.Distinct("repo_name").Find(&res).Error
	if err != nil {
		return nil, err
	}
	ans := make([]string, 0)
	for i := range res {
		if res[i].RepoName != "" {
			ans = append(ans, res[i].RepoName)
		}
	}
	return ans, nil
}

func (s *ScanConfigDao) SearchScanConfig(ctx context.Context, param SearchScanConfigParam, filter *model.Filter) ([]model.ScanConfig, int64, error) {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()
	db := s.db.Get().WithContext(timeoutCtx).Model(new(model.ScanConfig))

	if param.ScanConfigID > 0 {
		db.Where("id = ?", param.ScanConfigID)
	}

	res := make([]model.ScanConfig, 0)
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}

	db = model.AddFilter(db, filter)
	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	for i := range res {
		res[i] = *res[i].Deserialize()
	}

	return res, cnt, nil
}

func (s *ScanConfigDao) SearchStrategy(ctx context.Context, parm SearchStrategyParam, filter *model.Filter) ([]model.ScanStrategy, int64, error) {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()
	db := s.db.Get().WithContext(timeoutCtx).Model(new(model.ScanStrategy))
	if parm.IsDefault == consts.TrueString {
		db.Where("is_default = ?", true)
	}
	if parm.IsDefault == consts.FalseString {
		db.Where("is_default = ?", false)
	}
	if parm.StrategyID > 0 {
		db.Where("id = ? ", parm.StrategyID)
	}
	if parm.Name != "" {
		db.Where("name = ? ", parm.Name)
	}

	res := make([]model.ScanStrategy, 0)
	var cnt int64
	if err := db.Count(&cnt).Error; err != nil {
		return nil, 0, err
	}

	db = model.AddFilter(db, filter)
	if err := db.Find(&res).Error; err != nil {
		return nil, 0, err
	}
	for i := range res {
		res[i] = *res[i].Deserialize()
	}

	return res, cnt, nil
}

func (s *ScanConfigDao) CreateScanConfig(ctx context.Context, data *model.ScanConfig) error {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()
	return s.db.Get().WithContext(timeoutCtx).Model(new(model.ScanConfig)).Create(data).Error
}

func (s *ScanConfigDao) CreateStrategy(ctx context.Context, data *model.ScanStrategy) error {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()
	db := s.db.Get().WithContext(timeoutCtx)
	if err := db.Model(new(model.ScanStrategy)).Create(data).Error; err != nil {
		return err
	}
	return nil
}

func (s *ScanConfigDao) UpdateStrategy(ctx context.Context, parm SearchStrategyParam, updater map[string]interface{}) error {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()
	db := s.db.Get().WithContext(timeoutCtx).Model(new(model.ScanStrategy))
	if parm.IsDefault == consts.TrueString {
		db = db.Where("is_default = ? ", true)
	} else if parm.IsDefault == consts.FalseString {
		db = db.Where("is_default = ? ", false)
	}
	err := db.Where("id = ?", parm.StrategyID).Updates(updater).Error
	return err
}

func (s *ScanConfigDao) DeleteStrategy(ctx context.Context, strategyId int64) error {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()
	db := s.db.Get().WithContext(timeoutCtx)
	err := db.Model(new(model.ScanStrategy)).Where("id = ?", strategyId).Delete(&model.ScanStrategy{}).Error
	return err
}

func (s *ScanConfigDao) UpdateScanConfig(ctx context.Context, configID int64, updater map[string]interface{}) error {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()
	db := s.db.Get().WithContext(timeoutCtx)
	err := db.Model(new(model.ScanConfig)).Where("id = ?", configID).Updates(updater).Error
	return err
}

func NewScanConfigDao(db *rdbtools.GormWrapper) *ScanConfigDao {
	return &ScanConfigDao{db: db}
}
