package scap

import (
	"context"
	"fmt"

	"github.com/pkg/errors"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func (s *Service) RuleBatch(ctx context.Context, scapType, keyword string, limit, offset int) ([]model.PolicyDetailInfo, int64, error) {
	db := s.rdb.Get().WithContext(ctx).Model(&model.PolicyDetailInfo{}).Where("check_type = ?", scapType)
	if keyword != "" {
		cond := "%" + keyword + "%"
		db = db.Where("policy_id LIKE ? OR title_zh LIKE ?", cond, cond)
	}
	if scapType == "host" {
		db = db.Where("id >= 1000")
	} else if scapType == "docker" {
		db = db.Where("policy_id NOT IN ?", []string{"0.1.1", "0.2.1", "1.1"})
	}

	var count int64
	if err := db.Count(&count).Error; err != nil {
		logging.GetLogger().Err(err).Msg("count rules error")
		return nil, 0, errors.New("获取数量失败")
	}

	var v = make([]model.PolicyDetailInfo, 0, limit)

	if err := db.Limit(limit).Offset(offset).Omit("extra_detail").
		Order("policy_id ASC").Find(&v).Error; err != nil {
		logging.GetLogger().Err(err).Msg("get rules error")
		return nil, 0, errors.New("获取规则失败")
	}

	return v, count, nil
}

func (s *Service) RuleDetail(ctx context.Context, scapType string, id int) (*model.PolicyDetailInfo, error) {
	db := s.rdb.Get().WithContext(ctx).
		Model(&model.PolicyDetailInfo{}).
		Where("check_type = ?", scapType).
		Where("id = ?", id)
	// 只有kube才会获取 extra_detail 字段
	if scapType != "kube" {
		db = db.Omit("extra_detail")
	}

	var data model.PolicyDetailInfo

	err := db.First(&data).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("get rules detail error")
		return nil, fmt.Errorf("获取规则详情失败:%s", err.Error())
	}

	return &data, nil
}
