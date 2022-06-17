package scap

import (
	"context"

	"github.com/pkg/errors"

	"gitlab.com/piccolo_su/vegeta/pkg/logging"
	"gitlab.com/piccolo_su/vegeta/pkg/model"
)

func (s *Service) RuleBatch(ctx context.Context, scapType uint8, limit, offset int) ([]model.PolicyDetailInfo, int64, error) {
	var checkType string
	switch scapType {
	case 1:
		checkType = kube
	case 2:
		checkType = docker
	case 3:
		checkType = host
	default:
		return nil, 0, errors.New("unsupported check type")
	}

	db := s.rdb.Get().WithContext(ctx).Model(&model.PolicyDetailInfo{}).Where("check_type = ?", checkType)

	var count int64
	if err := db.Count(&count).Error; err != nil {
		logging.GetLogger().Err(err).Msg("count rules error")
		return nil, 0, errors.New("获取数量失败")
	}

	var v = make([]model.PolicyDetailInfo, 0, limit)

	if err := db.Limit(limit).Offset(offset).Omit("extra_detail").Find(&v).Error; err != nil {
		logging.GetLogger().Err(err).Msg("get rules error")
		return nil, 0, errors.New("获取规则失败")
	}

	return v, count, nil
}

func (s *Service) RuleDetail(ctx context.Context, scapType uint8, id int) (*model.PolicyDetailInfo, error) {
	var checkType string
	switch scapType {
	case 1:
		checkType = kube
	case 2:
		checkType = docker
	case 3:
		checkType = host
	default:
		return nil, errors.New("unsupported check type")
	}

	db := s.rdb.Get().WithContext(ctx).
		Model(&model.PolicyDetailInfo{}).
		Where("check_type = ?", checkType).
		Where("id = ?", id)
	// 只有kube才会获取 extra_detail 字段
	if scapType != 1 {
		db = db.Omit("extra_detail")
	}

	var data model.PolicyDetailInfo

	err := db.First(&data).Error
	if err != nil {
		logging.GetLogger().Err(err).Msg("get rules detail error")
		return nil, errors.New("获取规则详情失败")
	}

	return &data, nil
}
